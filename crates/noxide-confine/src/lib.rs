//! Operating-system confinement for Noxide processes.
//!
//! Landlock and seccomp bind only the calling thread and threads it later starts,
//! so [`apply`] must run before the process starts any thread. It refuses when
//! other threads exist instead of leaving them unconfined.
//!
//! This limits what follows a Wasmtime or host compromise; it is not the guest
//! boundary. Landlock port rules name no address, so loopback-only connections
//! remain a separate check in deployment configuration.
#![forbid(unsafe_code)]
use anyhow::Result;
use std::path::PathBuf;

/// What to do when the kernel cannot provide the whole policy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    /// Fail startup. The secure default.
    #[default]
    Required,
    /// Apply what the kernel supports and report the rest.
    BestEffort,
    /// An explicit operator decision to run without confinement.
    Disabled,
}

/// Everything the process may reach after [`apply`]. Nothing else on the
/// filesystem is accessible, and no other TCP port can be bound or connected.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    pub mode: Mode,
    /// Directories or files with full read and write access.
    pub writable: Vec<PathBuf>,
    /// Directories or files with read access.
    pub readable: Vec<PathBuf>,
    pub tcp_bind: Vec<u16>,
    pub tcp_connect: Vec<u16>,
    /// Keep the right to start programs, limited to `readable` by Landlock. Only for
    /// the guest broker, whose whole purpose is starting workers. What it starts
    /// inherits these limits.
    pub spawn: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Confined,
    /// Part of the policy is not enforced; `Mode::BestEffort` only.
    Partial,
    Unconfined,
}

/// Apply the policy to this process. Irreversible.
pub fn apply(policy: &Policy) -> Result<Outcome> {
    if policy.mode == Mode::Disabled {
        return Ok(Outcome::Unconfined);
    }
    imp::apply(policy)
}

#[cfg(target_os = "linux")]
mod imp {
    use super::{Mode, Outcome, Policy};
    use anyhow::{Context, Result, ensure};
    use landlock::{
        ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, NetPort, PathBeneath, PathFd,
        Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    };
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule, TargetArch,
    };
    use std::collections::BTreeMap;

    pub(super) fn apply(policy: &Policy) -> Result<Outcome> {
        ensure!(single_threaded()?, "confinement requires one thread");
        let filesystem = landlock(policy)?;
        seccomp(policy)?;
        Ok(if filesystem {
            Outcome::Confined
        } else {
            Outcome::Partial
        })
    }

    fn single_threaded() -> Result<bool> {
        Ok(std::fs::read_dir("/proc/self/task")
            .context("cannot count process threads")?
            .count()
            == 1)
    }

    fn landlock(policy: &Policy) -> Result<bool> {
        // ABI 4 is the first with TCP rules. A required policy must get all of it.
        let abi = ABI::V4;
        let level = match policy.mode {
            Mode::Required => CompatLevel::HardRequirement,
            _ => CompatLevel::BestEffort,
        };
        let mut rules = Ruleset::default()
            .set_compatibility(level)
            .handle_access(AccessFs::from_all(abi))?
            .handle_access(AccessNet::from_all(abi))?
            .create()?;
        for (paths, access) in [
            (&policy.writable, AccessFs::from_all(abi)),
            (&policy.readable, AccessFs::from_read(abi)),
        ] {
            for path in paths {
                let access = if path.is_dir() {
                    access
                } else {
                    access & AccessFs::from_file(abi)
                };
                let fd = PathFd::new(path)
                    .with_context(|| format!("confinement path {}", path.display()))?;
                rules = rules.add_rule(PathBeneath::new(fd, access))?;
            }
        }
        for port in &policy.tcp_bind {
            rules = rules.add_rule(NetPort::new(*port, AccessNet::BindTcp))?;
        }
        for port in &policy.tcp_connect {
            rules = rules.add_rule(NetPort::new(*port, AccessNet::ConnectTcp))?;
        }
        let status = rules.restrict_self()?;
        let complete = status.ruleset == RulesetStatus::FullyEnforced;
        ensure!(
            complete || policy.mode != Mode::Required,
            "the kernel cannot enforce the required Landlock policy"
        );
        Ok(complete)
    }

    /// Syscalls a confined server has no use for. Denied rather than allow-listed,
    /// because Wasmtime, the allocator and the database driver have no stable set.
    const DENIED: &[libc::c_long] = &[
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_process_madvise,
        libc::SYS_pidfd_getfd,
        libc::SYS_kcmp,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_setns,
        libc::SYS_unshare,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_userfaultfd,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_kexec_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_keyctl,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_reboot,
        libc::SYS_acct,
        libc::SYS_name_to_handle_at,
        libc::SYS_open_by_handle_at,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_fork,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_vfork,
    ];

    /// What `Policy::spawn` keeps available.
    const SPAWNING: &[libc::c_long] = &[
        libc::SYS_execve,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_fork,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_vfork,
    ];

    fn seccomp(policy: &Policy) -> Result<()> {
        let arch = TargetArch::try_from(std::env::consts::ARCH).context("seccomp architecture")?;
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = DENIED
            .iter()
            .filter(|call| !(policy.spawn && SPAWNING.contains(call)))
            .map(|call| (*call, Vec::new()))
            .collect();
        // A new process would leave this filter's view; threads share it.
        if !policy.spawn {
            rules.insert(
                libc::SYS_clone,
                vec![SeccompRule::new(vec![SeccompCondition::new(
                    0,
                    SeccompCmpArgLen::Qword,
                    SeccompCmpOp::MaskedEq(libc::CLONE_THREAD as u64),
                    0,
                )?])?],
            );
        }
        let mut families = vec![libc::AF_UNIX];
        if !policy.tcp_bind.is_empty() || !policy.tcp_connect.is_empty() {
            families.extend([libc::AF_INET, libc::AF_INET6]);
        }
        rules.insert(
            libc::SYS_socket,
            vec![SeccompRule::new(
                families
                    .into_iter()
                    .map(|family| {
                        SeccompCondition::new(
                            0,
                            SeccompCmpArgLen::Dword,
                            SeccompCmpOp::Ne,
                            family as u64,
                        )
                    })
                    .collect::<std::result::Result<_, _>>()?,
            )?],
        );
        let deny = program(rules, libc::EPERM, arch)?;
        // clone3 hides its flags behind a pointer. ENOSYS makes libc fall back to
        // clone, whose flags the rule above can inspect.
        let clone3 = program(
            BTreeMap::from([(libc::SYS_clone3, Vec::new())]),
            libc::ENOSYS,
            arch,
        )?;
        seccompiler::apply_filter(&deny)?;
        if !policy.spawn {
            seccompiler::apply_filter(&clone3)?;
        }
        Ok(())
    }

    fn program(
        rules: BTreeMap<i64, Vec<SeccompRule>>,
        errno: i32,
        arch: TargetArch,
    ) -> Result<BpfProgram> {
        Ok(SeccompFilter::new(
            rules,
            SeccompAction::Allow,
            SeccompAction::Errno(errno as u32),
            arch,
        )?
        .try_into()?)
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::{Mode, Outcome, Policy};
    use anyhow::{Result, ensure};

    pub(super) fn apply(policy: &Policy) -> Result<Outcome> {
        ensure!(
            policy.mode != Mode::Required,
            "confinement is implemented only on Linux; set it to best_effort or disabled"
        );
        Ok(Outcome::Partial)
    }
}

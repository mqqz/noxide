//! Each case re-executes this binary, because confinement cannot be undone and
//! requires a process with one thread. A default test harness has several.
use noxide_confine::{Mode, Outcome, Policy, apply};
use std::{
    fs,
    net::{TcpListener, TcpStream},
    os::unix::net::UnixListener,
    path::PathBuf,
    process::Command,
};

fn policy(root: &str, tcp: bool) -> Policy {
    let root = PathBuf::from(root);
    Policy {
        mode: Mode::Required,
        writable: vec![root.join("data")],
        readable: vec![root.join("public")],
        tcp_bind: if tcp { vec![48_731] } else { vec![] },
        tcp_connect: if tcp { vec![48_731] } else { vec![] },
    }
}

fn no_network(root: &str) {
    assert_eq!(apply(&policy(root, false)).unwrap(), Outcome::Confined);
    let root = PathBuf::from(root);
    // Filesystem scope.
    fs::write(root.join("data/new"), b"ok").unwrap();
    assert_eq!(fs::read(root.join("public/file")).unwrap(), b"public");
    assert!(fs::write(root.join("public/file"), b"changed").is_err());
    assert!(fs::read(root.join("secret")).is_err());
    assert!(fs::read("/etc/hostname").is_err() && fs::read_dir("/etc").is_err());
    // Threads still start; processes do not.
    std::thread::spawn(|| ()).join().unwrap();
    assert!(Command::new("/bin/true").status().is_err());
    // Only local sockets exist.
    assert!(TcpListener::bind("127.0.0.1:0").is_err());
    assert!(TcpStream::connect("127.0.0.1:1").is_err());
    UnixListener::bind(root.join("data/socket")).unwrap();
}

fn tcp_ports(root: &str) {
    assert_eq!(apply(&policy(root, true)).unwrap(), Outcome::Confined);
    let listener = TcpListener::bind("127.0.0.1:48731").unwrap();
    TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let denied = TcpListener::bind("127.0.0.1:48732").unwrap_err();
    assert_eq!(denied.kind(), std::io::ErrorKind::PermissionDenied);
    let denied = TcpStream::connect("127.0.0.1:48733").unwrap_err();
    assert_eq!(denied.kind(), std::io::ErrorKind::PermissionDenied);
}

fn refuses_threads(root: &str) {
    let (stop, stopped) = std::sync::mpsc::channel::<()>();
    let worker = std::thread::spawn(move || stopped.recv());
    assert!(apply(&policy(root, false)).is_err());
    drop(stop);
    worker.join().unwrap().unwrap_err();
    // Still unconfined after the refusal.
    assert!(fs::read(PathBuf::from(root).join("secret")).is_ok());
}

fn disabled(root: &str) {
    let mut policy = policy(root, false);
    policy.mode = Mode::Disabled;
    assert_eq!(apply(&policy).unwrap(), Outcome::Unconfined);
    assert!(fs::read(PathBuf::from(root).join("secret")).is_ok());
}

fn main() {
    let mut arguments = std::env::args().skip(1);
    if let (Some(case), Some(root)) = (arguments.next(), arguments.next())
        && root.starts_with('/')
    {
        match case.as_str() {
            "no_network" => no_network(&root),
            "tcp_ports" => tcp_ports(&root),
            "refuses_threads" => refuses_threads(&root),
            "disabled" => disabled(&root),
            _ => panic!("unknown case"),
        }
        return;
    }
    if !cfg!(target_os = "linux")
        || !fs::read_to_string("/sys/kernel/security/lsm").is_ok_and(|lsm| lsm.contains("landlock"))
    {
        println!("skipped: Landlock is unavailable");
        return;
    }
    for case in ["no_network", "tcp_ports", "refuses_threads", "disabled"] {
        let root =
            std::env::temp_dir().join(format!("noxide-confine-{case}-{}", std::process::id()));
        fs::create_dir_all(root.join("data")).unwrap();
        fs::create_dir_all(root.join("public")).unwrap();
        fs::write(root.join("public/file"), b"public").unwrap();
        fs::write(root.join("secret"), b"secret").unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .arg(case)
            .arg(&root)
            .status()
            .unwrap();
        fs::remove_dir_all(&root).unwrap();
        assert!(status.success(), "{case}: {status}");
        println!("{case} ok");
    }
}

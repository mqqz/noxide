#!/usr/bin/env bash
# Bootstrap the disposable Ubuntu 24.04 GitHub-hosted runner, never a serving host.
set -euo pipefail

: "${RUNNER_TEMP:?requires a GitHub Actions runner}"
: "${GITHUB_ENV:?requires a GitHub Actions environment file}"

sudo apt-get update
sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a \
  apt-get install --yes --no-install-recommends \
  qemu-system-x86 linux-image-virtual build-essential binutils \
  libc6-dev python3 util-linux coreutils systemd-sysv

# The runner's Azure kernel need not exist in /boot. Use the installed guest
# kernel; copy it out of /boot because Ubuntu kernels may be root-readable only.
mapfile -t kernels < <(find /boot -maxdepth 1 -name 'vmlinuz-*-generic' -print | sort -V)
if (( ${#kernels[@]} == 0 )); then
  echo 'linux-image-virtual did not install a usable guest kernel' >&2
  exit 1
fi
kernel="${kernels[-1]}"
destination="$RUNNER_TEMP/noxide-ci-kernel"
sudo install -m 0644 -o "$(id -u)" -g "$(id -g)" "$kernel" "$destination"
echo "NOXIDE_CI_KERNEL=$destination" >> "$GITHUB_ENV"

printf 'Guest kernel: %s\n' "$kernel"
sha256sum "$destination"
qemu-system-x86_64 --version
gcc --version
rustc --version
python3 --version

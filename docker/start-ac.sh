#!/bin/bash
set -euo pipefail

/iptables_defaults.sh -f

# Fail fast if baseline iptables setup fails above; running the AC without those
# local defaults would be misleading even before a developer opts into eBPF.
#
# FilterMode=EBPFXDP pins maps and programs under /sys/fs/bpf. The local image
# defaults to iptables mode, so keep startup usable even on hosts that cannot
# mount bpffs; the eBPF load path will fail clearly if a developer flips the
# mode without the compose-granted privileges. If the mountpoint cannot even be
# created, skip the mount attempt for the same default-iptables fail-open reason.
if ! mkdir -p /sys/fs/bpf 2>/dev/null; then
  echo "WARN: unable to create /sys/fs/bpf; FilterMode=EBPFXDP will fail unless bpffs is mounted"
elif ! awk '$2 == "/sys/fs/bpf" && $3 == "bpf" { found=1 } END { exit found ? 0 : 1 }' /proc/mounts; then
  mount -t bpf bpf /sys/fs/bpf || echo "WARN: unable to mount bpffs at /sys/fs/bpf; FilterMode=EBPFXDP will fail unless bpffs is mounted"
fi

exec /nhp-ac/nhp-acd run

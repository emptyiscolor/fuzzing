#!/bin/bash
# Boots the audit-built kernel under QEMU (TCG, no /dev/kvm in this environment).
#
# Usage:
#   ./run-qemu.sh                 # normal boot, serial console attached
#   ./run-qemu.sh --wait-gdb      # pause at first instruction, wait for `gdb -x gdb-attach.gdb`
#   ./run-qemu.sh --panic-on-oops # useful when triaging a specific known crash
set -euo pipefail
cd "$(dirname "$0")"

KERNEL="linux/arch/x86/boot/bzImage"
INITRD="rootfs/initramfs.cpio.gz"
MEM="${MEM:-2G}"
SMP="${SMP:-2}"

if [[ ! -f "$KERNEL" ]]; then
  echo "error: $KERNEL not found — build the kernel first (see build-kernel.sh)" >&2
  exit 1
fi
if [[ ! -f "$INITRD" ]]; then
  echo "error: $INITRD not found — run rootfs/build-initramfs.sh first" >&2
  exit 1
fi

GDB_FLAGS=()
APPEND="console=ttyS0 nokaslr panic=-1 oops=panic"

for arg in "$@"; do
  case "$arg" in
    --wait-gdb)
      GDB_FLAGS+=(-s -S)
      echo "QEMU will wait for gdb: target remote :1234 (see gdb-attach.gdb)" >&2
      ;;
    --panic-on-oops)
      APPEND="console=ttyS0 nokaslr panic=-1"
      ;;
    *)
      echo "unknown flag: $arg" >&2; exit 1
      ;;
  esac
done

exec qemu-system-x86_64 \
  -kernel "$KERNEL" \
  -initrd "$INITRD" \
  -append "$APPEND" \
  -m "$MEM" \
  -smp "$SMP" \
  -nographic \
  -no-reboot \
  -serial mon:stdio \
  "${GDB_FLAGS[@]}"

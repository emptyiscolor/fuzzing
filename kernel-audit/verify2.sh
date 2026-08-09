#!/bin/bash
# Second verification lane: same contract as verify.sh but stages its own
# initramfs under a per-instance directory, so two candidates can be booted
# concurrently without clobbering each other's /repro.
#
#   ./verify2.sh repro/x.c bt [--timeout N]
set -uo pipefail
cd "$(dirname "$0")"

SRC="${1:-}"; INST="${2:-b}"
[[ -z "$SRC" || ! -f "$SRC" ]] && { echo "usage: $0 <repro.c> <instance> [--timeout N]" >&2; exit 2; }
shift 2

TIMEOUT=300
while [[ $# -gt 0 ]]; do
  case "$1" in
    --timeout) TIMEOUT="$2"; shift 2 ;;
    *) shift ;;
  esac
done

NAME="$(basename "$SRC" .c)"
STAGE="/tmp/initramfs-$INST"
LOG="/tmp/verify-${NAME}.log"

echo "[*] compiling $SRC"
if ! clang -static -O1 -Wall -Wno-unused-function -o /tmp/repro-$INST "$SRC" 2>/tmp/cc-$INST.log; then
  echo "[!] compile failed:"; cat /tmp/cc-$INST.log; exit 2
fi

rm -rf "$STAGE"; mkdir -p "$STAGE"/{bin,proc,sys,dev,tmp}
cp /bin/busybox "$STAGE/bin/busybox"; chmod +x "$STAGE/bin/busybox"
for c in sh mount umount ls cat echo ps mkdir insmod mknod dmesg poweroff reboot sleep; do
  ln -sf busybox "$STAGE/bin/$c"
done
cp /tmp/repro-$INST "$STAGE/repro"; chmod +x "$STAGE/repro"
cp rootfs/initramfs/init "$STAGE/init"; chmod +x "$STAGE/init"
( cd "$STAGE" && find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -9 > /tmp/initramfs-$INST.cpio.gz )

echo "[*] booting instance '$INST' (timeout ${TIMEOUT}s)"
rm -f "$LOG"
timeout "$TIMEOUT" qemu-system-x86_64 \
  -kernel linux/arch/x86/boot/bzImage \
  -initrd /tmp/initramfs-$INST.cpio.gz \
  -append "console=ttyS0 nokaslr repro=1 kasan_multi_shot=1 panic=-1 slub_debug=UZ" \
  -m 2G -smp 1 -nographic -no-reboot -nodefaults \
  -serial mon:stdio < /dev/null > "$LOG" 2>&1

PATTERN='BUG: KASAN:|kernel BUG at |general protection fault|Oops: |UBSAN: [a-z-]*out-of-bounds|stack smashing|__stack_chk_fail|null-ptr-deref|Unable to handle kernel NULL pointer|stack-protector: Kernel stack is corrupted'

echo
if grep -qE "$PATTERN" "$LOG"; then
  echo "=============================================="
  echo " REPRODUCED - memory-safety report fired"
  echo "=============================================="
  grep -nE "$PATTERN" "$LOG" | head -5
  echo "---------------- report ----------------------"
  awk '/BUG: KASAN|general protection fault|kernel BUG at|UBSAN:|stack-protector/{f=1} f' "$LOG" | head -70
  echo "full log: $LOG"
  exit 0
fi
grep -q REPRO_START "$LOG" || { echo "[!] repro never ran:"; tail -20 "$LOG"; exit 2; }
echo "[-] clean run, no report"
grep -E "REPRO_EXIT|REPRO_DONE" "$LOG" | head -2
echo "full log: $LOG"
exit 1

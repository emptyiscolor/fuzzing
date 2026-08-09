#!/bin/bash
# Compile a C reproducer, boot it on the KASAN kernel, and report whether it
# tripped a memory-safety check.
#
#   ./verify.sh repro/sctp-oob.c              # run it, print verdict
#   ./verify.sh repro/x.c --timeout 300       # allow a longer run
#   ./verify.sh repro/x.c --keep              # keep the full serial log
#
# Exit status: 0 = a memory-safety report fired (bug reproduced)
#              1 = clean run, no report (candidate not confirmed)
#              2 = harness/boot failure
set -uo pipefail
cd "$(dirname "$0")"

SRC="${1:-}"
[[ -z "$SRC" ]] && { echo "usage: $0 <repro.c> [--timeout N] [--keep]" >&2; exit 2; }
[[ -f "$SRC" ]] || { echo "error: $SRC not found" >&2; exit 2; }
shift

TIMEOUT=240
KEEP=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --keep)    KEEP=1; shift ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

NAME="$(basename "$SRC" .c)"
LOG="/tmp/verify-${NAME}.log"

echo "[*] compiling $SRC"
# -static: the initramfs has no libc. -O1: keep the repro's own logic intact.
if ! clang -static -O1 -Wall -Wno-unused-function \
     -o rootfs/initramfs/repro "$SRC" 2>/tmp/cc-${NAME}.log; then
  echo "[!] compile failed:"; cat /tmp/cc-${NAME}.log; exit 2
fi
chmod +x rootfs/initramfs/repro

echo "[*] packing initramfs"
./rootfs/build-initramfs.sh >/dev/null 2>&1 || { echo "[!] initramfs pack failed" >&2; exit 2; }

echo "[*] booting (timeout ${TIMEOUT}s)"
rm -f "$LOG"
timeout "$TIMEOUT" qemu-system-x86_64 \
  -kernel linux/arch/x86/boot/bzImage \
  -initrd rootfs/initramfs.cpio.gz \
  -append "console=ttyS0 nokaslr repro=1 kasan_multi_shot=1 panic=-1 slub_debug=UZ" \
  -m 2G -smp 2 -nographic -no-reboot -nodefaults \
  -serial mon:stdio < /dev/null > "$LOG" 2>&1

# A memory-safety hit. Deliberately does NOT match plain "WARNING" or
# lockdep splats -- we only care about OOB/overflow/UAF here.
PATTERN='KASAN:|BUG: KASAN|general protection fault|kernel BUG at|Oops:|stack-out-of-bounds|slab-out-of-bounds|use-after-free|double-free|invalid-free|UBSAN:.*(overflow|out of bounds|index)'

echo
if grep -qE "$PATTERN" "$LOG"; then
  echo "=============================================="
  echo " REPRODUCED - memory-safety report fired"
  echo "=============================================="
  # Print the report with enough context to identify the object and call site.
  grep -nE "$PATTERN" "$LOG" | head -5
  echo "---------------- full report -----------------"
  awk '/BUG: KASAN|general protection fault|kernel BUG at|UBSAN:/{f=1} f' "$LOG" | head -80
  echo "----------------------------------------------"
  echo "full log: $LOG"
  exit 0
fi

if ! grep -q "REPRO_START" "$LOG"; then
  echo "[!] reproducer never ran - boot or harness problem. Tail of log:"
  tail -25 "$LOG"
  exit 2
fi

echo "[-] clean run: no memory-safety report"
grep -E "REPRO_EXIT|REPRO_DONE" "$LOG" | head -3
[[ $KEEP -eq 1 ]] && echo "full log: $LOG" || rm -f "$LOG"
exit 1

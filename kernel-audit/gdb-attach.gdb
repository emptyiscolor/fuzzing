# Attach gdb to a QEMU instance started with `run-qemu.sh --wait-gdb`.
#
# Usage:
#   ./run-qemu.sh --wait-gdb &
#   gdb -x gdb-attach.gdb
#
# vmlinux-gdb.py (from CONFIG_GDB_SCRIPTS=y) is auto-loaded from the same
# directory as vmlinux and adds kernel-aware commands: lx-dmesg, lx-ps,
# lx-symbols (module symbol autoload), etc. See `apropos lx` once attached.

file linux/vmlinux
target remote :1234

# Kernel is compiled with -pie/KASLR disabled (nokaslr) so symbols in
# vmlinux line up directly with runtime addresses.
break start_kernel
continue

# Linux kernel code-audit environment

Environment for auditing https://github.com/torvalds/linux, reproducing
suspected bugs, and verifying fixes under QEMU with live gdb debugging.

## Layout

```
kernel-audit/
├── linux/                  # torvalds/linux (shallow clone, depth 1)
├── configs/audit.config    # kconfig fragment: debug info, KASAN/UBSAN, KGDB, lockdep
├── rootfs/
│   ├── initramfs/          # minimal busybox-based root (source tree)
│   ├── build-initramfs.sh  # packs initramfs/ -> initramfs.cpio.gz
│   └── initramfs.cpio.gz   # built initrd (generated)
├── build-kernel.sh         # configure + build bzImage with clang/LLVM
├── run-qemu.sh             # boot bzImage+initrd under QEMU
└── gdb-attach.gdb          # attach live gdb to a QEMU instance
```

## Toolchain (already installed on this host)

- `clang`/`lld`/`llvm` 18.x — kernel is built fully with `LLVM=1` (no gcc)
- `gdb` 15.x — live kernel debugging over QEMU's gdbstub
- `qemu-system-x86_64` 8.2 — no `/dev/kvm` in this environment, so it runs
  under TCG software emulation (slower than KVM, but fully functional; no
  `-enable-kvm` flag is passed)
- kernel build deps: bison, flex, libssl-dev, libelf-dev, libncurses-dev,
  dwarves (pahole), bc, cpio

## Workflow

### 0. Clone the kernel source (first time only)

`linux/` is gitignored (multi-GB nested git repo) — clone it yourself:

```
git clone --depth 1 https://github.com/torvalds/linux.git linux
```

### 1. Update the kernel source

```
cd linux
git fetch origin --depth 1        # or drop --depth to unshallow for `git bisect`
git checkout origin/master
# or: git checkout <tag/commit> to audit/reproduce against a specific version
```

To bisect a regression you'll need full history: `git fetch --unshallow`.

### 2. Build a debug kernel

```
./build-kernel.sh
```

This runs `defconfig` + merges `configs/audit.config` (KASAN, UBSAN, lockdep,
KGDB, full debug info, `CONFIG_GDB_SCRIPTS`) + builds `bzImage` with clang.
Edit `configs/audit.config` to add/drop instrumentation (e.g. switch
`CONFIG_KASAN_GENERIC`→`CONFIG_KASAN_SW_TAGS`, add `CONFIG_KFENCE`,
`CONFIG_KCSAN` for data-race hunting, etc.) then re-run.

### 3. Boot it

```
./run-qemu.sh
```

Plain serial-console boot into a busybox shell. Ctrl-A X exits QEMU.

To reproduce a crash from a syscall reproducer, module, or test binary:
compile/copy it into `rootfs/initramfs/root/`, rerun
`rootfs/build-initramfs.sh`, boot, and run it from the shell.

### 4. Debug live with gdb

```
./run-qemu.sh --wait-gdb &
gdb -x gdb-attach.gdb
```

QEMU halts at the reset vector until gdb connects on `:1234`.
`gdb-attach.gdb` loads `linux/vmlinux` symbols, connects, and sets an
initial breakpoint at `start_kernel`. Because the kernel boots with
`nokaslr`, addresses in `vmlinux` match runtime addresses directly — no
`lx-symbols`/KASLR offset dance needed for core kernel code (loadable
modules still need `lx-symbols` from the GDB kernel scripts, auto-loaded
since `CONFIG_GDB_SCRIPTS=y`).

Useful gdb commands once attached (from `scripts/gdb/`):
- `lx-dmesg` — dump the kernel log ring buffer
- `lx-ps` — list tasks
- `lx-symbols` — load symbols for loaded modules
- standard breakpoints/`bt`/`p` work on kernel data structures with full
  type info since `CONFIG_DEBUG_INFO=y`

### 5. Triage a crash/oops without gdb

`run-qemu.sh` boots with `oops=panic panic=-1` so any oops/BUG/KASAN report
immediately panics and reboots is disabled (`-no-reboot` + `panic=-1` halts
QEMU instead of looping), keeping the full report on the serial console for
copy-paste analysis. Pass `--panic-on-oops` is the default variant; the flag
list in `run-qemu.sh` documents overriding `-append`.

### 6. Verify a fix

Apply/revert the patch under audit in `linux/`, `./build-kernel.sh`, repeat
step 3/4/5, and confirm the KASAN/UBSAN/lockdep report is gone and behavior
is correct.

## Notes / caveats

- The clone is shallow (`--depth 1`) to save disk/time. Unshallow
  (`git fetch --unshallow`) before bisecting or when you need old tags.
- No hardware KVM acceleration is available in this container — boots are
  slower than on bare metal but adequate for triage. If you move this setup
  to a host with `/dev/kvm`, add `-enable-kvm -cpu host` to `run-qemu.sh` for
  a large speedup.
- The initramfs is intentionally minimal (busybox only). Add any
  reproducer binaries, `.ko` modules, or test harnesses under
  `rootfs/initramfs/` and repack before booting.

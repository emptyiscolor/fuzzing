#!/bin/bash
# (Re)configures and builds the audited kernel with clang/LLVM.
# Safe to re-run after `git pull` or after editing configs/audit.config.
set -euo pipefail
cd "$(dirname "$0")/linux"

JOBS="${JOBS:-$(nproc)}"

make LLVM=1 defconfig
scripts/kconfig/merge_config.sh -m .config ../configs/audit.config
make LLVM=1 olddefconfig
make LLVM=1 -j"$JOBS" bzImage

echo ""
echo "Built: $(pwd)/arch/x86/boot/bzImage"
echo "Symbols: $(pwd)/vmlinux"

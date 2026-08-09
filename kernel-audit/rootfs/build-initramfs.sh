#!/bin/bash
# Packs rootfs/initramfs/ into a gzipped cpio archive QEMU can boot with -initrd.
# bin/ is (re)populated from the host's busybox-static on every run rather
# than committed to git.
set -euo pipefail
cd "$(dirname "$0")/initramfs"

mkdir -p bin
cp -f /bin/busybox bin/busybox
chmod +x bin/busybox
for cmd in sh mount umount ls cat echo ps mkdir insmod mknod dmesg poweroff reboot; do
  ln -sf busybox "bin/$cmd"
done

find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs.cpio.gz
echo "Wrote $(cd ..; pwd)/initramfs.cpio.gz"

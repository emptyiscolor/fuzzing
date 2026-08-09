# Bluetooth: `eir_create_scan_rsp()` stack overflow via stale `scan_rsp_len`

**Class:** stack buffer overflow, 4 bytes past a 251-byte on-stack array
**Site:** `net/bluetooth/eir.c:370-375`, destination at `net/bluetooth/hci_sync.c:1528`;
enabled by `net/bluetooth/hci_core.c:1699` + `:1771-1775`
**Reachable by:** local process with `CAP_NET_ADMIN` and `/dev/vhci` — six MGMT commands
**Verified:** `Kernel panic - not syncing: stack-protector: Kernel stack is corrupted in: hci_set_ext_scan_rsp_data_sync+0x3b5/0x3e0`

## Defect

`eir_create_scan_rsp()` takes **no size parameter**, unlike its sibling
`eir_create_adv_data(hdev, instance, ptr, u8 size)`. It writes 4 bytes of
appearance plus `adv->scan_rsp_len` into a 251-byte `DEFINE_FLEX` stack buffer.

`tlv_data_max_len()` subtracts 4 when `MGMT_ADV_FLAG_APPEARANCE` is set, so a
251-byte scan response only validates while that flag is clear. Flag and length
are set by different commands and only one is reset: `hci_add_adv_instance()` on
an existing instance clears the scan response *data* and replaces `adv->flags`,
while `hci_set_adv_instance_data()` assigns `adv->scan_rsp_len` **only when the
new length is non-zero** — and `ADD_EXT_ADV_PARAMS` passes zero.
`adv->scan_rsp_len` is assigned in exactly one place in the file, so it never
returns to 0.

Same shape as `bt-enckeysize-ltk-oob`: a validator runs once at set time and a
later unvalidated write invalidates its conclusion. This case was found by
generalizing that shape, not by auditing fresh code.

## Upstream status: UNIQUE

Present verbatim at `origin/master` `b643e495ae92` — `eir_create_scan_rsp()`
still takes no size argument and `adv->scan_rsp_len` is still assigned in exactly
one place. No matching report was found (subject to the archive-access caveat in
`../README.md`).

## Note on detectability

This was expected to require `CONFIG_KASAN_STACK=y`, on the assumption that 4
bytes would land in adjacent stack slots rather than on the canary. That was
wrong — `CONFIG_STACKPROTECTOR_STRONG` catches it directly, on the same kernel
used for the other two cases.

## Files

- `reproducer/bt-scanrsp-stackoob.c` — PoC
- `reproducer/bt-scanrsp-control.c` — negative control (flag re-issue removed)
- `reproducer/common.h`
- `reproducer/0001-*.patch` — proposed fix (compile-tested): gives
  `eir_create_scan_rsp()` the `size` argument its sibling already has
- `diagnosis/bt-scanrsp-stackoob-crash.log` — full console log with the panic
- `diagnosis/bt-scanrsp-NEGATIVE-CONTROL.log` — control, clean

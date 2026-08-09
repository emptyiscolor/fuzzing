# Bluetooth: unbounded `enc_key_size` corrupts `ltk->enc_size`

**Class:** OOB slab read (239 bytes past a 72-byte object), OOB write into a
16-byte stack array, `size_t` underflow in a `memset` length
**Site:** `net/bluetooth/hci_event.c:745,769` (write) → `:6720-6721` (sinks)
**Reachable by:** local process with `CAP_NET_ADMIN` and `/dev/vhci` — no remote peer
**Verified:** `KASAN: slab-out-of-bounds` (read of size 255) **and** independently
`UBSAN: array-index-out-of-bounds ... index 255 is out of range for '__u8[16]'`

## Defect

`hci_cc_read_enc_key_size()` stores a raw u8 from a Command Complete into the
persistent key material. Both guards are *downgrade* checks (`<`), so by
construction they permit arbitrarily large values, and
`*key_enc_size = conn->enc_key_size` writes it into `ltk->enc_size` whose `val[]`
is 16 bytes. `hci_le_ltk_request_evt()` then uses it as a `memcpy` length.

The event is accepted unsolicited: `hci_cmd_complete_evt()` picks the handler
purely from the opcode in the event, with no correlation against a command the
host sent. `hci_read_enc_key_size()` is only ever *sent* for ACL links, but the
handler re-resolves the connection from an attacker-chosen handle and never
re-checks `conn->type`, so an LE connection can be targeted.

## Upstream status: INCOMPLETE FIX — disclose as such, not as a fresh bug

`b8dbe9648d69` ("Bluetooth: MGMT: validate LTK enc_size on load", 2026-03-28,
reported by Keenan Dong) addressed **the same sink**. Its commit message:

> Load Long Term Keys stores the user-provided enc_size and later uses it to
> size fixed-size stack operations when replying to LE LTK requests. An
> enc_size larger than the 16-byte key buffer can therefore overflow the reply
> stack buffer.
> Reject oversized enc_size values while validating the management LTK record
> so invalid keys never reach the stored key state.

That closed the **MGMT load** path by adding `key->enc_size > sizeof(key->val)`
to `ltk_is_valid()`. It runs at install time only. The finding here is that the
stored key state can still be made invalid *after* validation, through the write
in `hci_cc_read_enc_key_size()` introduced by `c82b6357a546` — so the same
16-byte sink stays reachable by a second path the fix did not cover.

So: **not a duplicate report**, but directly adjacent to a merged fix, and it
should be reported as completing that fix rather than as an independent bug.
The proposed patch carries `Fixes: c82b6357a546`.

## Fix validation

With `reproducer/0001-*.patch` applied and the kernel rebuilt, the reproducer
still drives the whole sequence — LE Connection Complete, the unsolicited
`key_size = 255` Command Complete, and the LTK Request — and produces no report.

## Files

- `reproducer/bt-enckeysize-oob.c` — PoC (emulates enough of a controller over
  `/dev/vhci` to reach `HCI_UP`, loads an LTK over MGMT, then injects the
  unsolicited Command Complete and the LTK request)
- `reproducer/common.h`
- `reproducer/0001-*.patch` — proposed fix (compile-tested), adds
  `HCI_MAX_ENC_KEY_SIZE` alongside the existing `HCI_MIN_ENC_KEY_SIZE`
- `diagnosis/bt-enckeysize-oob-crash.log` — KASAN report + UBSAN report

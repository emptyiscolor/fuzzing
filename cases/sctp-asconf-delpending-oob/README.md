# sctp: ASCONF chunk under-reservation via `asconf_addr_del_pending`

**Class:** out-of-bounds write, 12 bytes past the reserved chunk
**Site:** `net/sctp/sm_make_chunk.c:2877-2878` (sizing) vs `:2908-2916` (fill)
**Reachable by:** unprivileged local process (`unshare(CLONE_NEWUSER|CLONE_NEWNET)`),
plain `setsockopt` only — no packet injection
**Verified:** `kernel BUG at net/core/skbuff.c:214` (`skb_over_panic`)

## Defect

The chunk is sized in one pass and filled in another. When
`asoc->asconf_addr_del_pending` is set, the sizing pass charges the extra DEL_IP
parameter using `addr_param_len` — which at that point holds the address
parameter length of the address being walked in the *caller's* array — while the
fill pass recomputes it from the pending address's own family. The in-tree
comment states the assumption ("reuse the parameter length from the same scope
one") that nothing enforces. A v6 pending delete (20-byte address parameter)
with v4 additions (8-byte) under-reserves by exactly 12 bytes.

## Reachability

`sctp_bindx_rem()` returns `-EBUSY` unless the **endpoint** holds >= 2 addresses,
while the del_pending branch requires the **association** to hold exactly the one
being removed — so the two lists must diverge. The lever is address scoping:
`sctp_in_scope()` copies an endpoint address into a new association only when
`addr_scope <= peer_scope` (`GLOBAL(0) < PRIVATE(1) < LINK(2) < LOOPBACK(3)`), so
associating with a global-scope peer leaves private v4 addresses on the endpoint
but out of the association.

Whether the 12-byte overrun escapes the allocation depends on where the chunk
size lands relative to the kmalloc bucket, so the reproducer sweeps the add
count; it fires at n=21.

## Upstream status: UNIQUE

Present verbatim at `origin/master` `b643e495ae92`. Distinct from both known
ASCONF bugs, whose fixes are already in the tree:
- `9de7922bc709` (CVE-2014-3673) — receive path, `WORD_ROUND` off-by-one.
- `9b2854f86f0b` (CVE-2026-64564 "SCTPhantom") — DEL-IP transport UAF.

This one is in the ASCONF **builder** on the `setsockopt` path, a different
function and a different mechanism.

## Fix validation

With `reproducer/0001-*.patch` applied and the kernel rebuilt, the reproducer
completes the full n=1..24 sweep with every `trigger rc=0` and no report — it
previously died at n=21 with `skb_over_panic`.

## Files

- `reproducer/sctp-asconf-oob.c` — PoC, sweeps n=1..24 in one boot
- `reproducer/sctp-asconf-control.c` — negative control (arming step removed)
- `reproducer/common.h` — shared netlink/netns scaffolding
- `reproducer/0001-*.patch` — proposed fix (compile-tested)
- `diagnosis/sctp-asconf-oob-crash.log` — full console log with the BUG
- `diagnosis/sctp-asconf-NEGATIVE-CONTROL.log` — control, 24 iterations clean

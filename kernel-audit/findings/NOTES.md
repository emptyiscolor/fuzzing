# net/ memory-safety audit — running notes

Tree: torvalds/linux @ `06cf61899` (2026-08-08). Scope per user: **OOB, integer
overflow, UAF only** — races and pure leaks explicitly out of scope.

## Verification standard

A candidate is only counted as **VERIFIED** if a reproducer trips a sanitizer
report (KASAN / UBSAN / GPF) on the instrumented kernel and the report is
captured in a serial log. Static reasoning alone is a *candidate*, never a
verified bug — this code is fuzzed continuously by syzbot, so the prior on any
given candidate being real is low and the false-positive rate of pure code
reading is high.

Important limitation discovered early: **not every real defect is
KASAN-detectable.** An over-read that stays inside the same slab object (very
common with `sk_buff` tailroom) is invisible to KASAN. Those are KMSAN-class
findings; KMSAN needs a separate, KASAN-incompatible build.

---

## Candidates

### C1 — sctp_verify_asconf: missing length check on SCTP_PARAM_ERR_CAUSE
- **File:** `net/sctp/sm_make_chunk.c:3213-3214` (missing guard); over-read at
  `:3327` (`sctp_process_asconf`) and `:3441` (`sctp_get_asconf_response`).
- **Class:** OOB-read → 4-byte uninitialised-memory disclosure to peer.
- **Status:** **CODE DEFECT CONFIRMED BY INSPECTION, NOT VERIFIABLE HERE.**
- **What:** `sctp_verify_asconf()` enforces a per-type minimum length for every
  accepted ASCONF parameter except `SCTP_PARAM_ERR_CAUSE`, which has a bare
  `break;`. Its siblings in the same switch (`SCTP_PARAM_SUCCESS_REPORT`,
  `SCTP_PARAM_ADAPTATION_LAYER_IND`) are both forced to
  `length == sizeof(struct sctp_addip_param)` (8). Consumers unconditionally
  treat the parameter as a `struct sctp_addip_param` and read `crr_id` at
  offset 4..7, so a 4-byte `ERR_CAUSE` parameter placed last in the chunk is
  read past `chunk_end`. `sctp_add_asconf_response()` then copies that value
  into the outgoing ASCONF-ACK, mailing the bytes back to the sender.
- **Independently checked:** yes — read the switch and both consumers directly;
  the agent's reading is accurate.
- **Why not verified:** the 4 bytes land in skb tailroom / `skb_shared_info`,
  still inside the `skb->head` slab allocation, so KASAN stays silent by
  construction. Detecting it needs KMSAN (uninitialised-value tracking).
  Reaching it also needs a full hand-rolled SCTP association (INIT / INIT-ACK /
  COOKIE-ECHO / COOKIE-ACK) via raw packet injection plus
  `addip_enable`+`addip_noauth_enable` — very high reproducer cost for a
  non-KASAN-detectable infoleak.
- **Verdict:** real, worth reporting upstream as a hardening fix, but does not
  count toward the goal's "verified" bar.

### C3 — sctp_make_asconf_update_ip: del-pickup length accounting mismatch
- **File:** `net/sctp/sm_make_chunk.c:2877-2878` (sizing) vs `:2908-2916` (write).
- **Class:** OOB-write (12 bytes past the reserved chunk).
- **Status:** **PRIMARY CANDIDATE — reproducer written, verification pending.**
- **What:** the chunk is sized in one pass and filled in a second. When
  `asoc->asconf_addr_del_pending` is set, the sizing pass charges the extra
  DEL_IP parameter using `addr_param_len` from the address being walked in the
  *caller's* array; the write pass recomputes it from
  `asconf_addr_del_pending`'s own family. The comment ("reuse the parameter
  length from the same scope one") states an assumption nothing enforces. A v6
  pending address (20-byte address parameter) with v4 additions (8-byte)
  under-reserves by exactly 12 bytes.
- **Independently checked:** yes — read both passes; the agent's reading is
  accurate.
- **Why this one is verifiable (unlike C1/C2):** it is a *write*, not a read.
  `sctp_addto_chunk` → `skb_put` traps `tail > end` via `skb_over_panic()`,
  which is a hard BUG the harness detects. It also needs no packet injection —
  plain `setsockopt` on a loopback association.
- **Reachability (the hard part, worked out by reading the code):**
  `sctp_bindx_rem` returns `-EBUSY` unless the ENDPOINT holds >= 2 addresses,
  while the del_pending branch requires the ASSOCIATION to hold exactly the one
  address being removed. The two lists must therefore diverge. Lever:
  `sctp_in_scope()` (default policy ENABLE) copies an endpoint address into a
  new association only when `addr_scope <= peer_scope`, with
  GLOBAL=0 < PRIVATE=1 < LINK=2 < LOOPBACK=3. Connecting to a **global**-scope
  peer leaves PRIVATE v4 addresses on the endpoint but out of the association.
- **Predicted trigger point:** `alloc_skb` rounds the data area to 64B then adds
  320B of `skb_shared_info`, so usable = `bucket(align64(L)+320) - 320`. The
  first window where a 12-byte overrun exceeds it is L in [181,192] (bucket 512,
  usable exactly 192). With L ~= 16n+44 that is **n=9** additions — which
  matches the auditing agent's independently derived estimate.
- **Reproducer:** `repro/sctp-asconf-oob.c`, sweeps n=1..24 in one boot.

### C2 — sctp_get_asconf_response: padded/unpadded walk desync
- **File:** `net/sctp/sm_make_chunk.c:3459-3461`
- **Class:** OOB-read (bounded ~4 bytes past chunk end).
- **Status:** candidate, low confidence, same non-detectability problem as C1.
- **What:** the validator walks with `sctp_walk_params()` (advances by
  `SCTP_PAD4(length)`); this consumer advances by the raw unpadded
  `ntohs(length)`. Enabled by C1's missing constraint, a non-4-aligned
  `ERR_CAUSE` desynchronises the two walks, so the consumer reinterprets
  padding as a parameter header.
- **Verdict:** deprioritised — depends on C1, same slab-internal read, and its
  more interesting consequence (non-terminating loop) is a DoS, out of scope.

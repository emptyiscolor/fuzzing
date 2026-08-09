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

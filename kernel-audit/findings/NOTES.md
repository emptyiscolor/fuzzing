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

## Harness correction (recorded because it affected a verdict)

The first detection pattern matched the bare string `use-after-free`, which
appears in the **boot banner** `rcu: RCU callback double-/use-after-free debug
is enabled.` That made the SCTP negative control report "REPRODUCED" when it had
in fact run clean. Fixed to match real report headers only (`BUG: KASAN:`,
`kernel BUG at `, `UBSAN: *-out-of-bounds`, ...). Both confirmed bugs were
re-checked against the corrected pattern and still match on genuine reports; the
control re-evaluates to 0 matches. Logged here because a detector that
over-matches would otherwise manufacture false positives.

## Verified bugs

| # | Bug | Sanitizer evidence |
|---|-----|--------------------|
| 1 | `sctp_make_asconf_update_ip()` under-reserves the ASCONF chunk | `kernel BUG at net/core/skbuff.c:214` (`skb_over_panic`) |
| 2 | `hci_cc_read_enc_key_size()` unbounded write -> `hci_le_ltk_request_evt()` | `KASAN: slab-out-of-bounds`, read of size 255; plus `UBSAN: array-index-out-of-bounds` |
| 3 | `eir_create_scan_rsp()` stack overflow via stale `adv->scan_rsp_len` | `stack-protector: Kernel stack is corrupted in hci_set_ext_scan_rsp_data_sync` |

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

### C3 — sctp_make_asconf_update_ip: del-pickup length accounting mismatch  ✅ **VERIFIED**
- **Reproduced:** `kernel BUG at net/core/skbuff.c:214` (`skb_over_panic`),
  evidence in `findings/evidence/sctp-asconf-oob-crash.log`.
- **Trace (exactly the predicted path):**
  ```
  skb_over_panic+0x14f  <- skb_put+0x110  <- sctp_make_asconf_update_ip+0xb08
  <- sctp_send_asconf_add_ip+0x85f <- sctp_setsockopt+0x778
  <- do_sock_setsockopt <- __x64_sys_setsockopt
  ```
- **Reached from an unprivileged user+net namespace** (`unshare(CLONE_NEWUSER|
  CLONE_NEWNET)`), via plain `setsockopt` — no packet injection, no real root.
- Fired at n=21 additions, not the n=9 I predicted; my slack arithmetic was off
  on the chunk header/laddr parameter sizes. The mechanism is confirmed, the
  size prediction was not — which is exactly why the sweep exists.
- **Negative control:** `repro/sctp-asconf-control.c` runs the identical
  sequence minus the arming `bindx_rem`. Required to attribute the crash to the
  del-pickup mismatch rather than to adding N addresses per se.


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

### C4 — hci_cc_read_enc_key_size: unbounded enc_key_size  ✅ **VERIFIED**
- **File:** `net/bluetooth/hci_event.c:745,769` (unbounded write) →
  `net/bluetooth/hci_event.c:6720-6721` (sinks).
- **Class:** OOB-read (slab, 239 bytes past a 72-byte object) + OOB-write to a
  16-byte stack array + `memset` length underflow.
- **Reproduced:** evidence in `findings/evidence/bt-enckeysize-oob-crash.log`.
  ```
  BUG: KASAN: slab-out-of-bounds in hci_le_ltk_request_evt+0x309/0xa00
  Read of size 255 at addr ffff88800d06f558 by task kworker/u5:0/65
    __asan_memcpy <- hci_le_ltk_request_evt <- hci_event_packet <- hci_rx_work
  object: kmalloc-96, allocated 72-byte region, bad access 56 bytes in
    (offset 56 == struct smp_ltk .val[16])
  allocated by: hci_add_ltk <- load_long_term_keys <- hci_mgmt_cmd

  UBSAN: array-index-out-of-bounds in net/bluetooth/hci_event.c:6721:16
  index 255 is out of range for type '__u8[16]'
  ```
- **What:** `conn->enc_key_size = rp->key_size` takes a raw u8 (0..255) from a
  Command Complete. Both subsequent checks are *downgrade* checks (`<`), so
  nothing rejects a value above 16, and `*key_enc_size = conn->enc_key_size`
  writes it into `ltk->enc_size`. The validators that normally bound that field
  — `ltk_is_valid()` (mgmt) and `check_enc_key_size()` (smp) — run at key
  *install* time, so this later write bypasses both.
- **Why the Command Complete is accepted at all:** `hci_cmd_complete_evt`
  selects the handler purely from the opcode carried in the event, with no
  correlation against a command the host actually sent — so it can be injected
  unsolicited. `hci_read_enc_key_size()` is only ever *sent* for ACL links, but
  the *handler* re-resolves the connection from an attacker-chosen handle and
  never re-checks `conn->type`, so an LE connection can be targeted.
- **Reachability:** local only, no remote peer — `/dev/vhci` plus the mgmt
  channel. The reproducer emulates enough of a controller to reach `HCI_UP`.
- **Note:** two independent sanitizers fired on the same call path, and both the
  read side (`memcpy` source) and the index side (`memset`) are flagged.

### C5 — eir_create_scan_rsp: stale scan_rsp_len -> 4-byte stack OOB write  ✅ **VERIFIED**
- **File:** `net/bluetooth/eir.c:370-375` (unsized write) via
  `net/bluetooth/hci_sync.c:1528,1545`; enabled by `net/bluetooth/hci_core.c:1699`
  (flags replaced) + `:1771-1775` (length not reset).
- **Class:** OOB-write, 4 bytes past a 251-byte **stack** flex array.
- **Status:** **VERIFIED.** `stack-protector: Kernel stack is corrupted in:
  hci_set_ext_scan_rsp_data_sync+0x3b5/0x3e0`, via `add_ext_adv_data_sync` <-
  `hci_cmd_sync_work`. Evidence in
  `findings/evidence/bt-scanrsp-stackoob-crash.log`.
- **Prediction that was wrong:** I expected this to need `CONFIG_KASAN_STACK=y`.
  It does not — `STACKPROTECTOR_STRONG` catches it on the same kernel used for
  the other two findings. (The KASAN_STACK rebuild was attempted and failed on
  an unrelated `-Werror` frame-size limit in `lib/maple_tree.c`; the config was
  restored to match the kernel that produced all three results.)
- **Negative control:** `repro/bt-scanrsp-control.c` — identical sequence minus
  the flag re-issue — runs clean
  (`findings/evidence/bt-scanrsp-NEGATIVE-CONTROL.log`).
- **What:** `eir_create_scan_rsp()` takes **no size parameter**, unlike its
  sibling `eir_create_adv_data(hdev, instance, ptr, u8 size)`. It writes 4 bytes
  of appearance plus `adv->scan_rsp_len` bytes into a 251-byte
  `DEFINE_FLEX(...)` stack buffer.
- **Why the validator does not stop it:** `tlv_data_max_len()` subtracts 4 when
  `MGMT_ADV_FLAG_APPEARANCE` is set, so 251 only validates while that flag is
  clear. The two fields are then set by different commands and only one is
  reset: `hci_add_adv_instance()` on an existing instance memsets the scan
  response *data* and replaces `adv->flags`, while
  `hci_set_adv_instance_data()` assigns `adv->scan_rsp_len` **only when the new
  length is non-zero** — and `ADD_EXT_ADV_PARAMS` passes zero. `adv->scan_rsp_len`
  is assigned in exactly one place in the whole file, so it can never return to 0.
- **Independently checked:** yes — read `eir_create_scan_rsp`, the `DEFINE_FLEX`
  caller, and both `hci_core.c` sites.
- **Same shape as verified bug C4:** a validator runs once at set time and a
  later unvalidated write invalidates its conclusion.

### C6 — load_long_term_keys / load_irks: deterministic UAF of `smp->ltk`
- **File:** `net/bluetooth/mgmt.c:7370` (`hci_smp_ltks_clear`) → sinks at
  `net/bluetooth/smp.c:1068` and `:753`; IRK twin at `mgmt.c:7286` → `smp.c:1036`.
- **Class:** slab use-after-free (1-byte write, then 6-byte `bacpy` write) and
  double `kfree_rcu`.
- **Status:** candidate, high confidence, **not attempted** — see cost note.
- **What:** `struct smp_chan` caches raw pointers (`smp->ltk`,
  `smp->responder_ltk`) to list-owned `smp_ltk` objects.
  `MGMT_OP_LOAD_LONG_TERM_KEYS` calls `hci_smp_ltks_clear()`, which
  `list_del_rcu` + `kfree_rcu`s every key with no notification to a live SMP
  session. `smp_notify_keys()` then does `smp->ltk->bdaddr_type = ...`.
- **Strongest evidence it is an oversight:** the correct guard exists elsewhere.
  `smp_cancel_and_remove_pairing()` explicitly NULLs `smp->ltk`,
  `smp->responder_ltk` and `smp->remote_irk` before teardown, with the comment
  *"Set keys to NULL to make sure smp_failure() does not try to remove and free
  already invalidated rcu list entries."* `load_long_term_keys()` performs the
  identical invalidation without that step.
- **Deterministic, not a race:** both sides are serialized under `hdev->lock`
  and ordered purely by userspace.
- **Cost note (why not attempted):** reaching `smp->ltk` requires an established
  encrypted LE link — `smp_allow_key_dist()` is only called from
  `smp_distribute_keys()`, and the `allow_cmd` bitmask enforces the phase order
  strictly. That means driving full Just-Works legacy pairing over injected
  L2CAP frames, including a valid `c1()` Pairing Confirm, i.e. implementing
  AES-128 in the reproducer. Deferred in favour of C5, whose reproducer is six
  mgmt commands.

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

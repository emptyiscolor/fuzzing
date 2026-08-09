# Candidates — analysed but NOT verified

Nothing in this file has been reproduced. Each entry states what stopped it, so
the next person can judge whether to spend the effort. Ranked by my confidence
that the defect is real.

---

## C7 — VERIFIED, moved out of this file

The sctp `stream->outcnt` underflow was reproduced and now lives in
`cases/sctp-reconf-outcnt-underflow/`, with a userspace SCTP peer as the
reproducer and a negative control. Left as a pointer here so the numbering
in earlier notes still resolves.

---

## C6 — Bluetooth: deterministic UAF of `smp->ltk` via `load_long_term_keys`

**Site:** `net/bluetooth/mgmt.c:7370` (`hci_smp_ltks_clear`) → sinks at
`net/bluetooth/smp.c:1068` (1-byte UAF write then a 6-byte `bacpy`) and `:753`
(UAF read plus a second `kfree_rcu`). IRK twin at `mgmt.c:7286` → `smp.c:1036`.
**Confidence:** high

`struct smp_chan` caches raw pointers (`smp->ltk`, `smp->responder_ltk`) into
list-owned `smp_ltk` objects. `MGMT_OP_LOAD_LONG_TERM_KEYS` calls
`hci_smp_ltks_clear()`, which `list_del_rcu` + `kfree_rcu`s every key without
notifying a live SMP session. Deterministic, not a race — both sides are
serialized under `hdev->lock` and ordered purely by userspace.

The strongest evidence that this is an oversight is that the guard already exists
on a neighbouring path: `smp_cancel_and_remove_pairing()` explicitly NULLs
`smp->ltk`, `smp->responder_ltk` and `smp->remote_irk` before teardown, with the
comment *"Set keys to NULL to make sure smp_failure() does not try to remove and
free already invalidated rcu list entries."* `load_long_term_keys()` performs the
identical invalidation without that step.

**Why it was not verified.** `smp->ltk` is only set during phase 3 key
distribution, and `smp_allow_key_dist()` is reached only from
`smp_distribute_keys()` with the `allow_cmd` bitmask enforcing phase order
strictly. A reproducer must drive full Just-Works legacy pairing over injected
L2CAP frames including a valid `c1()` Pairing Confirm — i.e. implement AES-128 in
userspace.

---

## C1 / C2 — sctp: ASCONF `SCTP_PARAM_ERR_CAUSE` length handling

`net/sctp/sm_make_chunk.c:3213` (missing guard); over-read at `:3327` and
`:3441`, plus a padded/unpadded walk desynchronisation at `:3459-3461`.

`sctp_verify_asconf()` enforces a per-type minimum length for every accepted
ASCONF parameter except `SCTP_PARAM_ERR_CAUSE`, whose case arm is a bare
`break;`, while its siblings in the same switch are pinned to
`sizeof(struct sctp_addip_param)`. Consumers read `crr_id` at offset 4..7 and
`sctp_add_asconf_response()` mails the value back to the peer.

**Not verifiable with this setup:** the over-read lands in skb tailroom, still
inside the `skb->head` slab allocation, so KASAN is silent by construction. This
is KMSAN-class (uninitialised value), and KMSAN needs a separate,
KASAN-incompatible build. Real, but a hardening fix rather than a crash.

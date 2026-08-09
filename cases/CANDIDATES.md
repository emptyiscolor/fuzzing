# Candidates — analysed but NOT verified

Nothing in this file has been reproduced. Each entry states what stopped it, so
the next person can judge whether to spend the effort. Ranked by my confidence
that the defect is real.

---

## C7 — sctp: `stream->outcnt` u16 underflow via a replayed RECONF response

**Site:** `net/sctp/stream.c:1050`, committed at `:1060`
**Class:** integer underflow on long-lived state → out-of-range stream count
**Confidence:** high that the defect is real; medium on exploit impact

```c
__u16 number;
nums   = ntohs(addstrm->number_of_streams);
number = stream->outcnt - nums;          /* no floor */
...
} else {                                  /* result != PERFORMED */
        sctp_stream_outq_migrate(stream, NULL, number);
        stream->outcnt = number;
}
```

`stream->outcnt` and `number` are both `__u16`.

**Why a response can be applied twice — confirmed by reading the code directly:**
`sctp_process_strreset_resp()` resolves a response through
`sctp_chunk_lookup_strreset_param()`, which walks the params of our own retained
`asoc->strreset_chunk` and returns the **first** whose `request_seq` matches the
response's `response_seq`. It keeps **no record of which request sequence numbers
have already been answered**. The chunk itself is only released once
`asoc->strreset_outstanding` reaches 0:

```c
asoc->strreset_outstanding--;
asoc->strreset_outseq++;
if (!asoc->strreset_outstanding) {
        ...
        sctp_chunk_put(asoc->strreset_chunk);
        asoc->strreset_chunk = NULL;
}
```

So when the local side requested **both** ADD_OUT and ADD_IN,
`sctp_make_strreset_addstrm()` emits two params with `request_seq = S` and
`S+1` and `strreset_outstanding == 2`. Two responses both carrying
`response_seq = S` therefore both resolve to the **same ADD_OUT param**, and the
subtraction at `:1050` runs twice against an already-rolled-back `outcnt`.
`sctp_verify_reconf()` explicitly permits RESET_RESPONSE to follow
RESET_RESPONSE, and `sctp_sf_do_reconf()` processes every param in the chunk, so
both can arrive in a single injected chunk.

Concretely with `sinit_num_ostreams = 10` and `SCTP_ADD_STREAMS` of 100:
outcnt 10 → 110 at request time; first DENIED response rolls it back to 10;
second DENIED response computes `10 - 100` → **65446**.

The `SCTP_STRRESET_PERFORMED` branch is harmless on underflow — the bug needs
`result` to be neither PERFORMED nor IN_PROGRESS (e.g. `DENIED == 3`), which is a
peer-chosen 32-bit field. `sctp_stream_outq_migrate(stream, NULL, 65446)` is a
no-op for the underflowed value, so nothing catches it before the commit.

**Sinks:** `sctp_stream_free()` `:189` (loop to `outcnt`, dereferences
`SCTP_SO(stream, i)->ext`), `sctp_stream_clear()` `:199` (write), and the
`sinfo_stream >= asoc->stream.outcnt` gate in `sctp_sendmsg_to_asoc()`, which
would then admit stream ids up to 65445.

**Detectability nuance — this matters:** `SCTP_SO()` is `genradix_ptr()`, which
returns **NULL** for an index whose node was never preallocated rather than
walking off an allocation. The observable failure is therefore a NULL-pointer
dereference, not a slab OOB. The audit's original detection pattern would have
scored that as a clean run; it has since been widened to match `null-ptr-deref`.

**Why it was not verified.** Reaching the double-resolve needs the victim to have
two outstanding reconf requests *and* to receive two crafted responses before a
legitimate one arrives. A real kernel peer answers immediately over loopback and
clears the state, so a reproducer needs a **userspace SCTP peer**: CRC32c
checksumming, an INIT / INIT-ACK / COOKIE-ECHO / COOKIE-ACK handshake with a
SUPPORTED_EXT param advertising RECONF, plus veth and a static neighbour entry so
the peer address is not local (otherwise the host stack ABORTs the INIT itself).
That is roughly 400-500 lines and was out of budget. It is the best remaining
lead in `net/sctp`.

**Minimal fix shape:** reject a response whose `request_seq` has already been
consumed, or clamp with `if (nums > stream->outcnt) break;` before line 1050.

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

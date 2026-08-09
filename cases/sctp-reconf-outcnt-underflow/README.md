# sctp: `stream->outcnt` u16 underflow via a replayed RECONF response

**Class:** integer underflow on long-lived association state → out-of-range
stream count → NULL-pointer dereference in the teardown path
**Site:** `net/sctp/stream.c:1050` (subtraction), committed at `:1060`;
root cause in `sctp_chunk_lookup_strreset_param()` at `:483`
**Reachable by:** a remote SCTP peer. No local privilege on the victim is
needed beyond having an association with a reconf-capable peer.
**Verified:** `KASAN: null-ptr-deref` / `general protection fault` in
`sctp_stream_free_ext` ← `sctp_stream_free` ← `sctp_association_free`

## Defect

`sctp_process_strreset_resp()` resolves a Re-configuration Response through
`sctp_chunk_lookup_strreset_param()`, which walks the parameters of our own
retained `asoc->strreset_chunk` and returns the **first** whose `request_seq`
matches. It keeps **no record of which request sequence numbers have already
been answered**, and the chunk is only released once `strreset_outstanding`
reaches zero.

`sctp_make_strreset_addstrm()` emits the add-out and add-in parameters with
`request_seq` S and S+1 and leaves `strreset_outstanding` at 2. A peer that
answers **twice with `response_seq = S`** therefore resolves the same add-out
parameter both times, and the add-out handler computes

```c
nums   = ntohs(addstrm->number_of_streams);
number = stream->outcnt - nums;          /* both __u16, no floor */
...
} else {
        stream->outcnt = number;
}
```

against an already rolled-back count. Any `result` other than
`SCTP_STRRESET_PERFORMED` takes that branch — the reproducer uses
`SCTP_STRRESET_DENIED (0x02)`.

With 10 outbound streams and an add of 100: `outcnt` goes 10 → 110 at request
time, back to 10 on the first response, then to **65446** on the second.

`sctp_verify_reconf()` explicitly permits `RESET_RESPONSE` to follow
`RESET_RESPONSE` (`last != SCTP_PARAM_RESET_RESPONSE` is an accepted
predecessor) and allows up to three parameters, so both responses fit in one
chunk.

## Why a userspace SCTP peer was required

A real kernel peer answers the reconf request immediately over loopback, which
clears `strreset_outstanding` and frees `asoc->strreset_chunk` before anything
can be replayed. The reproducer therefore speaks SCTP itself:

- **TUN in `IFF_TUN` mode**, not `AF_PACKET`. `AF_PACKET` can only transmit
  *outbound*; TUN injects packets that arrive **inbound** at the victim, and raw
  IP mode removes all MAC/ARP plumbing.
- The peer address `192.168.9.2` is **never assigned locally**, so the host SCTP
  stack does not ABORT the victim's INIT itself.
- CRC32c (Castagnoli, reflected `0x82F63B78`), stored little-endian, for the
  SCTP checksum, plus IP header and checksum construction.
- The INIT-ACK carries a `STATE_COOKIE` (opaque — the victim just echoes it)
  and a `SUPPORTED_EXT` advertising `SCTP_CID_RECONF`, which is what sets
  `asoc->peer.reconf_capable` and lets `SCTP_ADD_STREAMS` proceed.
- Every packet sent to the victim must carry the **victim's** verification tag
  (its own initiate tag from the INIT) — *not* the tag on the victim's later
  packets, which is the peer's. Getting this wrong makes the handshake time out.

## Evidence

`diagnosis/sctp-reconf-outcnt-crash.log`

```
Oops: general protection fault, probably for non-canonical address 0xdffffc0000000001
KASAN: null-ptr-deref in range [0x0000000000000008-0x000000000000000f]
RIP: 0010:sctp_stream_free_ext+0x61/0x120
Call Trace:
 sctp_stream_free+0x6f/0xd0
 sctp_association_free+0x21c/0x660
 sctp_do_sm+0x1edb/0x4720
 sctp_primitive_ABORT+0x8a/0xc0
 sctp_close+0x17e/0x600
 __x64_sys_close+0x7b/0xc0
```

`RBP = 0x7e` (126) is the loop index at the fault — the walk had passed the
populated genradix nodes on its way to 65446. `SCTP_SO()` is `genradix_ptr()`,
which returns NULL for an index whose node was never allocated, hence a NULL
dereference rather than a slab overrun. This is precisely the case that the
audit's original detection pattern would have scored as a clean run; the pattern
was widened to match `null-ptr-deref` before this was run.

**One honest caveat:** the reproducer also attempts a `sendmsg()` on stream
60000 as a second sink. That returned `EINVAL` and is *not* evidence of
anything — most likely the hand-rolled `SCTP_SNDRCV` control message is
malformed. Only the close/teardown path is demonstrated here.

## Upstream status

Present at `origin/master` `b643e495ae92`. No fix merged. Found during this
audit after four independent static passes over `net/sctp` had otherwise gone
dry; it was recorded as candidate C7 and then verified.

## Files

- `reproducer/sctp-reconf-outcnt-underflow.c` — PoC with the userspace peer
- `reproducer/sctp-reconf-outcnt-control.c` — negative control: one response
  instead of two, everything else identical
- `reproducer/common.h`
- `reproducer/0001-*.patch` — proposed fix (compile-tested): only roll back when
  the subtraction is valid
- `diagnosis/sctp-reconf-outcnt-crash.log`

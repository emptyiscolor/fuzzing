# Memory-safety audit of `net/` — findings

**Tree:** `torvalds/linux` @ `06cf61899` (2026-08-08)
**Scope:** out-of-bounds access, integer overflow/underflow, use-after-free.
Race conditions and pure memory leaks were explicitly out of scope.
**Verification standard:** a finding counts as *verified* only if a reproducer
trips a sanitizer on an instrumented kernel and the report is captured. Static
reasoning alone yields a *candidate*, never a verified bug.

**Environment:** x86-64 kernel built with clang 18 (`LLVM=1`), `KASAN_INLINE`,
`UBSAN`, `STACKPROTECTOR_STRONG`, `SLUB_DEBUG_ON`, `FAILSLAB`, booted under
QEMU (TCG; no KVM available). Reproducers are static binaries in a busybox
initramfs, driven by `verify.sh` / `verify2.sh`.

---

## 1. VERIFIED — SCTP: `sctp_make_asconf_update_ip()` under-reserves the ASCONF chunk

**File:** `net/sctp/sm_make_chunk.c:2877-2878` (sizing) vs `:2908-2916` (fill)
**Class:** out-of-bounds write (12 bytes past the reserved chunk)
**Impact:** unprivileged local denial of service (kernel `BUG`). Absent
`skb_put()`'s assertion this would be a controlled heap overflow into
`skb_shared_info`.

### Defect

The chunk is sized in a first pass and filled in a second. When
`asoc->asconf_addr_del_pending` is set, the sizing pass charges the extra
`DEL_IP` parameter using the address-parameter length of the address being
walked in the **caller's array**:

```c
addr_param_len = af->to_addr_param(addr, &addr_param);   /* addrs[i] */
totallen += paramlen;
totallen += addr_param_len;
addr_buf += af->sockaddr_len;
if (asoc->asconf_addr_del_pending && !del_pickup) {
        /* reuse the parameter length from the same scope one */
        totallen += paramlen;
        totallen += addr_param_len;          /* <-- addrs[i]'s length */
        del_pickup = 1;
}
```

but the fill pass recomputes that length from `asconf_addr_del_pending`'s **own**
address family:

```c
addr = asoc->asconf_addr_del_pending;
af = sctp_get_af_specific(addr->v4.sin_family);
addr_param_len = af->to_addr_param(addr, &addr_param);   /* its own length */
sctp_addto_chunk(retval, paramlen, &param);
sctp_addto_chunk(retval, addr_param_len, &addr_param);
```

The comment states the assumption ("the same scope one") that nothing enforces.
A pending-delete IPv6 address (20-byte address parameter) combined with IPv4
additions (8-byte) under-reserves by exactly **12 bytes**.

Note the sizing pass's `addr_param_len` is whatever the loop variable held on
the iteration where `del_pickup` was latched — i.e. `addrs[0]` — so it is not
even related to the pending address.

### Reachability

The non-obvious part, and the likely reason fuzzers have not hit it: the
**endpoint** and **association** bind lists must disagree.

* `sctp_bindx_rem()` returns `-EBUSY` unless the *endpoint* holds >= 2 addresses.
* The `del_pending` branch requires `sctp_find_unmatch_addr() == NULL &&
  addrcnt == 1`, i.e. the *association* holds exactly the one address being
  removed.

The lever is address scoping. `sctp_in_scope()` under the default
`SCTP_SCOPE_POLICY_ENABLE` copies an endpoint address into a new association
only when `addr_scope <= peer_scope`, ordered
`GLOBAL(0) < PRIVATE(1) < LINK(2) < LOOPBACK(3)`. Associating with a
**global-scope** peer therefore leaves PRIVATE IPv4 addresses on the endpoint
but out of the association.

Sequence (all plain `setsockopt`, no packet injection):

1. bind a global IPv6 address — endpoint `{v6g}`
2. `bindx_add` a private IPv4 — endpoint `{v6g, v4p}`, no association yet
3. `connect()` to a global IPv6 peer — association `{v6g}` only
4. `bindx_rem` the IPv6 — arms `asconf_addr_del_pending` with a v6 address
5. `bindx_add` N private IPv4 addresses — builds the ASCONF and overruns

Requires `net.sctp.addip_enable` (and `addip_noauth_enable` to skip AUTH), both
netns-scoped and writable by the namespace owner.

### Evidence

`findings/evidence/sctp-asconf-oob-crash.log`

```
kernel BUG at net/core/skbuff.c:214!
Oops: invalid opcode: 0000 [#1] SMP KASAN NOPTI
RIP: 0010:skb_over_panic+0x14f/0x160
Call Trace:
 skb_put+0x110/0x1f0
 sctp_make_asconf_update_ip+0xb08/0xdb0
 sctp_send_asconf_add_ip+0x85f/0xad0
 sctp_setsockopt+0x778/0xed0
 do_sock_setsockopt+0x113/0x140
 __x64_sys_setsockopt+0x13f/0x180
```

Reached from an unprivileged `unshare(CLONE_NEWUSER|CLONE_NEWNET)`.

Whether the 12-byte overrun escapes the allocation depends on where the chunk
size falls relative to the kmalloc bucket, since `alloc_skb` rounds the data
area to 64 bytes and then adds `skb_shared_info`. The reproducer sweeps the
add-count; it fired at **n=21**. (My a-priori estimate of n=9 was wrong — the
mechanism prediction held, the slack arithmetic did not, which is precisely
why the sweep exists.)

### Negative control

`repro/sctp-asconf-control.c` runs the identical sequence with the arming
`bindx_rem` removed. It completes all 24 iterations with no report
(`findings/evidence/sctp-asconf-NEGATIVE-CONTROL.log`). This is what makes the
crash attributable to the del-pickup mismatch rather than to adding N addresses.

### Suggested fix

Compute the del-pickup reservation from the pending address itself:

```c
if (asoc->asconf_addr_del_pending && !del_pickup) {
        struct sctp_af *daf =
            sctp_get_af_specific(asoc->asconf_addr_del_pending->v4.sin_family);
        union sctp_addr_param dparam;

        totallen += paramlen;
        totallen += daf->to_addr_param(asoc->asconf_addr_del_pending, &dparam);
        del_pickup = 1;
}
```

---

## 2. VERIFIED — Bluetooth: unbounded encryption key size corrupts `ltk->enc_size`

**File:** `net/bluetooth/hci_event.c:745,769` (unbounded write)
→ `net/bluetooth/hci_event.c:6720-6721` (sinks)
**Class:** out-of-bounds slab read (239 bytes past a 72-byte object), stack
buffer overflow, and `size_t` underflow in a `memset` length.
**Introduced by:** `c82b6357a546` ("Bluetooth: hci_event: Fix not using key
encryption size when its known", 2025-04-30) — itself a fix for a regression
from `522e9ed157e3`.

### Defect

`hci_cc_read_enc_key_size()` takes the key size verbatim from a Command
Complete event and writes it back into the persistent key object:

```c
conn->enc_key_size = rp->key_size;              /* raw u8, 0..255, off the wire */
...
if (conn->enc_key_size < hdev->min_enc_key_size ||
    (key_enc_size && conn->enc_key_size < *key_enc_size)) { ... }
...
if (key_enc_size && *key_enc_size != conn->enc_key_size)
        *key_enc_size = conn->enc_key_size;     /* no upper bound */
```

Both checks are **downgrade** checks (`<`) and by construction permit
arbitrarily large values. The introducing commit's message confirms the author
reasoned only about smaller values: *"attempts to check that there is no
downgrade of security if HCI_OP_READ_ENC_KEY_SIZE returns a value smaller than
what has been previously stored."*

For an LE link `hci_conn_key_enc_size()` returns `&ltk->enc_size` of the stored
`struct smp_ltk`, whose `val[]` is 16 bytes. The validators that normally bound
that field — `ltk_is_valid()` (rejects `enc_size > sizeof(val)`) and
`check_enc_key_size()` — run at key **install** time, so this later write
bypasses both.

The corrupted field is then used as a length in `hci_le_ltk_request_evt()`:

```c
struct hci_cp_le_ltk_reply cp;                  /* 18 bytes, on the stack */
memcpy(cp.ltk, ltk->val, ltk->enc_size);
memset(cp.ltk + ltk->enc_size, 0, sizeof(cp.ltk) - ltk->enc_size);
```

With `enc_size = 0xFF`: a 255-byte read from a 16-byte field, a 255-byte write
into a 16-byte stack array, and a `memset` whose length `16 - 255` underflows
`size_t`.

### Why the event is accepted at all

`hci_cmd_complete_evt()` selects the handler purely from the opcode carried in
the event, with no correlation against a command the host actually sent, so the
Command Complete can be injected **unsolicited**. Separately,
`hci_read_enc_key_size()` is only ever *sent* for ACL links, but the *handler*
re-resolves the connection from an attacker-chosen handle and never re-checks
`conn->type` — so an LE connection can be targeted.

### Reachability

Local only, no remote peer: `/dev/vhci` (`CONFIG_BT_HCIVHCI`) accepts arbitrary
injected HCI events, and the mgmt channel installs the LTK. Needs
`CAP_NET_ADMIN`. The reproducer emulates enough of a controller (answering the
kernel's init command sequence) to reach `HCI_UP`.

### Evidence

`findings/evidence/bt-enckeysize-oob-crash.log`

```
BUG: KASAN: slab-out-of-bounds in hci_le_ltk_request_evt+0x309/0xa00
Read of size 255 at addr ffff88800d06f558 by task kworker/u5:0/65
 __asan_memcpy+0x29/0x70
 hci_le_ltk_request_evt+0x309/0xa00
 hci_event_packet+0x627/0xa80
 hci_rx_work+0x31c/0x700

The buggy address belongs to the object at ffff88800d06f520
 which belongs to the cache kmalloc-96 of size 96
The buggy address is located 56 bytes inside of
 allocated 72-byte region        <-- offset 56 == struct smp_ltk .val[16]
Allocated by task ...:
 hci_add_ltk+0x175/0x310
 load_long_term_keys+0x409/0x950

UBSAN: array-index-out-of-bounds in net/bluetooth/hci_event.c:6721:16
index 255 is out of range for type '__u8[16]'
```

Two independent sanitizers on the same call path — KASAN on the `memcpy`
source, UBSAN on the `memset` index.

### Suggested fix

Bound the value before storing it:

```c
if (rp->key_size > sizeof(((struct smp_ltk *)0)->val)) {
        bt_dev_err(hdev, "invalid key size %u for handle %u",
                   rp->key_size, handle);
        status = HCI_ERROR_AUTH_FAILURE;
        goto done;
}
```

`hci_conn_key_enc_size()` also returns `&link_key->pin_len` for ACL links, so
the same unbounded write reaches that field; any fix should cover both.

---

## 3. VERIFIED — Bluetooth: `eir_create_scan_rsp()` stack overflow via stale `scan_rsp_len`

**File:** `net/bluetooth/eir.c:370-375` (unsized write), destination allocated at
`net/bluetooth/hci_sync.c:1528`; enabled by `net/bluetooth/hci_core.c:1699`
(flags replaced) and `:1771-1775` (length not reset).
**Class:** stack buffer overflow — 4 bytes past a 251-byte on-stack array.
**Impact:** kernel panic (stack-protector). The overwritten bytes are
attacker-influenced advertising data.

### Defect

`eir_create_scan_rsp()` takes **no size parameter**, unlike its sibling
`eir_create_adv_data(struct hci_dev *hdev, u8 instance, u8 *ptr, u8 size)`:

```c
u8 eir_create_scan_rsp(struct hci_dev *hdev, u8 instance, u8 *ptr)
{
        ...
        if ((adv->flags & MGMT_ADV_FLAG_APPEARANCE) && hdev->appearance)
                scan_rsp_len = eir_append_appearance(hdev, ptr, scan_rsp_len);   /* +4 */

        memcpy(&ptr[scan_rsp_len], adv->scan_rsp_data, adv->scan_rsp_len);
```

The destination is a 251-byte flexible array on the **stack**:

```c
DEFINE_FLEX(struct hci_cp_le_set_ext_scan_rsp_data, pdu, data, length,
            HCI_MAX_EXT_AD_LENGTH);        /* HCI_MAX_EXT_AD_LENGTH == 251 */
...
len = eir_create_scan_rsp(hdev, instance, pdu->data);
```

so `4 + 251 = 255` bytes are written into `data[251]`.

### Why the validator does not prevent it

That combination is supposed to be unreachable: `tlv_data_max_len()` subtracts 4
for `MGMT_ADV_FLAG_APPEARANCE`, so a 251-byte scan response only passes
`tlv_data_is_valid()` while that flag is **clear**. The bypass is that the flag
and the length are set by different commands, and only one of them is reset:

```c
/* hci_add_adv_instance(), on an EXISTING instance */
memset(adv->scan_rsp_data, 0, sizeof(adv->scan_rsp_data));   /* clears the DATA */
...
adv->flags = flags;                                          /* replaces the FLAGS */

/* hci_set_adv_instance_data() */
if (scan_rsp_len && SCAN_RSP_CMP(adv, scan_rsp_data, scan_rsp_len)) {
        ...
        adv->scan_rsp_len = scan_rsp_len;    /* assigned ONLY when non-zero */
}
```

`MGMT_OP_ADD_EXT_ADV_PARAMS` passes `scan_rsp_len = 0`, so re-issuing it for an
existing instance swaps in a new `flags` value while the previously validated
length survives. `adv->scan_rsp_len` is assigned in exactly one place in the
file, so it can never return to 0.

This is the same shape as finding 2: **a validator runs once at set time and a
later unvalidated write invalidates its conclusion.** Finding 3 was found by
generalizing that shape rather than by auditing fresh code.

### Reachability

Local only, no remote peer: `/dev/vhci` plus the mgmt channel, `CAP_NET_ADMIN`.
The emulated controller must advertise `HCI_LE_EXT_ADV` in
`le_features[1]` (so `ext_adv_capable()` holds and `max_adv_len()` is 251) and a
non-zero `LE Read Number of Supported Advertising Sets`. Sequence:

1. `MGMT_OP_SET_POWERED`, `MGMT_OP_SET_LE`, `MGMT_OP_SET_APPEARANCE` (non-zero)
2. `ADD_EXT_ADV_PARAMS` instance 1, `flags = 0`
3. `ADD_EXT_ADV_DATA` instance 1, `scan_rsp_len = 251`  → validates, stores 251
4. `ADD_EXT_ADV_PARAMS` instance 1, `flags = MGMT_ADV_FLAG_APPEARANCE`  ← arms
5. `ADD_EXT_ADV_DATA` instance 1, `scan_rsp_len = 0`  ← triggers the sync

### Evidence

`findings/evidence/bt-scanrsp-stackoob-crash.log`

```
Kernel panic - not syncing: stack-protector: Kernel stack is corrupted in:
    hci_set_ext_scan_rsp_data_sync+0x3b5/0x3e0
Workqueue: hci0 hci_cmd_sync_work
Call Trace:
 __stack_chk_fail+0x26/0x30
 hci_set_ext_scan_rsp_data_sync+0x3b5/0x3e0
 add_ext_adv_data_sync+0xaf/0x140
 hci_cmd_sync_work+0x222/0x2f0
```

**Prediction that was wrong, recorded:** this was expected to require
`CONFIG_KASAN_STACK=y`, on the assumption that 4 bytes would land in adjacent
stack slots rather than on the canary. It does not —
`CONFIG_STACKPROTECTOR_STRONG` catches it directly on the same kernel used for
findings 1 and 2. (A `KASAN_STACK` rebuild was attempted and failed for an
unrelated reason: `-Werror` plus a frame-size warning in `lib/maple_tree.c`. The
config was restored to match the kernel that produced all three results.)

### Negative control

`repro/bt-scanrsp-control.c` runs the identical sequence — same 251-byte scan
response, same trigger — with only step 4 (the flag re-issue) removed. It
completes clean (`REPRO_EXIT=0`, no report), which attributes the panic to the
flags/length desynchronisation rather than to the long scan response itself.

### Suggested fix

Give `eir_create_scan_rsp()` a `size` parameter like its sibling and bound the
copy, and/or reset `adv->scan_rsp_len` when the instance's data is cleared in
`hci_add_adv_instance()`. Re-validating the stored length against
`tlv_data_max_len(hdev, new_flags, false)` whenever `adv->flags` changes would
close the whole class.

---

## Unverified candidates

These are real code defects confirmed by inspection, but **not** verifiable with
this setup, and are reported as such.

### C1 — SCTP: missing length check on `SCTP_PARAM_ERR_CAUSE`

`net/sctp/sm_make_chunk.c:3213` (missing guard); over-read at `:3327` and
`:3441`. `sctp_verify_asconf()` enforces a per-type minimum length for every
accepted ASCONF parameter except `SCTP_PARAM_ERR_CAUSE`, whose case arm is a
bare `break;`. Its siblings in the same switch (`SCTP_PARAM_SUCCESS_REPORT`,
`SCTP_PARAM_ADAPTATION_LAYER_IND`) are both pinned to
`sizeof(struct sctp_addip_param)` (8). Consumers unconditionally treat the
parameter as a `struct sctp_addip_param` and read `crr_id` at offset 4..7, so a
4-byte `ERR_CAUSE` parameter placed last is read past `chunk_end`, and
`sctp_add_asconf_response()` copies the value into the outgoing ASCONF-ACK —
mailing the bytes back to the peer.

**Not verifiable here:** the 4 bytes land in skb tailroom, still inside the
`skb->head` slab allocation, so KASAN is silent by construction. This is a
KMSAN-class (uninitialised value) finding, and KMSAN requires a separate,
KASAN-incompatible build.

### C2 — SCTP: padded/unpadded walk desynchronisation

`net/sctp/sm_make_chunk.c:3459-3461`. The validator walks with
`sctp_walk_params()` (advancing by `SCTP_PAD4(length)`) while
`sctp_get_asconf_response()` advances by the raw unpadded `ntohs(length)`.
Enabled by C1's missing constraint, a non-4-aligned `ERR_CAUSE` desynchronises
the two walks. Same slab-internal read limitation as C1.

### C7 — SCTP: `stream->outcnt` u16 underflow via a replayed RECONF response

`net/sctp/stream.c:1050` (`number = stream->outcnt - nums;`, both `__u16`, no
floor) committed at `:1060`. Sinks: `sctp_stream_free()` `:189`,
`sctp_stream_clear()` `:199` (write), and the
`sinfo_stream >= asoc->stream.outcnt` gate in `sctp_sendmsg_to_asoc()`.

`sctp_process_strreset_resp()` resolves a response via
`sctp_chunk_lookup_strreset_param()`, which matches purely on
`request_seq == response_seq` inside our own still-held `asoc->strreset_chunk`,
with **no record of which request sequence numbers have already been answered**.
When the local side requested both ADD_OUT and ADD_IN, `strreset_outstanding`
is 2 and the chunk is retained, so two responses both carrying the ADD_OUT
sequence number resolve to the same parameter and the subtraction runs twice
against an already-rolled-back `outcnt`.

**Not attempted, and note the detectability nuance:** `SCTP_SO()` is
`genradix_ptr()`, which returns **NULL** for an index whose node was never
preallocated rather than walking off an allocation. So the observable failure is
a NULL-pointer deref, not a slab OOB. That is a real memory-safety failure but
it would have been **missed by this audit's original detection pattern**, which
only matched KASAN/UBSAN/BUG headers — the pattern has since been widened to
include `null-ptr-deref`. Worth pursuing next; the reproducer needs raw
injection of a RECONF chunk with the negotiated verification tag.

### C6 — Bluetooth: deterministic UAF of `smp->ltk` via `load_long_term_keys`

`net/bluetooth/mgmt.c:7370` (`hci_smp_ltks_clear`) → sinks at
`net/bluetooth/smp.c:1068` (1-byte UAF write, then a 6-byte `bacpy`) and
`:753` (UAF read plus a second `kfree_rcu`). IRK twin at `mgmt.c:7286` →
`smp.c:1036`.

`struct smp_chan` caches raw pointers (`smp->ltk`, `smp->responder_ltk`) into
list-owned `smp_ltk` objects. `MGMT_OP_LOAD_LONG_TERM_KEYS` calls
`hci_smp_ltks_clear()`, which `list_del_rcu` + `kfree_rcu`s every key without
notifying a live SMP session. Deterministic, not a race: both sides are
serialized under `hdev->lock` and ordered purely by userspace.

The strongest evidence that this is an oversight is that the correct guard
already exists on a neighbouring path — `smp_cancel_and_remove_pairing()`
explicitly NULLs `smp->ltk`, `smp->responder_ltk` and `smp->remote_irk` before
teardown, with the comment *"Set keys to NULL to make sure smp_failure() does
not try to remove and free already invalidated rcu list entries."*
`load_long_term_keys()` performs the identical invalidation without that step.

**Not attempted** (rather than unverifiable): reaching `smp->ltk` requires an
established encrypted LE link, because `smp_allow_key_dist()` is only called
from `smp_distribute_keys()` and the `allow_cmd` bitmask enforces the phase
order strictly. A reproducer therefore has to drive full Just-Works legacy
pairing over injected L2CAP frames, including a valid `c1()` Pairing Confirm —
i.e. implement AES-128 in userspace. This was deprioritised in favour of
finding 3, whose reproducer is six mgmt commands. It is the most promising
remaining lead.

---

## Notes on method

**What the sanitizers can and cannot see.** The dominant lesson of this audit:
static analysis readily surfaces *missing length checks*, but most of those
produce a small over-read of an `sk_buff` payload, which stays inside the same
slab object — skbs carry tailroom and are rounded up to a kmalloc bucket — so
KASAN never fires. The classes that are actually verifiable are **writes past an
allocation** and **use-after-free**, plus reads whose corrupted length is large
relative to a *small* object. Both verified bugs are of that kind. Retargeting
the search on that basis is what produced them.

**Detection pattern widened twice, both times because it was too narrow.**
Second correction: it matched only KASAN/UBSAN/BUG headers, so a NULL-pointer
dereference — a genuine memory-safety failure, and the expected outcome of
candidate C7 — would have been scored as a clean run. `null-ptr-deref` and the
stack-protector panic string are now matched. All five evidence logs were
re-scored against the widened pattern: both negative controls remain at zero
matches, all three confirmed bugs still match on genuine reports.

**Harness defect found and corrected.** The initial detection pattern matched
the bare string `use-after-free`, which appears in the boot banner
`rcu: RCU callback double-/use-after-free debug is enabled.` That caused the
SCTP negative control to be reported as REPRODUCED when it had in fact run
clean. The pattern now matches report headers only. Both verified bugs were
re-checked against the corrected pattern and still match on genuine reports.
Recorded here because a detector that over-matches manufactures false positives.

**Negative results worth stating.** Two independent, thorough passes over
`net/sched` — one on netlink attribute parsing and array indexing, one on
error-path object lifetime — returned no defensible deterministic finding, each
with explicit self-rejection of its own candidates. Given that `net/sched` is
among the most continuously fuzzed code in the kernel, this is a meaningful
negative rather than a gap in coverage.

A fault-injection stress run over `net/sched` and protocol-socket construction
(4000 rounds, `repro/failslab-stress.c`) produced no report. This is **weak
evidence and should not be read as coverage**: the `FAILSLAB` debugfs knobs were
present, but the run was not instrumented to confirm that allocations were
actually being failed, so it is unknown how many error paths it genuinely
reached. Verifying the injection is live — e.g. by asserting that some
operations return `-ENOMEM` — is the first thing to fix before drawing any
conclusion from a clean run of it.

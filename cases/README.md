# Cases

One directory per finding:

```
cases/<case>/reproducer/   PoC sources + proposed .patch
cases/<case>/diagnosis/    raw console / KASAN logs, incl. negative controls
```

All findings were produced against `torvalds/linux` `06cf61899` (2026-08-08) and
re-checked against `origin/master` `b643e495ae92`.

| Case | Class | Verified by | Upstream status |
|------|-------|-------------|-----------------|
| `sctp-asconf-delpending-oob` | OOB write, 12 bytes past an skb | `kernel BUG` / `skb_over_panic` | **unique** — unfixed at `b643e495ae92` |
| `bt-enckeysize-ltk-oob` | OOB slab read + stack write + `memset` size underflow | `KASAN: slab-out-of-bounds` + `UBSAN` | **incomplete fix** of `b8dbe9648d69` — second path to the same sink, still open |
| `bt-scanrsp-stack-oob` | 4-byte stack OOB write | `stack-protector: Kernel stack is corrupted` | **unique** — unfixed at `b643e495ae92` |
| `sctp-reconf-outcnt-underflow` | u16 underflow of a stream count → NULL deref | `KASAN: null-ptr-deref` in `sctp_stream_free_ext` | **unique** — unfixed at `b643e495ae92` |

Filed separately because it is **not** a memory-safety bug:

| Case | Class | Verified by | Upstream status |
|------|-------|-------------|-----------------|
| `sched-emmeta-shift-oob` | undefined behaviour (shift exponent), no memory corruption | `UBSAN: shift-out-of-bounds` | unique — unfixed at `b643e495ae92` |

## Fix validation

The proposed patches are not just suggested diffs — they were **applied together
to the tree, compiled, and the reproducers re-run against the resulting
kernel**. All four went from crashing to clean, and each was checked to have
actually reached its trigger rather than failing early:

| Case | Unpatched kernel | Patched kernel |
|------|------------------|----------------|
| `sctp-asconf-delpending-oob` | `kernel BUG at net/core/skbuff.c:214` at n=21 | full n=1..24 sweep, every `trigger rc=0` |
| `bt-enckeysize-ltk-oob` | `KASAN: slab-out-of-bounds`, read of size 255 | full injection sequence, no report |
| `bt-scanrsp-stack-oob` | `stack-protector: Kernel stack is corrupted` | step1 -> step4 incl. ARM and TRIGGER, no report |
| `sctp-reconf-outcnt-underflow` | `KASAN: null-ptr-deref` in `sctp_stream_free_ext` | handshake + double response injected, no report |

The tree was reverted to pristine upstream afterwards; the patches live only as
`.patch` files under each case.

## How the duplicate check was done, and its limits

**Authoritative half (git).** The clone was unshallowed and `origin/master`
re-fetched. The 6 commits merged since the audit HEAD are all s390/zcrypt and
touch no networking file. The defective code for all four findings is present
verbatim at `b643e495ae92`, so **no fix for any of them has been merged**.
Related history was checked too: the tree already contains
`9de7922bc709` (CVE-2014-3673, ASCONF receive-path `skb_over_panic`),
`9b2854f86f0b` (the DEL-IP transport UAF, CVE-2026-64564 "SCTPhantom"), and
`b8dbe9648d69` (LTK `enc_size` validation on MGMT load) — all distinct from, or
only partially overlapping with, the findings here.

**Partial half (web search).** `lkml.org` and `lore.kernel.org` are both blocked
by this environment's egress policy, so the mailing-list archives could not be
queried directly and only general web search was available. That means a patch
**posted but not yet merged** could have been missed. The git half is
conclusive for merged fixes; the archive half is not conclusive for pending
ones.

## Reproducing

Requires the audit environment in `../kernel-audit` (clang-built kernel with
`KASAN_INLINE`, `UBSAN`, `STACKPROTECTOR_STRONG`, `SLUB_DEBUG_ON`, plus the
`configs/net-audit.config` fragment for `USER_NS`, SCTP and `BT_HCIVHCI`):

```
cd ../kernel-audit
./verify.sh  <path to reproducer>.c          # boot, run, scan for a report
./verify2.sh <path to reproducer>.c <name>   # second lane, runs concurrently
```

Exit status 0 means a memory-safety report fired. Each case that ships a
`*-control.c` also ships its clean run under `diagnosis/`; the control exists so
the crash can be attributed to the specific mechanism claimed rather than to the
surrounding setup.

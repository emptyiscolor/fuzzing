# net/sched: em_meta unvalidated shift exponent

**Class:** undefined behaviour (shift exponent >= `BITS_PER_LONG`).
**Not** an out-of-bounds access — see the severity note below.
**Site:** `net/sched/em_meta.c:766` (use), missing guard in `em_meta_change()`
**Reachable by:** an unprivileged process in a user+net namespace
**Verified:** `UBSAN: shift-out-of-bounds in net/sched/em_meta.c:766:14`

## Defect

```c
static void meta_int_apply_extras(struct meta_value *v, struct meta_obj *dst)
{
        if (v->hdr.shift)
                dst->value >>= v->hdr.shift;      /* dst->value is unsigned long */
```

`v->hdr` is a verbatim copy of the user-supplied
`struct tcf_meta_val { __u16 kind; __u8 shift; __u8 op; }`, so `shift` ranges
over 0..255. `em_meta_change()` validates only `TCF_META_TYPE()`,
`TCF_META_ID()`, and that the id has a `->get`; `shift` and `op` are never
bounded, in that function or anywhere else.

The asymmetry that let this survive: the variable-length sibling
`meta_var_apply_extras()` **is** guarded with `shift < dst->len`. Only the
integer path is unguarded.

## Severity — stated plainly

Shifting an `unsigned long` by >= 64 is undefined behaviour, but on x86 the CPU
masks the shift count to 63, so the consequence is a **wrong value, not a
memory-safety violation**. This does not meet the bar of the four
memory-safety cases in this directory and is filed separately for that reason.
It is worth fixing as UB and as an input-validation gap, not as an exploitable
bug.

## Evidence

`diagnosis/sched-emmeta-shift-ubsan.log`

```
UBSAN: shift-out-of-bounds in net/sched/em_meta.c:766:14
Call Trace:
 __ubsan_handle_shift_out_of_bounds+0x2d4/0x2f0
 meta_int_apply_extras+0xf0/0x100
 meta_get+0x144/0x330
 em_meta_match+0x84/0x1c0
 __tcf_em_tree_match+0x15e/0x540
 basic_classify+0xed/0x220
 tcf_classify+0x31c/0x4d0
 prio_enqueue+0x146/0x4e0
 __dev_queue_xmit+0xeed/0x23d0
```

## Config caveat — why earlier passes could not see this

The audit kernel could not reach or observe this until two options were turned
on:

- `CONFIG_NET_EMATCH_META` — off, so the filter would simply have been
  rejected. Note `CONFIG_NET_EMATCH=y` alone is **not** enough; every
  `NET_EMATCH_*` match kind is a separate option and all were off.
- `CONFIG_UBSAN_SHIFT` — off, so even once reached the shift would not have
  been reported.

This is worth recording because it was my own error: when briefing the auditing
agent I asserted that "all `NET_SCH_*`/`NET_CLS_*`/`NET_ACT_*` are built in",
without noticing the `NET_EMATCH_*` sub-options are separate. The agent caught
it and flagged that its finding was untestable in the stated config.

## Upstream status

Present at `origin/master` `b643e495ae92`; `git log -- net/sched/em_meta.c`
shows no fix.

## Fix validation

With `reproducer/0001-*.patch` applied, the filter is refused at configuration
time with `-EINVAL` and no UBSAN report is produced.

## Files

- `reproducer/sched-emmeta-shift.c` — PoC: dummy device, `prio` qdisc,
  `cls_basic` filter carrying an `em_meta` ematch with `shift = 255`, then
  traffic through the qdisc
- `reproducer/common.h`
- `reproducer/0001-*.patch` — proposed fix (compile-tested): reject a shift of
  `BITS_PER_LONG` or more for integer metadata at configure time
- `diagnosis/sched-emmeta-shift-ubsan.log`

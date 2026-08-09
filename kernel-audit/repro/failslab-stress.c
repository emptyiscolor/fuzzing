/* Fault-injection stress over net/ error paths.
 *
 * Rationale: the static audits keep surfacing missing length checks whose
 * over-read stays inside a slab object and is therefore invisible to KASAN.
 * The bug classes KASAN *does* catch reliably are use-after-free and writes
 * past an allocation, and in this subsystem those live overwhelmingly on
 * allocation-failure error paths -- code that never runs in normal operation
 * and that fuzzers reach only when they can force kmalloc to fail.
 *
 * CONFIG_FAILSLAB + CONFIG_FAULT_INJECTION_DEBUG_FS make those paths reachable
 * on demand. /proc/self/make-it-fail + task-filter confine the injected
 * failures to this process, so the rest of the system stays alive and any
 * report we get is attributable to the operation we just performed.
 *
 * This is a search, not a targeted reproducer: it drives a broad battery of
 * create/modify/destroy operations across net/sched, SCTP, and assorted
 * protocol sockets with allocations failing underneath, and lets KASAN decide
 * whether anything is wrong. A clean run proves nothing; a report is a lead.
 */
#include "common.h"
#include <netinet/in.h>

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

static int nl;
static int ifi;

static const char *QDISCS[] = {
	"qfq", "htb", "hfsc", "drr", "ets", "netem", "tbf", "red", "sfb",
	"sfq", "codel", "fq_codel", "cake", "fq", "hhf", "pie", "prio",
	"multiq", "gred", "plug", "choke", "cbs", "etf", "taprio",
};
#define NQDISC (int)(sizeof(QDISCS) / sizeof(QDISCS[0]))

static const char *CLS[] = { "u32", "basic", "fw", "route", "flow", "flower", "matchall" };
#define NCLS (int)(sizeof(CLS) / sizeof(CLS[0]))

/* Injection accounting. A clean stress run means nothing unless we can show
 * allocations were actually being failed, so count the -ENOMEM returns that
 * failslab produces. If this stays zero, the run exercised no error paths and
 * the result is vacuous. */
static unsigned long n_ops, n_enomem, n_othererr;

static void account(int rc)
{
	n_ops++;
	if (rc == -ENOMEM)
		n_enomem++;
	else if (rc < 0)
		n_othererr++;
}

static void qdisc_op(int type, int flags, const char *kind, unsigned handle,
		     unsigned parent)
{
	struct nlbuf b;
	struct tcmsg tcm;

	memset(&tcm, 0, sizeof(tcm));
	tcm.tcm_family = AF_UNSPEC;
	tcm.tcm_ifindex = ifi;
	tcm.tcm_handle = handle;
	tcm.tcm_parent = parent;

	nlb_init(&b, type, flags);
	nlb_put_hdr(&b, &tcm, sizeof(tcm));
	if (kind)
		nlb_put_str(&b, TCA_KIND, kind);
	account(nl_send(nl, &b));
}

static void filter_op(int type, int flags, const char *kind, unsigned parent,
		      unsigned prio)
{
	struct nlbuf b;
	struct tcmsg tcm;

	memset(&tcm, 0, sizeof(tcm));
	tcm.tcm_family = AF_UNSPEC;
	tcm.tcm_ifindex = ifi;
	tcm.tcm_parent = parent;
	tcm.tcm_info = (prio << 16) | htons(0x0003);   /* prio | ETH_P_ALL */

	nlb_init(&b, type, flags);
	nlb_put_hdr(&b, &tcm, sizeof(tcm));
	if (kind)
		nlb_put_str(&b, TCA_KIND, kind);
	account(nl_send(nl, &b));
}

/* Sockets whose setup/teardown allocates, so failslab exercises their
 * partial-construction paths. */
static void socket_churn(int round)
{
	static const int fam[][3] = {
		{ AF_INET,  SOCK_STREAM,    IPPROTO_SCTP },
		{ AF_INET6, SOCK_SEQPACKET, IPPROTO_SCTP },
		{ 30 /*AF_TIPC*/, SOCK_STREAM, 0 },
		{ 29 /*AF_CAN*/,  SOCK_RAW,    1 /*CAN_RAW*/ },
		{ 29 /*AF_CAN*/,  SOCK_DGRAM,  2 /*CAN_BCM*/ },
		{ 40 /*AF_VSOCK*/, SOCK_STREAM, 0 },
		{ AF_INET,  SOCK_DGRAM,     0 },
		{ AF_NETLINK, SOCK_RAW,     0 /*NETLINK_ROUTE*/ },
		{ AF_PACKET, SOCK_DGRAM,    0 },
	};
	int n = (int)(sizeof(fam) / sizeof(fam[0]));
	int i, s;

	for (i = 0; i < n; i++) {
		s = socket(fam[(i + round) % n][0], fam[(i + round) % n][1],
			   fam[(i + round) % n][2]);
		if (s >= 0) {
			/* Touch a few option paths that allocate. */
			int one = 1;
			setsockopt(s, SOL_SOCKET, SO_RCVBUF, &one, sizeof(one));
			setsockopt(s, SOL_SOCKET, SO_SNDBUF, &one, sizeof(one));
			close(s);
		}
	}
}

int main(void)
{
	int round;
	const int ROUNDS = 4000;

	logf("=== failslab stress over net/ error paths ===");
	enter_userns();

	nl = nl_open();
	{
		int lo = if_index("lo");
		if (lo > 0)
			link_up(nl, lo);
	}
	ifi = create_dummy(nl, "d0");
	if (ifi < 0)
		die("create dummy");
	link_up(nl, ifi);
	logf("d0 ifindex=%d", ifi);

	if (access("/sys/kernel/debug/failslab", F_OK) != 0)
		logf("WARN: failslab unavailable - running WITHOUT fault injection");

	for (round = 0; round < ROUNDS; round++) {
		const char *kind = QDISCS[round % NQDISC];
		const char *cls = CLS[round % NCLS];
		unsigned h = 0x10000u;

		/* Vary how aggressively allocations fail. Interval/times control
		 * WHICH allocation in the sequence fails, which is what walks the
		 * failure point through the middle of each construction. */
		failslab_arm(1, (round % 17) + 1, (round % 5) ? 100 : 0);

		qdisc_op(RTM_NEWQDISC, NLM_F_CREATE | NLM_F_REPLACE, kind, h, TC_H_ROOT);
		qdisc_op(RTM_NEWQDISC, NLM_F_CREATE | NLM_F_REPLACE, kind, h, TC_H_ROOT);
		filter_op(RTM_NEWTFILTER, NLM_F_CREATE | NLM_F_REPLACE, cls, h, 1 + (round % 8));
		filter_op(RTM_NEWTFILTER, NLM_F_CREATE | NLM_F_REPLACE, cls, h, 1 + (round % 8));
		socket_churn(round);
		filter_op(RTM_DELTFILTER, 0, cls, h, 1 + (round % 8));
		qdisc_op(RTM_DELQDISC, 0, NULL, h, TC_H_ROOT);

		failslab_disarm();

		if ((round % 250) == 0) {
			logf("round %d/%d  ops=%lu enomem=%lu othererr=%lu", round, ROUNDS, n_ops, n_enomem, n_othererr);
			/* Give RCU a chance to actually free things, so
			 * use-after-free has a window to be detected. */
			usleep(50000);
		}
	}

	logf("stress complete (%d rounds) ops=%lu enomem=%lu othererr=%lu",
	     ROUNDS, n_ops, n_enomem, n_othererr);
	if (n_enomem == 0)
		logf("VACUOUS: no allocation ever failed - fault injection was NOT active");
	return 0;
}

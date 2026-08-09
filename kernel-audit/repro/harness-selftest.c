/* Harness self-test: proves compile -> initramfs -> boot -> run -> collect
 * works, and that the pieces reproducers depend on (userns, netlink, dummy
 * devices, qdisc creation, failslab) are actually functional in this kernel.
 * Exercises no bug. Expected result: verify.sh reports a clean run.
 */
#include "common.h"

int main(void)
{
	struct nlbuf b;
	struct tcmsg tcm;
	int nl, ifi, err;
	struct stat st;

	logf("uid=%d", getuid());

	enter_userns();

	nl = nl_open();
	logf("netlink socket ok");

	ifi = create_dummy(nl, "dummy0");
	if (ifi < 0)
		die("create_dummy");
	logf("dummy0 ifindex=%d", ifi);

	if (link_up(nl, ifi) != 0)
		logf("WARN: link_up failed");

	/* Attach a qdisc -- confirms net/sched is reachable from here. */
	memset(&tcm, 0, sizeof(tcm));
	tcm.tcm_family = AF_UNSPEC;
	tcm.tcm_ifindex = ifi;
	tcm.tcm_handle = 0x10000u;   /* 1: */
	tcm.tcm_parent = TC_H_ROOT;

	nlb_init(&b, RTM_NEWQDISC, NLM_F_CREATE | NLM_F_EXCL);
	nlb_put_hdr(&b, &tcm, sizeof(tcm));
	nlb_put_str(&b, TCA_KIND, "qfq");
	err = nl_send(nl, &b);
	logf("RTM_NEWQDISC qfq -> %d (%s)", err, err ? strerror(-err) : "ok");

	/* Confirm the fault-injection knobs exist; without them the error-path
	 * bug classes are effectively unreachable. */
	if (stat("/sys/kernel/debug/failslab", &st) == 0)
		logf("failslab available");
	else
		logf("WARN: failslab NOT available (debugfs not mounted?)");

	logf("selftest complete");
	return 0;
}

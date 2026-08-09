/* Shared scaffolding for net/ reproducers.
 *
 * Everything here is deliberately dependency-free (no libmnl/libnl) so a
 * reproducer stays a single self-contained file that clang can build with
 * -static against the busybox initramfs.
 *
 * The usual shape of a net/sched reproducer:
 *      enter_userns();                 // unprivileged -> CAP_NET_ADMIN in netns
 *      int nl = nl_open();
 *      int ifi = create_dummy(nl, "dummy0");
 *      link_up(nl, ifi);
 *      ... build RTM_NEWQDISC / RTM_NEWTFILTER and nl_send() ...
 */
#ifndef REPRO_COMMON_H
#define REPRO_COMMON_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <signal.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <linux/if.h>
#include <linux/if_link.h>

#define logf(...) do { printf("[repro] " __VA_ARGS__); printf("\n"); fflush(stdout); } while (0)
#define die(...)  do { printf("[repro] FATAL: " __VA_ARGS__); printf(" (%s)\n", strerror(errno)); fflush(stdout); exit(1); } while (0)

/* ---- namespaces ---------------------------------------------------------
 * Unprivileged processes get CAP_NET_ADMIN *inside* a fresh user+net
 * namespace, which is what makes most of net/sched reachable without root.
 * This mirrors how syzkaller reaches this code.
 */
static void write_file(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY);
	if (fd < 0)
		return;
	if (write(fd, val, strlen(val)) < 0) { /* best effort */ }
	close(fd);
}

static void enter_userns(void)
{
	uid_t uid = getuid();
	gid_t gid = getgid();
	char buf[64];

	if (unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0) {
		/* Already root (our initramfs runs as uid 0) -- a plain netns
		 * unshare is enough and keeps full privileges. */
		if (unshare(CLONE_NEWNET) != 0)
			die("unshare(CLONE_NEWNET)");
		logf("running as root: netns only");
		return;
	}
	write_file("/proc/self/setgroups", "deny");
	snprintf(buf, sizeof(buf), "0 %d 1", uid);
	write_file("/proc/self/uid_map", buf);
	snprintf(buf, sizeof(buf), "0 %d 1", gid);
	write_file("/proc/self/gid_map", buf);
	logf("entered user+net namespace");
}

/* Netns only, deliberately WITHOUT CLONE_NEWUSER.
 *
 * Use this when the reproducer needs fault injection. proc_fault_inject_write()
 * gates /proc/<pid>/make-it-fail on capable(CAP_SYS_RESOURCE), which is checked
 * against the INIT user namespace -- so entering a user namespace silently
 * costs you the ability to arm failslab, and every injection attempt returns
 * -EPERM while the run still looks healthy. Reproducers that want to
 * demonstrate unprivileged reachability should use enter_userns() instead; this
 * one trades that away to keep init-namespace capabilities.
 */
static void enter_netns_only(void)
{
	if (unshare(CLONE_NEWNET) != 0)
		die("unshare(CLONE_NEWNET)");
	logf("entered netns only (kept init-userns caps for fault injection)");
}

/* ---- netlink ------------------------------------------------------------ */
static int nl_open(void)
{
	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };

	if (fd < 0)
		die("socket(AF_NETLINK)");
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		die("bind(netlink)");
	return fd;
}

/* Message builder. Deliberately raw so a reproducer can emit malformed or
 * hostile attributes that a well-behaved library would refuse to encode. */
struct nlbuf {
	char buf[8192];
	struct nlmsghdr *nlh;
};

static void nlb_init(struct nlbuf *b, int type, int flags)
{
	memset(b, 0, sizeof(*b));
	b->nlh = (struct nlmsghdr *)b->buf;
	b->nlh->nlmsg_len = NLMSG_LENGTH(0);
	b->nlh->nlmsg_type = type;
	b->nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
	b->nlh->nlmsg_seq = 1;
}

static void *nlb_put_hdr(struct nlbuf *b, const void *hdr, size_t len)
{
	void *p = (char *)b->buf + NLMSG_ALIGN(b->nlh->nlmsg_len);
	memcpy(p, hdr, len);
	b->nlh->nlmsg_len = NLMSG_ALIGN(b->nlh->nlmsg_len) + len;
	return p;
}

static struct rtattr *nlb_put_attr(struct nlbuf *b, int type,
				   const void *data, size_t len)
{
	struct rtattr *rta = (struct rtattr *)((char *)b->buf +
					       NLMSG_ALIGN(b->nlh->nlmsg_len));
	rta->rta_type = type;
	rta->rta_len = RTA_LENGTH(len);
	if (len && data)
		memcpy(RTA_DATA(rta), data, len);
	b->nlh->nlmsg_len = NLMSG_ALIGN(b->nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
	return rta;
}

static void nlb_put_u32(struct nlbuf *b, int type, unsigned int v)
{
	nlb_put_attr(b, type, &v, sizeof(v));
}

static void nlb_put_str(struct nlbuf *b, int type, const char *s)
{
	nlb_put_attr(b, type, s, strlen(s) + 1);
}

/* Nested attributes: open, add children, then close. */
static struct rtattr *nlb_nest_start(struct nlbuf *b, int type)
{
	return nlb_put_attr(b, type | NLA_F_NESTED, NULL, 0);
}

static void nlb_nest_end(struct nlbuf *b, struct rtattr *nest)
{
	nest->rta_len = (char *)b->buf + b->nlh->nlmsg_len - (char *)nest;
}

/* Returns the kernel's errno for the request (0 == success). */
static int nl_send(int fd, struct nlbuf *b)
{
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	char resp[8192];
	struct nlmsghdr *rh;
	int n;

	if (sendto(fd, b->buf, b->nlh->nlmsg_len, 0,
		   (struct sockaddr *)&sa, sizeof(sa)) < 0)
		return -errno;

	n = recv(fd, resp, sizeof(resp), 0);
	if (n < 0)
		return -errno;

	for (rh = (struct nlmsghdr *)resp; NLMSG_OK(rh, (unsigned)n);
	     rh = NLMSG_NEXT(rh, n)) {
		if (rh->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(rh);
			return e->error;
		}
	}
	return 0;
}

/* ---- link helpers ------------------------------------------------------- */
static int if_index(const char *name)
{
	/* if_nametoindex() without pulling in net/if.h's glibc bits. */
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM, 0), idx;

	if (fd < 0)
		return -1;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	idx = ioctl(fd, SIOCGIFINDEX, &ifr) < 0 ? -1 : ifr.ifr_ifindex;
	close(fd);
	return idx;
}

static int create_dummy(int nl, const char *name)
{
	struct nlbuf b;
	struct ifinfomsg ifi = { .ifi_family = AF_UNSPEC };
	struct rtattr *linfo;
	int err;

	nlb_init(&b, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL);
	nlb_put_hdr(&b, &ifi, sizeof(ifi));
	nlb_put_str(&b, IFLA_IFNAME, name);
	linfo = nlb_nest_start(&b, IFLA_LINKINFO);
	nlb_put_str(&b, IFLA_INFO_KIND, "dummy");
	nlb_nest_end(&b, linfo);

	err = nl_send(nl, &b);
	if (err)
		logf("create_dummy(%s) failed: %d (%s)", name, err, strerror(-err));
	return err ? -1 : if_index(name);
}

static int link_up(int nl, int ifindex)
{
	struct nlbuf b;
	struct ifinfomsg ifi = {
		.ifi_family = AF_UNSPEC,
		.ifi_index  = ifindex,
		.ifi_flags  = IFF_UP,
		.ifi_change = IFF_UP,
	};

	nlb_init(&b, RTM_NEWLINK, 0);
	nlb_put_hdr(&b, &ifi, sizeof(ifi));
	return nl_send(nl, &b);
}

/* ---- address configuration ---------------------------------------------- */
static int addr_add4(int nl, int ifindex, const char *cidr_addr, int plen)
{
	struct nlbuf b;
	struct ifaddrmsg ifa = {
		.ifa_family    = AF_INET,
		.ifa_prefixlen = plen,
		.ifa_scope     = 0,
		.ifa_index     = ifindex,
	};
	unsigned char a[4];
	unsigned int x0, x1, x2, x3;

	if (sscanf(cidr_addr, "%u.%u.%u.%u", &x0, &x1, &x2, &x3) != 4)
		return -EINVAL;
	a[0] = x0; a[1] = x1; a[2] = x2; a[3] = x3;

	nlb_init(&b, RTM_NEWADDR, NLM_F_CREATE | NLM_F_REPLACE);
	nlb_put_hdr(&b, &ifa, sizeof(ifa));
	nlb_put_attr(&b, IFA_LOCAL, a, 4);
	nlb_put_attr(&b, IFA_ADDRESS, a, 4);
	return nl_send(nl, &b);
}

/* addr16 must be 16 raw bytes. IFA_F_NODAD keeps the address out of the
 * tentative state, which would otherwise make it unusable for a second. */
static int addr_add6(int nl, int ifindex, const unsigned char addr16[16], int plen)
{
	struct nlbuf b;
	struct ifaddrmsg ifa = {
		.ifa_family    = AF_INET6,
		.ifa_prefixlen = plen,
		.ifa_flags     = 0x20 /* IFA_F_NODAD */,
		.ifa_scope     = 0,
		.ifa_index     = ifindex,
	};

	nlb_init(&b, RTM_NEWADDR, NLM_F_CREATE | NLM_F_REPLACE);
	nlb_put_hdr(&b, &ifa, sizeof(ifa));
	nlb_put_attr(&b, IFA_LOCAL, addr16, 16);
	nlb_put_attr(&b, IFA_ADDRESS, addr16, 16);
	return nl_send(nl, &b);
}

/* ---- fault injection ----------------------------------------------------
 * Error paths guarded only by allocation failure are where a lot of the
 * lifetime bugs live. CONFIG_FAILSLAB + debugfs lets us reach them on demand:
 * arm, run the operation that should fail, then disarm.
 */
static void failslab_arm(int times, int interval, int probability)
{
	char v[32];

	write_file("/sys/kernel/debug/failslab/task-filter", "Y");
	snprintf(v, sizeof(v), "%d", times);
	write_file("/sys/kernel/debug/failslab/times", v);
	snprintf(v, sizeof(v), "%d", interval);
	write_file("/sys/kernel/debug/failslab/interval", v);
	snprintf(v, sizeof(v), "%d", probability);
	write_file("/sys/kernel/debug/failslab/probability", v);
	write_file("/sys/kernel/debug/failslab/verbose", "0");
	write_file("/proc/self/make-it-fail", "1");
}

static void failslab_disarm(void)
{
	write_file("/proc/self/make-it-fail", "0");
	write_file("/sys/kernel/debug/failslab/probability", "0");
	write_file("/sys/kernel/debug/failslab/times", "0");
}

#endif /* REPRO_COMMON_H */

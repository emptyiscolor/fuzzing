/* Negative control for repro/sctp-asconf-oob.c.
 *
 * Identical sequence with the arming step (SCTP_SOCKOPT_BINDX_REM, which sets
 * asoc->asconf_addr_del_pending) removed. A clean run here is what makes the
 * crash in the main reproducer attributable to the del-pickup length mismatch
 * rather than to simply adding N addresses in one bindx_add.
 */
#define SKIP_ARM 1
#include "sctp-asconf-oob.c"

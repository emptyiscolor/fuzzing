/* Negative control for repro/bt-scanrsp-stackoob.c.
 *
 * Identical sequence with step 3 removed -- the re-issue of
 * ADD_EXT_ADV_PARAMS that replaces adv->flags with APPEARANCE while the
 * previously validated adv->scan_rsp_len (251) survives. A clean run here is
 * what makes the stack-protector panic attributable to that flags/length
 * desynchronisation rather than to a 251-byte scan response by itself.
 */
#define SKIP_ARM 1
#include "bt-scanrsp-stackoob.c"

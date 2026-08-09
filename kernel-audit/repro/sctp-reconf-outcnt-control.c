/* Negative control for repro/sctp-reconf-outcnt-underflow.c.
 *
 * Identical run -- same handshake, same SCTP_ADD_STREAMS, same abort-on-close
 * teardown -- except the peer answers with ONE Re-configuration Response
 * instead of two sharing a response_seq. That is what a well-behaved peer
 * sends, so a clean run here attributes the crash in the main reproducer to the
 * replayed response specifically, and not to the add-streams request, the
 * userspace peer, or the ABORT path on close.
 */
#define SKIP_REPLAY 1
#include "sctp-reconf-outcnt-underflow.c"

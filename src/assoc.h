/* assoc.h -- the association object (D-13, FR-P-02, FR-L-03, FR-L-04).
 *
 * One association per application socket, holding the TCP control connection
 * and the relay address.  Duplicated descriptors share it by refcount; it is
 * torn down when the last of them closes.
 *
 * It owns no data socket: FR-I-07 redirects the application's own fd to the
 * relay, which is what makes FR-P-06 (one stable local socket per association)
 * automatic rather than something to enforce.
 */
#ifndef UDPCHAINS_ASSOC_H
#define UDPCHAINS_ASSOC_H

#include "compat.h"

#include <stdatomic.h>
#include <stdbool.h>

#include "config.h"
#include "fdtable.h"
#include "socks5.h"

/* How long an association must have been idle before a send bothers to check
 * whether the proxy has expired it.  Busy sockets pay nothing; only sockets
 * that have actually been quiet -- the ones FR-P-08 is about -- take the extra
 * poll().  Well under the reference proxy's 60 s expiry (baseline §0.5). */
#define UDPC_IDLE_PROBE_SECS 1

struct udpc_assoc {
	_Atomic int refcount;
	unsigned fork_generation; /* global generation when established */
	_Atomic long last_used;   /* CLOCK_MONOTONIC_COARSE seconds */
	struct udpc_socks_conn conn;
};

/* Global fork generation.  A pthread_atfork child handler bumps this and does
 * nothing else -- all real work is deferred off the handler, where
 * async-signal-safety constraints are tightest (FR-L-04, DESIGN.md 3.4). */
unsigned udpc_fork_generation(void);

/* Registers the atfork handler.  Called once from shim initialisation. */
void udpc_assoc_init(void);

void udpc_assoc_ref(struct udpc_assoc *a);
void udpc_assoc_unref(struct udpc_assoc *a);

/* Ensures fd has a live association, establishing one if needed, and points
 * the application's fd at the relay (FR-I-07).
 *
 * Returns 0 on success.  On failure returns -1 and sets *out_errno to what the
 * application's call should report.  There is no path from here to a direct
 * send (SEC-01).
 *
 * Establishment is serialised per entry, so two threads sending on the same
 * fresh fd produce one association rather than two (FR-L-01). */
int udpc_assoc_ensure(int fd, struct udpc_fdent *e, const struct udpc_config *cfg,
                      int *out_errno);

/* Tears down the association on this entry, so the next send re-establishes.
 * Used for transparent re-association after the proxy expires an idle
 * association (FR-P-08). */
void udpc_assoc_invalidate(struct udpc_fdent *e);

/* Records activity, so the idle probe knows when the association last carried
 * anything. */
void udpc_assoc_touch(struct udpc_fdent *e);

/* If the association has been idle long enough to have been expired, checks
 * whether the proxy has dropped it and invalidates it if so (FR-P-08).
 *
 * Called before a send rather than after a failure, because by the time a
 * failure is visible the datagram that triggered it has already gone to a relay
 * port that no longer exists -- the application would see a successful send
 * whose payload vanished.  Detecting it up front is what makes the
 * re-association actually transparent. */
void udpc_assoc_revalidate(struct udpc_fdent *e);

/* The relay address for a live association.  Returns false if there is none. */
bool udpc_assoc_relay(const struct udpc_fdent *e, struct sockaddr_storage *out);

#endif /* UDPCHAINS_ASSOC_H */

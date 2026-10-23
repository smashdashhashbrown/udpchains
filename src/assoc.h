/* assoc.h -- the association object (D-13, FR-P-02, FR-L-03, FR-L-04).
 *
 * One association per application socket, holding a control connection and a
 * relay address for each hop of the chain (FR-CH-09, FR-CH-10).  Duplicated descriptors share it by refcount; it is
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
#include "dgram.h"
#include "fdtable.h"
#include "socks5.h"

/* Associations are TYPE-STABLE (D-24): once allocated, an object is never
 * returned to the allocator, only to a free list for reuse.  A thread that
 * loaded a pointer an instant before another thread dropped the last reference
 * therefore reads valid -- if possibly recycled -- memory, never freed memory.
 * udpc_assoc_get() turns that into safety: it takes a reference only while the
 * count is non-zero, then checks the entry still points at the same object. */
struct udpc_assoc {
	_Atomic int refcount;       /* 0 while on the free list */
	unsigned fork_generation;   /* global generation when established */
	_Atomic long last_used;     /* CLOCK_MONOTONIC_COARSE seconds */
	struct udpc_socks_chain chain; /* every hop's control fd is a shim fd */
	struct udpc_assoc *next_free;
};

/* Global fork generation.  A pthread_atfork child handler bumps this and closes
 * the child's copies of the control connections (D-31); everything else is
 * deferred off the handler, where async-signal-safety constraints are tightest
 * (FR-L-04, DESIGN.md 3.4). */
unsigned udpc_fork_generation(void);

/* Registers the atfork handler.  Called once from shim initialisation. */
void udpc_assoc_init(void);

/* A new association with one reference and no control connection, from the
 * free list when one is available.  NULL only if allocation fails. */
struct udpc_assoc *udpc_assoc_alloc(void);

/* Takes a reference to e's current association, or returns NULL if it has
 * none.  Every read of an association's fields goes through this, and the
 * caller drops the reference with udpc_assoc_unref() -- a bare load of e->assoc
 * may be racing with the last unref on another thread (D-24). */
struct udpc_assoc *udpc_assoc_get(struct udpc_fdent *e);

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

/* The datagram path's way in: ensures fd has a live association and returns ONE
 * reference to it, which the caller uses for everything the datagram needs and
 * then drops with udpc_assoc_unref() (D-24).  With revalidate, an association
 * idle long enough to have been expired is first checked, and replaced if the
 * proxy has dropped it (FR-P-08).  NULL on failure, with *out_errno set --
 * there is no path from here to a direct send (SEC-01). */
struct udpc_assoc *udpc_assoc_hold(int fd, struct udpc_fdent *e,
                                   const struct udpc_config *cfg, bool revalidate,
                                   int *out_errno);

/* Detaches a from e if e still points at it, so the next use re-establishes.
 * The caller's own reference to a is untouched. */
void udpc_assoc_drop(struct udpc_fdent *e, struct udpc_assoc *a);

/* a's relay address, in a form a socket of `family` can reach.  False if there
 * is none. */
bool udpc_assoc_relay_of(const struct udpc_assoc *a, int family,
                         struct sockaddr_storage *out);

/* Records activity on a held association, for the idle check. */
void udpc_assoc_mark_used(struct udpc_assoc *a);

/* Tears down the association on this entry, so the next send re-establishes.
 * Used for transparent re-association after the proxy expires an idle
 * association (FR-P-08). */
void udpc_assoc_invalidate(struct udpc_fdent *e);


#endif /* UDPCHAINS_ASSOC_H */

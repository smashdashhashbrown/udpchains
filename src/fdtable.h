/* fdtable.h -- per-fd state (FR-L-01, FR-L-02, D-07).
 *
 * A two-level radix table indexed by fd:
 *
 *     top[fd >> 8]  ->  block of 256 entries  ->  entry[fd & 0xff]
 *
 * Blocks are allocated on demand in socket()/dup*(), never on the datagram
 * path, so NFR-02 holds without a fixed fd ceiling chosen at start-up.  A
 * lookup on the datagram path is two atomic loads: no locks, no allocation, no
 * syscalls, which is what makes NFR-03 hold by construction rather than by
 * documented caveat.
 *
 * Blocks are never freed.  A program that once used fd N is likely to again,
 * and freeing would reintroduce the use-after-free hazard the generation
 * counter exists to prevent.
 */
#ifndef UDPCHAINS_FDTABLE_H
#define UDPCHAINS_FDTABLE_H

#include "compat.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

struct udpc_assoc;

enum udpc_fd_state {
	UDPC_FD_FREE = 0,
	UDPC_FD_CLAIMING, /* being set up; neither absent nor usable yet */
	UDPC_FD_ACTIVE,
	UDPC_FD_DYING, /* being released; a concurrent call must not use it */
	UDPC_FD_SHIM   /* the shim's own descriptor: never intercepted, and never
	                * closed on the application's behalf (D-26) */
};

/* An entry's cookie while its descriptor is being re-examined (D-23).  Real
 * socket cookies start at 1 and count up, so a value this large never is one. */
#define UDPC_FD_COOKIE_RECOVERING UINT64_MAX

/* fd >> 8 indexes the top level, so this covers fds below 2^20.  Beyond that
 * the shim cannot track the descriptor, and an untrackable descriptor must fail
 * rather than pass through unproxied (SEC-01). */
#define UDPC_FD_BLOCK_BITS 8
#define UDPC_FD_BLOCK_SIZE (1u << UDPC_FD_BLOCK_BITS)
#define UDPC_FD_TOP_SIZE 4096u
#define UDPC_FD_MAX (UDPC_FD_TOP_SIZE * UDPC_FD_BLOCK_SIZE)

struct udpc_fdent {
	_Atomic int state;         /* enum udpc_fd_state */
	_Atomic unsigned generation; /* bumped on release; guards fd reuse */

	/* The kernel's SO_COOKIE for the socket this entry describes: unique
	 * for the life of the system, never reused.  A descriptor closed by a
	 * route no hook sees leaves its entry behind, and the kernel may hand
	 * the number to something else entirely; comparing cookies is how that
	 * is noticed before the stranger is treated as this socket (D-23).
	 * 0 means unknown, which skips the check. */
	_Atomic uint64_t cookie;

	_Atomic(struct udpc_assoc *) assoc;

	/* Atomic, not plain ints.  These are written at claim time and read
	 * after lookup.  On the ordinary path the release-store that publishes
	 * the entry orders them, but an application that closes a descriptor
	 * while another of its threads is still using it can have a reader
	 * holding a pointer to an entry that is being re-claimed -- and a plain
	 * int there is a data race, which TSan duly reports.  Relaxed atomics
	 * cost nothing and make it defined.
	 *
	 * That the entry can be recycled under a reader at all is an
	 * application-level race the kernel does not protect against either;
	 * what matters here is that it stays defined behaviour. */
	_Atomic int family; /* AF_INET or AF_INET6 */
	_Atomic int type;   /* always SOCK_DGRAM when intercepted */

	/* Destination the application named via connect().  Written before
	 * `connected` is published with release ordering, and read after it is
	 * observed with acquire ordering.  Concurrent connect() and send() on
	 * one fd is an application-level race that the kernel does not order
	 * either; this ordering just guarantees a torn address is never used. */
	struct sockaddr_storage app_dst;
	_Atomic bool connected;

	/* Concrete address the application bound, for FR-P-05 and FR-I-05. */
	struct sockaddr_storage bound;
	_Atomic bool bound_set;

	/* Set once the application's own fd has been pointed at the relay
	 * (FR-I-07), so the redirect is not repeated on every send. */
	_Atomic bool redirected;
};

/* Returns the entry for fd if it is being intercepted, else NULL.
 * Two atomic loads on the hot path.  Does not check the entry still describes
 * the socket now at fd; see udpc_fd_lookup_verified. */
struct udpc_fdent *udpc_fd_lookup(int fd);

/* As udpc_fd_lookup, but first confirms the entry still describes the socket at
 * fd, by its cookie -- one getsockopt, and only for an intercepted descriptor.
 * A stale entry is released, and whatever now holds the number is adopted if it
 * is a UDP socket (D-23).  This is the lookup every hooked call makes. */
struct udpc_fdent *udpc_fd_lookup_verified(int fd);

/* Adopts fd if it is an AF_INET/AF_INET6 datagram socket the table does not yet
 * track -- one inherited across exec, received over SCM_RIGHTS, or found behind
 * a stale entry.  Returns 1 if adopted, 0 if it is not such a socket, and -1 if
 * it is one but cannot be tracked: the caller must then not let it through. */
int udpc_fd_adopt(int fd);

/* Claims fd, allocating a block if needed.  Returns the entry, or NULL if the
 * descriptor cannot be tracked (out of range, or out of memory) -- in which
 * case the caller must fail closed rather than let it through. */
struct udpc_fdent *udpc_fd_claim(int fd, int family, int type);

/* Publishes a claimed entry as usable. */
void udpc_fd_publish(struct udpc_fdent *e);

/* Records that the socket behind e's descriptor has been deliberately replaced
 * by the shim itself -- after fork, FR-L-04 -- so the change is not mistaken
 * for a stale entry (D-23). */
void udpc_fd_rebind_cookie(struct udpc_fdent *e, int fd);

/* Releases fd: drops the association reference and bumps the generation so a
 * later socket landing on the same fd number inherits nothing (FR-L-02).  A
 * shim-owned entry is left alone: only udpc_fd_shim_close releases one. */
void udpc_fd_release(int fd);

/* udpc_fd_release for every descriptor in [first, last], visiting only blocks
 * that exist -- so close_range(3, ~0U) costs a few thousand loads, not a
 * million. */
void udpc_fd_release_range(unsigned first, unsigned last);

/* --- the shim's own descriptors (D-26) --------------------------------------
 *
 * Control connections and the resolver's sockets live in the application's
 * descriptor space, where a close-all loop, close_range or a dup2 onto the
 * number would take them away without the shim knowing -- after which the shim
 * would poll, and eventually close, whatever the application had put there.
 * They are therefore moved to a band of high numbers, out of the way of the
 * lowest-free allocation the application relies on, and marked, so the close
 * and dup hooks can refuse to touch them. */

/* Moves fd into the shim's band and marks it.  Returns the descriptor to use
 * from now on (fd itself, if it could not be moved; it is marked either way). */
int udpc_fd_shim_adopt(int fd);

/* Unmarks and closes a shim-owned descriptor.  No-op for fd < 0. */
void udpc_fd_shim_close(int fd);

/* True if fd is marked shim-owned AND still is the socket that was marked.  A
 * stale mark -- the descriptor closed by a route no hook sees, and the number
 * reused -- is cleared and reported as false, so the application is never
 * refused its own descriptor. */
bool udpc_fd_is_shim(int fd);

/* The lowest shim-marked descriptor in [from, last], or -1. */
long udpc_fd_next_shim(unsigned from, unsigned last);

/* Called after the kernel has made newfd a duplicate of oldfd, by any route
 * (dup, dup2, dup3, fcntl F_DUPFD).  If oldfd is intercepted, points newfd at
 * its association, sharing it by refcount (FR-L-03); otherwise releases any
 * stale entry left at newfd's number.
 *
 * Returns 0, or -1 if oldfd is intercepted but newfd cannot be tracked.  The
 * caller must then close newfd and fail the call: an untracked duplicate of an
 * intercepted socket sends directly (SEC-01). */
int udpc_fd_share(int oldfd, int newfd);

#endif /* UDPCHAINS_FDTABLE_H */

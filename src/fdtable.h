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
#include <sys/socket.h>

struct udpc_assoc;

enum udpc_fd_state {
	UDPC_FD_FREE = 0,
	UDPC_FD_CLAIMING, /* being set up; neither absent nor usable yet */
	UDPC_FD_ACTIVE,
	UDPC_FD_DYING /* being released; a concurrent call must not use it */
};

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
 * Two atomic loads on the hot path. */
struct udpc_fdent *udpc_fd_lookup(int fd);

/* Claims fd, allocating a block if needed.  Returns the entry, or NULL if the
 * descriptor cannot be tracked (out of range, or out of memory) -- in which
 * case the caller must fail closed rather than let it through. */
struct udpc_fdent *udpc_fd_claim(int fd, int family, int type);

/* Publishes a claimed entry as usable. */
void udpc_fd_publish(struct udpc_fdent *e);

/* Releases fd: drops the association reference and bumps the generation so a
 * later socket landing on the same fd number inherits nothing (FR-L-02). */
void udpc_fd_release(int fd);

/* Points newfd at oldfd's association, sharing it by refcount (FR-L-03). */
void udpc_fd_share(int oldfd, int newfd);

#endif /* UDPCHAINS_FDTABLE_H */

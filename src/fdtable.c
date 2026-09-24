#include "fdtable.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include "assoc.h"
#include "log.h"
#include "real.h"

static _Atomic(struct udpc_fdent *) g_top[UDPC_FD_TOP_SIZE];

static struct udpc_fdent *block_for(int fd, bool create)
{
	unsigned idx;
	struct udpc_fdent *blk, *fresh;

	if (fd < 0 || (unsigned)fd >= UDPC_FD_MAX)
		return NULL;

	idx = (unsigned)fd >> UDPC_FD_BLOCK_BITS;

	blk = atomic_load_explicit(&g_top[idx], memory_order_acquire);
	if (blk != NULL || !create)
		return blk;

	/* Allocation happens here, in socket()/dup*(), never on the datagram
	 * path (NFR-02). */
	fresh = calloc(UDPC_FD_BLOCK_SIZE, sizeof(*fresh));
	if (fresh == NULL)
		return NULL;

	/* Publish with release so a reader that observes the pointer also
	 * observes the zeroed contents.  If another thread won the race, drop
	 * ours and use theirs. */
	if (!atomic_compare_exchange_strong_explicit(&g_top[idx], &blk, fresh,
	                                             memory_order_release,
	                                             memory_order_acquire)) {
		free(fresh);
		return blk;
	}
	return fresh;
}

static struct udpc_fdent *entry_for(int fd, bool create)
{
	struct udpc_fdent *blk = block_for(fd, create);

	return blk == NULL ? NULL : &blk[(unsigned)fd & (UDPC_FD_BLOCK_SIZE - 1)];
}

/* The kernel's cookie for the socket at fd, or 0 if fd is not a socket (or not
 * open).  SO_COOKIE needs Linux 4.12; the floor is already 5.9 (NFR-01a). */
static uint64_t socket_cookie(int fd)
{
	uint64_t c = 0;
	socklen_t l = sizeof(c);

	if (getsockopt(fd, SOL_SOCKET, SO_COOKIE, &c, &l) != 0)
		return 0;
	return c;
}

struct udpc_fdent *udpc_fd_lookup(int fd)
{
	struct udpc_fdent *e = entry_for(fd, false);

	if (e == NULL ||
	    atomic_load_explicit(&e->state, memory_order_acquire) != UDPC_FD_ACTIVE)
		return NULL;
	return e;
}

/* Clears a shim mark.  The caller knows the entry is SHIM. */
static void unmark(struct udpc_fdent *e)
{
	int want = UDPC_FD_SHIM;

	if (atomic_compare_exchange_strong_explicit(&e->state, &want, UDPC_FD_DYING,
	                                            memory_order_acq_rel,
	                                            memory_order_acquire)) {
		atomic_store_explicit(&e->cookie, 0, memory_order_relaxed);
		atomic_fetch_add_explicit(&e->generation, 1u, memory_order_acq_rel);
		atomic_store_explicit(&e->state, UDPC_FD_FREE, memory_order_release);
	}
}

struct udpc_fdent *udpc_fd_claim(int fd, int family, int type)
{
	struct udpc_fdent *e;
	int expected = UDPC_FD_FREE;

	e = entry_for(fd, true);
	if (e == NULL) {
		if (fd >= 0 && (unsigned)fd >= UDPC_FD_MAX)
			udpc_err("descriptor %d is beyond the trackable range; "
			         "refusing rather than leaving it unproxied",
			         fd);
		return NULL;
	}

	/* Every caller passes an fd the kernel has JUST allocated -- from
	 * socket(), or as the target of a dup.  The kernel does not hand out a
	 * descriptor number that is already live, so finding anything other than
	 * FREE here is proof that the entry is STALE, not proof of a conflict.
	 *
	 * Stale entries are not hypothetical.  The table is released from the
	 * close() hook, and a program whose runtime closes descriptors by a
	 * route that does not go through libc's PLT entry never reaches it --
	 * dig, via libuv, makes 64 close syscalls of which 4 reach the hook.
	 * Its descriptor is then stranded ACTIVE, and the next socket() landing
	 * on that number used to be refused with EMFILE, breaking a program that
	 * had done nothing wrong.  Worse, the stranded entry still held a
	 * reference to its association, so the control connection leaked too.
	 *
	 * Recycling the slot fixes both: udpc_fd_release drops the association
	 * reference (closing the control connection, releasing the association
	 * at the proxy) and returns the slot to FREE, bumping the generation so
	 * anything still holding the old entry is rejected (FR-L-02).  A stale
	 * SHIM mark means one of the shim's own descriptors was closed behind
	 * its back; it is simply cleared.
	 *
	 * Found on 2026-08-19 against a real proxy.  The fixture suite never
	 * reached it because its clients close through libc. */
	if (!atomic_compare_exchange_strong_explicit(&e->state, &expected,
	                                             UDPC_FD_CLAIMING,
	                                             memory_order_acq_rel,
	                                             memory_order_acquire)) {
		udpc_debug("fd %d: reclaiming a stale entry (state %d) -- the "
		           "descriptor was closed without the shim seeing it",
		           fd, expected);
		if (expected == UDPC_FD_SHIM)
			unmark(e);
		else
			udpc_fd_release(fd);

		expected = UDPC_FD_FREE;
		if (!atomic_compare_exchange_strong_explicit(&e->state, &expected,
		                                             UDPC_FD_CLAIMING,
		                                             memory_order_acq_rel,
		                                             memory_order_acquire)) {
			udpc_debug("fd %d still not claimable (state %d)", fd,
			           expected);
			return NULL;
		}
	}

	atomic_store_explicit(&e->family, family, memory_order_relaxed);
	atomic_store_explicit(&e->type, type, memory_order_relaxed);
	atomic_store_explicit(&e->assoc, NULL, memory_order_relaxed);
	atomic_store_explicit(&e->connected, false, memory_order_relaxed);
	atomic_store_explicit(&e->bound_set, false, memory_order_relaxed);
	atomic_store_explicit(&e->redirected, false, memory_order_relaxed);
	memset(&e->app_dst, 0, sizeof(e->app_dst));
	memset(&e->bound, 0, sizeof(e->bound));
	atomic_store_explicit(&e->cookie, socket_cookie(fd), memory_order_relaxed);

	return e;
}

void udpc_fd_publish(struct udpc_fdent *e)
{
	atomic_store_explicit(&e->state, UDPC_FD_ACTIVE, memory_order_release);
}

void udpc_fd_rebind_cookie(struct udpc_fdent *e, int fd)
{
	atomic_store_explicit(&e->cookie, socket_cookie(fd), memory_order_release);
}

int udpc_fd_adopt(int fd)
{
	int domain = 0, type = 0;
	socklen_t len;
	struct udpc_fdent *e;

	len = sizeof(domain);
	if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &len) != 0)
		return 0;
	len = sizeof(type);
	if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len) != 0)
		return 0;
	if (type != SOCK_DGRAM || (domain != AF_INET && domain != AF_INET6))
		return 0;

	e = udpc_fd_claim(fd, domain, type);
	if (e == NULL)
		return -1;
	udpc_fd_publish(e);
	return 1;
}

/* The descriptor this thread is re-examining, or -1.  Lets a signal handler that
 * interrupts a recovery on the same descriptor avoid waiting on itself, exactly
 * as t_establishing_fd does for association setup. */
static __thread int t_recovering_fd = -1;

struct udpc_fdent *udpc_fd_lookup_verified(int fd)
{
	struct udpc_fdent *e;
	uint64_t want, have;
	int spins = 0;

	for (;;) {
		e = udpc_fd_lookup(fd);
		if (e == NULL)
			return NULL;
		want = atomic_load_explicit(&e->cookie, memory_order_acquire);
		if (want == 0)
			return e; /* unknown at claim time: nothing to compare */
		if (want != UDPC_FD_COOKIE_RECOVERING) {
			have = socket_cookie(fd);
			if (have == want)
				return e;
			break;
		}
		/* Another thread is re-examining this descriptor. */
		if (t_recovering_fd == fd)
			return e; /* ourselves, from a signal handler: see below */
		if (++spins > 100000)
			return e;
		sched_yield();
	}

	/* The socket this entry described is gone -- closed by a route no hook
	 * sees -- and the number now holds something else.  Treating that as
	 * the old socket would wrap a TCP stream's bytes in SOCKS headers, or
	 * swallow a pipe's data as malformed datagrams (D-23).  Exactly one
	 * thread recovers the entry; the cookie is the lock. */
	if (!atomic_compare_exchange_strong_explicit(&e->cookie, &want,
	                                             UDPC_FD_COOKIE_RECOVERING,
	                                             memory_order_acq_rel,
	                                             memory_order_acquire))
		return udpc_fd_lookup_verified(fd); /* lost the race; look again */

	udpc_debug("fd %d: the socket the shim tracked here was closed without "
	           "the shim seeing it; releasing the stale entry (D-23)",
	           fd);
	t_recovering_fd = fd;
	udpc_fd_release(fd);
	/* A UDP socket that arrived by a route no hook saw is adopted rather
	 * than let through: anything else here would send unproxied. */
	if (udpc_fd_adopt(fd) <= 0)
		atomic_store_explicit(&e->cookie, 0, memory_order_release);
	t_recovering_fd = -1;

	/* A signal handler that ran during the recovery above was handed the
	 * entry as it stood.  The memory is valid -- blocks are never freed --
	 * and the worst it can do is send through the entry's association,
	 * which is proxied; it can never reach the network directly. */
	return udpc_fd_lookup(fd);
}

void udpc_fd_release(int fd)
{
	struct udpc_fdent *e = entry_for(fd, false);
	struct udpc_assoc *a;
	int state;

	if (e == NULL)
		return;

	/* FREE has nothing to release, and a SHIM entry is the shim's own
	 * descriptor, released only by udpc_fd_shim_close (D-26). */
	state = atomic_load_explicit(&e->state, memory_order_acquire);
	do {
		if (state == UDPC_FD_FREE || state == UDPC_FD_SHIM)
			return;
	} while (!atomic_compare_exchange_weak_explicit(&e->state, &state,
	                                                UDPC_FD_DYING,
	                                                memory_order_acq_rel,
	                                                memory_order_acquire));

	a = atomic_exchange_explicit(&e->assoc, NULL, memory_order_acq_rel);
	if (a != NULL)
		udpc_assoc_unref(a);

	atomic_store_explicit(&e->connected, false, memory_order_relaxed);
	atomic_store_explicit(&e->bound_set, false, memory_order_relaxed);
	atomic_store_explicit(&e->redirected, false, memory_order_relaxed);

	/* Bump the generation BEFORE returning the slot to FREE, so a socket()
	 * that lands on this fd number cannot observe the old generation with a
	 * free slot (FR-L-02). */
	atomic_fetch_add_explicit(&e->generation, 1u, memory_order_acq_rel);
	atomic_store_explicit(&e->state, UDPC_FD_FREE, memory_order_release);
}

void udpc_fd_release_range(unsigned first, unsigned last)
{
	unsigned idx;

	if (first >= UDPC_FD_MAX)
		return;
	if (last >= UDPC_FD_MAX)
		last = UDPC_FD_MAX - 1;

	for (idx = first >> UDPC_FD_BLOCK_BITS; idx <= last >> UDPC_FD_BLOCK_BITS;
	     idx++) {
		struct udpc_fdent *blk =
			atomic_load_explicit(&g_top[idx], memory_order_acquire);
		unsigned lo, hi, fd;

		if (blk == NULL)
			continue;
		lo = idx << UDPC_FD_BLOCK_BITS;
		hi = lo + UDPC_FD_BLOCK_SIZE - 1;
		if (lo < first)
			lo = first;
		if (hi > last)
			hi = last;
		for (fd = lo; fd <= hi; fd++) {
			int st = atomic_load_explicit(
				&blk[fd & (UDPC_FD_BLOCK_SIZE - 1)].state,
				memory_order_relaxed);
			if (st != UDPC_FD_FREE && st != UDPC_FD_SHIM)
				udpc_fd_release((int)fd);
		}
	}
}

/* --- the shim's own descriptors (D-26) ------------------------------------- */

/* Where the band starts.  With the usual soft limit of 1024 the shim uses 768
 * and up: far above anything the lowest-free allocation hands an ordinary
 * program, and within the limit.  A much higher soft limit does not move the
 * band up, because the kernel sizes each process's descriptor table to the
 * highest number in use, and a table grown to a million entries costs
 * megabytes per process. */
static int band_base(void)
{
	struct rlimit rl;
	unsigned long cap = UDPC_FD_MAX;

	if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY &&
	    rl.rlim_cur < cap)
		cap = rl.rlim_cur;
	return cap >= 1024 ? 768 : (int)(cap / 2);
}

int udpc_fd_shim_adopt(int fd)
{
	struct udpc_fdent *e;
	int hi, st;

	if (fd < 0)
		return fd;

	hi = REAL_FCNTL(fd, F_DUPFD_CLOEXEC, band_base());
	if (hi >= 0 && (unsigned)hi < UDPC_FD_MAX) {
		REAL_CLOSE(fd);
		fd = hi;
	} else if (hi >= 0) {
		REAL_CLOSE(hi);
	}

	e = entry_for(fd, true);
	if (e == NULL)
		return fd; /* cannot be marked: works, but unprotected */

	/* The kernel just gave us this number, so anything recorded against it
	 * is stale. */
	st = atomic_load_explicit(&e->state, memory_order_acquire);
	if (st == UDPC_FD_SHIM)
		unmark(e);
	else if (st != UDPC_FD_FREE)
		udpc_fd_release(fd);

	atomic_store_explicit(&e->cookie, socket_cookie(fd), memory_order_relaxed);
	atomic_store_explicit(&e->state, UDPC_FD_SHIM, memory_order_release);
	return fd;
}

void udpc_fd_shim_close(int fd)
{
	struct udpc_fdent *e;

	if (fd < 0)
		return;
	e = entry_for(fd, false);
	if (e != NULL &&
	    atomic_load_explicit(&e->state, memory_order_acquire) == UDPC_FD_SHIM)
		unmark(e);
	REAL_CLOSE(fd);
}

bool udpc_fd_is_shim(int fd)
{
	struct udpc_fdent *e = entry_for(fd, false);
	uint64_t want;

	if (e == NULL ||
	    atomic_load_explicit(&e->state, memory_order_acquire) != UDPC_FD_SHIM)
		return false;

	want = atomic_load_explicit(&e->cookie, memory_order_relaxed);
	if (want != 0 && socket_cookie(fd) != want) {
		/* Ours once, closed behind our back, and the number reused: the
		 * application's now, not ours to protect. */
		unmark(e);
		return false;
	}
	return true;
}

long udpc_fd_next_shim(unsigned from, unsigned last)
{
	unsigned idx;

	if (from >= UDPC_FD_MAX)
		return -1;
	if (last >= UDPC_FD_MAX)
		last = UDPC_FD_MAX - 1;

	for (idx = from >> UDPC_FD_BLOCK_BITS; idx <= last >> UDPC_FD_BLOCK_BITS;
	     idx++) {
		struct udpc_fdent *blk =
			atomic_load_explicit(&g_top[idx], memory_order_acquire);
		unsigned lo, hi, fd;

		if (blk == NULL)
			continue;
		lo = idx << UDPC_FD_BLOCK_BITS;
		hi = lo + UDPC_FD_BLOCK_SIZE - 1;
		if (lo < from)
			lo = from;
		if (hi > last)
			hi = last;
		for (fd = lo; fd <= hi; fd++)
			if (atomic_load_explicit(
				    &blk[fd & (UDPC_FD_BLOCK_SIZE - 1)].state,
				    memory_order_acquire) == UDPC_FD_SHIM)
				return (long)fd;
	}
	return -1;
}

/* --- duplication ----------------------------------------------------------- */

int udpc_fd_share(int oldfd, int newfd)
{
	struct udpc_fdent *src, *dst;
	struct udpc_assoc *a;

	/* Verified: duplicating a stale entry would make newfd look like a UDP
	 * socket when oldfd is now something else entirely (D-23). */
	src = udpc_fd_lookup_verified(oldfd);
	if (src == NULL) {
		/* newfd now refers to something we do not intercept.  Any entry
		 * at its number is stale -- dup2 closed what was there, or the
		 * kernel has just allocated the number (D-17) -- and must not
		 * make this descriptor look like a UDP socket. */
		udpc_fd_release(newfd);
		return 0;
	}

	dst = udpc_fd_claim(newfd,
	                    atomic_load_explicit(&src->family, memory_order_relaxed),
	                    atomic_load_explicit(&src->type, memory_order_relaxed));
	if (dst == NULL) {
		udpc_err("cannot track duplicated descriptor %d; refusing it "
		         "rather than leaving it unproxied",
		         newfd);
		return -1;
	}

	/* FR-L-03: both descriptors share one association, which survives until
	 * the last of them closes.  udpc_assoc_get takes the reference that dst
	 * now holds (D-24). */
	a = udpc_assoc_get(src);
	if (a != NULL)
		atomic_store_explicit(&dst->assoc, a, memory_order_release);

	memcpy(&dst->app_dst, &src->app_dst, sizeof(dst->app_dst));
	memcpy(&dst->bound, &src->bound, sizeof(dst->bound));
	atomic_store_explicit(&dst->connected,
	                      atomic_load_explicit(&src->connected,
	                                           memory_order_acquire),
	                      memory_order_relaxed);
	atomic_store_explicit(&dst->bound_set,
	                      atomic_load_explicit(&src->bound_set,
	                                           memory_order_acquire),
	                      memory_order_relaxed);
	atomic_store_explicit(&dst->redirected,
	                      atomic_load_explicit(&src->redirected,
	                                           memory_order_acquire),
	                      memory_order_relaxed);

	udpc_fd_publish(dst);
	return 0;
}

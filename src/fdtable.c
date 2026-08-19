#include "fdtable.h"

#include <stdlib.h>
#include <string.h>

#include "assoc.h"
#include "log.h"

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

struct udpc_fdent *udpc_fd_lookup(int fd)
{
	struct udpc_fdent *blk, *e;

	blk = block_for(fd, false);
	if (blk == NULL)
		return NULL;

	e = &blk[(unsigned)fd & (UDPC_FD_BLOCK_SIZE - 1)];
	if (atomic_load_explicit(&e->state, memory_order_acquire) != UDPC_FD_ACTIVE)
		return NULL;
	return e;
}

struct udpc_fdent *udpc_fd_claim(int fd, int family, int type)
{
	struct udpc_fdent *blk, *e;
	int expected = UDPC_FD_FREE;

	blk = block_for(fd, true);
	if (blk == NULL) {
		if (fd >= 0 && (unsigned)fd >= UDPC_FD_MAX)
			udpc_err("descriptor %d is beyond the trackable range; "
			         "refusing rather than leaving it unproxied",
			         fd);
		return NULL;
	}

	e = &blk[(unsigned)fd & (UDPC_FD_BLOCK_SIZE - 1)];

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
	 * anything still holding the old entry is rejected (FR-L-02).
	 *
	 * Found on 2026-08-19 against a real proxy.  The fixture suite never
	 * reached it because its clients close through libc. */
	if (!atomic_compare_exchange_strong_explicit(&e->state, &expected,
	                                             UDPC_FD_CLAIMING,
	                                             memory_order_acq_rel,
	                                             memory_order_acquire)) {
		udpc_debug("fd %d: reclaiming a stale entry (state %d) -- the "
		           "descriptor was closed without the shim seeing it",
		           fd, atomic_load(&e->state));
		udpc_fd_release(fd);

		expected = UDPC_FD_FREE;
		if (!atomic_compare_exchange_strong_explicit(&e->state, &expected,
		                                             UDPC_FD_CLAIMING,
		                                             memory_order_acq_rel,
		                                             memory_order_acquire)) {
			udpc_debug("fd %d still not claimable (state %d)", fd,
			           atomic_load(&e->state));
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

	return e;
}

void udpc_fd_publish(struct udpc_fdent *e)
{
	atomic_store_explicit(&e->state, UDPC_FD_ACTIVE, memory_order_release);
}

void udpc_fd_release(int fd)
{
	struct udpc_fdent *blk, *e;
	struct udpc_assoc *a;
	int state;

	blk = block_for(fd, false);
	if (blk == NULL)
		return;

	e = &blk[(unsigned)fd & (UDPC_FD_BLOCK_SIZE - 1)];

	state = atomic_exchange_explicit(&e->state, UDPC_FD_DYING,
	                                 memory_order_acq_rel);
	if (state == UDPC_FD_FREE) {
		atomic_store_explicit(&e->state, UDPC_FD_FREE,
		                      memory_order_release);
		return;
	}

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

void udpc_fd_share(int oldfd, int newfd)
{
	struct udpc_fdent *src, *dst;
	struct udpc_assoc *a;

	src = udpc_fd_lookup(oldfd);
	if (src == NULL)
		return;

	dst = udpc_fd_claim(newfd,
	                    atomic_load_explicit(&src->family, memory_order_relaxed),
	                    atomic_load_explicit(&src->type, memory_order_relaxed));
	if (dst == NULL) {
		udpc_err("cannot track duplicated descriptor %d; its traffic "
		         "would be unproxied",
		         newfd);
		return;
	}

	/* FR-L-03: both descriptors share one association, which survives until
	 * the last of them closes. */
	a = atomic_load_explicit(&src->assoc, memory_order_acquire);
	if (a != NULL) {
		udpc_assoc_ref(a);
		atomic_store_explicit(&dst->assoc, a, memory_order_release);
	}

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
}

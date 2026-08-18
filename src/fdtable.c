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

	/* The kernel guarantees this fd number is not concurrently live, so the
	 * only states we can legitimately find are FREE or a stale DYING from a
	 * close that has already dropped its reference. */
	if (!atomic_compare_exchange_strong_explicit(&e->state, &expected,
	                                             UDPC_FD_CLAIMING,
	                                             memory_order_acq_rel,
	                                             memory_order_acquire)) {
		expected = UDPC_FD_DYING;
		if (!atomic_compare_exchange_strong_explicit(&e->state, &expected,
		                                             UDPC_FD_CLAIMING,
		                                             memory_order_acq_rel,
		                                             memory_order_acquire)) {
			udpc_debug("fd %d already claimed (state %d)", fd,
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

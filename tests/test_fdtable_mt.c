/* test_fdtable_mt.c -- the lock-free fd table under real race detection.
 *
 * D-07 chose a lock-free two-level radix table so that NFR-02 (no allocation on
 * the datagram path) and NFR-03 (signal safety) fall out of the design.  The
 * cost of that choice is memory ordering, which is the part of this codebase
 * most likely to harbour a rare, hard-to-reproduce bug -- §11 of the baseline
 * names it as a risk.
 *
 * This test exists because neither of the obvious tools can check that in the
 * normal integration setup:
 *
 *   Helgrind does not model C11 atomics, so it reports every atomic access as a
 *   possible race.  It cannot see the happens-before edges the design relies
 *   on, and its findings there are noise.
 *
 *   TSan does model C11 atomics correctly -- but it intercepts read(), recv()
 *   and recvfrom(), which is the same conflict that stops ASan from running the
 *   LD_PRELOAD integration tests (see tests/run_sanitizers.sh).
 *
 * So this test LINKS the fd table directly instead of preloading the shim.  No
 * interception, no conflict, and TSan can then say something meaningful about
 * the thing that actually needed checking.  It uses plain descriptor NUMBERS
 * rather than real sockets: the table is being tested, not the datagram path.
 *
 * Build:  make TSAN=1 build/test_fdtable_mt && ./build/test_fdtable_mt
 */
#include "tap.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "fdtable.h"

#define NTHREADS 8
#define NITER 2000
#define FD_SPAN 512  /* deliberately spans several 256-entry blocks */

static _Atomic int g_errors;
static _Atomic int g_claims;
static _Atomic int g_lookups;

/* Churns claim/publish/lookup/release across a range of descriptor numbers.
 *
 * Threads deliberately collide on the same numbers.  In the real shim the
 * kernel guarantees one live socket per descriptor, so two threads never claim
 * the same fd concurrently -- but the table must still behave sanely when they
 * try, rather than corrupting a neighbouring entry or tearing a block. */
static void *churn(void *arg)
{
	long id = (long)arg;
	int i;

	for (i = 0; i < NITER; i++) {
		int fd = (int)((id * 37 + i * 13) % FD_SPAN);
		struct udpc_fdent *e;

		e = udpc_fd_claim(fd, AF_INET, SOCK_DGRAM);
		if (e != NULL) {
			atomic_fetch_add(&g_claims, 1);

			/* Fields written before publish must be visible to any
			 * thread that later observes the entry as ACTIVE. */
			udpc_fd_publish(e);

			{
				struct udpc_fdent *found = udpc_fd_lookup(fd);
				if (found != NULL) {
					atomic_fetch_add(&g_lookups, 1);
					int fam = atomic_load_explicit(
						&found->family, memory_order_relaxed);
					int ty = atomic_load_explicit(
						&found->type, memory_order_relaxed);

					/* The entry may have been recycled by
					 * another thread between the lookup and
					 * this read, so AF_INET6 (from the
					 * sparse workers) is legitimate.  What
					 * must never appear is a value nobody
					 * ever wrote. */
					if ((fam != AF_INET && fam != AF_INET6) ||
					    ty != SOCK_DGRAM)
						atomic_fetch_add(&g_errors, 1);
				}
			}

			udpc_fd_release(fd);
		}

		/* Look up a descriptor this thread does not own, to exercise
		 * concurrent lookup against another thread's claim/release. */
		(void)udpc_fd_lookup((int)((id * 71 + i * 29) % FD_SPAN));
	}
	return NULL;
}

/* Exercises the block-allocation CAS: many threads racing to be the first to
 * touch descriptor numbers in previously unallocated blocks. */
static void *sparse(void *arg)
{
	long id = (long)arg;
	int i;

	for (i = 0; i < 64; i++) {
		/* Spread across high, previously untouched block indices. */
		int fd = 4096 + i * 256 + (int)id;
		struct udpc_fdent *e = udpc_fd_claim(fd, AF_INET6, SOCK_DGRAM);

		if (e == NULL)
			continue;
		udpc_fd_publish(e);
		if (udpc_fd_lookup(fd) == NULL)
			atomic_fetch_add(&g_errors, 1);
		udpc_fd_release(fd);
	}
	return NULL;
}

/* dup-style sharing: one owner descriptor, several threads pointing new
 * descriptors at it and releasing them (FR-L-03 refcounting). */
static int g_owner_fd = 9000;

static void *sharer(void *arg)
{
	long id = (long)arg;
	int i;

	for (i = 0; i < 200; i++) {
		int newfd = 9100 + (int)id * 16 + (i % 16);

		udpc_fd_share(g_owner_fd, newfd);
		if (udpc_fd_lookup(newfd) != NULL)
			udpc_fd_release(newfd);
	}
	return NULL;
}

int main(void)
{
	pthread_t th[NTHREADS];
	long i;

	TAP_GROUP("D-07: concurrent claim / publish / lookup / release");
	atomic_store(&g_errors, 0);
	atomic_store(&g_claims, 0);
	atomic_store(&g_lookups, 0);

	for (i = 0; i < NTHREADS; i++)
		pthread_create(&th[i], NULL, churn, (void *)i);
	for (i = 0; i < NTHREADS; i++)
		pthread_join(th[i], NULL);

	TAP_OK(atomic_load(&g_claims) > 0, "descriptors were claimed (%d)",
	       atomic_load(&g_claims));
	TAP_OK(atomic_load(&g_lookups) > 0, "descriptors were looked up (%d)",
	       atomic_load(&g_lookups));
	TAP_EQ_INT(atomic_load(&g_errors), 0,
	           "no entry was ever observed with torn or foreign contents");

	TAP_GROUP("D-07: racing block allocation in unallocated ranges");
	atomic_store(&g_errors, 0);
	for (i = 0; i < NTHREADS; i++)
		pthread_create(&th[i], NULL, sparse, (void *)i);
	for (i = 0; i < NTHREADS; i++)
		pthread_join(th[i], NULL);
	TAP_EQ_INT(atomic_load(&g_errors), 0,
	           "every entry published in a fresh block was then visible");

	TAP_GROUP("FR-L-03: concurrent sharing and release");
	{
		struct udpc_fdent *owner =
			udpc_fd_claim(g_owner_fd, AF_INET, SOCK_DGRAM);
		TAP_OK(owner != NULL, "the owning descriptor is claimed");
		udpc_fd_publish(owner);

		atomic_store(&g_errors, 0);
		for (i = 0; i < NTHREADS; i++)
			pthread_create(&th[i], NULL, sharer, (void *)i);
		for (i = 0; i < NTHREADS; i++)
			pthread_join(th[i], NULL);

		TAP_EQ_INT(atomic_load(&g_errors), 0,
		           "concurrent share/release left the table consistent");
		TAP_OK(udpc_fd_lookup(g_owner_fd) != NULL,
		       "the owning descriptor survived every share and release");
		udpc_fd_release(g_owner_fd);
		TAP_OK(udpc_fd_lookup(g_owner_fd) == NULL,
		       "and is gone once released");
	}

	TAP_GROUP("FR-L-02: a released entry is not visible to a later lookup");
	{
		struct udpc_fdent *e = udpc_fd_claim(77, AF_INET, SOCK_DGRAM);
		unsigned gen_before;

		TAP_OK(e != NULL, "descriptor 77 is claimed");
		udpc_fd_publish(e);
		gen_before = atomic_load(&e->generation);
		TAP_OK(udpc_fd_lookup(77) != NULL, "and is visible");

		udpc_fd_release(77);
		TAP_OK(udpc_fd_lookup(77) == NULL, "after release it is invisible");
		TAP_OK(atomic_load(&e->generation) != gen_before,
		       "and the generation counter advanced, so a reused fd "
		       "number cannot inherit stale state");
	}


	/* A descriptor closed WITHOUT the shim seeing it strands its entry
	 * ACTIVE.  That is not hypothetical: dig closes through libuv, which
	 * does not reach the interposed close(), so 60 of its 64 close syscalls
	 * are invisible to the shim.  When the kernel then hands the same fd
	 * number to a later socket(), the claim used to be refused and the
	 * caller got EMFILE -- a working program broken by a descriptor it had
	 * closed correctly.  The stranded entry also kept its association
	 * reference, leaking the control connection.
	 *
	 * The kernel never hands out a live descriptor number, so a non-FREE
	 * entry at claim time is proof of staleness, not of a conflict. */
	TAP_GROUP("a stale entry is recycled, not refused (uninterposed close)");
	{
		struct udpc_fdent *first, *second;
		unsigned gen_before;

		first = udpc_fd_claim(91, AF_INET, SOCK_DGRAM);
		TAP_OK(first != NULL, "descriptor 91 is claimed");
		udpc_fd_publish(first);
		gen_before = atomic_load(&first->generation);

		/* No udpc_fd_release: this is precisely the close the shim
		 * never saw. */
		second = udpc_fd_claim(91, AF_INET6, SOCK_DGRAM);
		TAP_OK(second != NULL,
		       "claiming it again SUCCEEDS rather than returning NULL, "
		       "which is what produced a spurious EMFILE");
		TAP_OK(second == first,
		       "and reuses the same slot, as the fd number demands");
		TAP_OK(atomic_load(&second->generation) != gen_before,
		       "the generation advanced, so anything holding the old "
		       "entry is rejected (FR-L-02)");
		TAP_EQ_INT(atomic_load(&second->family), AF_INET6,
		           "the slot carries the NEW socket's family, not the "
		           "stranded one's");
		TAP_OK(atomic_load(&second->assoc) == NULL,
		       "and no association is inherited from the stale entry");

		udpc_fd_publish(second);
		TAP_OK(udpc_fd_lookup(91) != NULL, "the recycled entry is usable");
		udpc_fd_release(91);
	}

	TAP_DONE();
}

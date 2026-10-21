#include "assoc.h"

#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "addr.h"
#include "guard.h"
#include "log.h"
#include "real.h"

/* Sentinel stored in the entry's assoc pointer while one thread is
 * establishing.  A real association is never at address 1. */
#define ASSOC_ESTABLISHING ((struct udpc_assoc *)1)

static _Atomic unsigned g_fork_generation = 0;

/* The fd this thread is currently establishing, or -1.
 *
 * Guards the one case where spinning on the sentinel would deadlock: a signal
 * handler that sends on the very fd the interrupted code is establishing.  The
 * interrupted code cannot make progress until the handler returns, so the
 * handler must not wait for it.  It gets EAGAIN instead -- which is honest,
 * non-deadlocking, and something a caller may retry. */
static __thread int t_establishing_fd = -1;

unsigned udpc_fork_generation(void)
{
	return atomic_load_explicit(&g_fork_generation, memory_order_acquire);
}

/* Closes every hop's control connection: what tells each proxy to release its
 * part of the association (FR-P-02).  Each is the shim's own descriptor, so it
 * is released as one (D-26).  A walk, close() and plain stores: safe in a fork
 * child handler (D-31). */
static void close_controls(struct udpc_socks_chain *ch)
{
	unsigned k;

	for (k = 0; k < ch->n && k < UDPC_CHAIN_MAX; k++) {
		if (ch->control_fd[k] >= 0)
			udpc_fd_shim_close(ch->control_fd[k]);
		ch->control_fd[k] = -1;
	}
}

/* D-31, for each of the child's table entries: let go of the parent's
 * control connections, and of a half-built association. */
static void child_drop_inherited(struct udpc_fdent *e)
{
	struct udpc_assoc *a = atomic_load_explicit(&e->assoc, memory_order_acquire);

	/* A thread of the parent's was establishing this association when the
	 * fork happened.  That thread does not exist in the child, so nothing
	 * would ever clear the marker, and the child's first send would wait
	 * on it forever. */
	if (a == ASSOC_ESTABLISHING) {
		atomic_store_explicit(&e->assoc, NULL, memory_order_release);
		return;
	}
	if (a != NULL)
		close_controls(&a->chain);
}

static void atfork_child(void)
{
	atomic_fetch_add_explicit(&g_fork_generation, 1u, memory_order_release);

	/* D-31: close the child's copies of the parent's control connections
	 * now.  Left open, they kept each association alive at the proxy for
	 * as long as any child lived: closing a TCP connection sends its FIN
	 * only when the LAST process holding it closes it.  The parent keeps
	 * its own copies, so nothing changes for the parent.
	 *
	 * This runs in the child of a possibly multithreaded parent, where
	 * only async-signal-safe work is allowed.  It is: a walk of the table
	 * with atomic loads, close(), and plain stores to memory the child
	 * alone now owns.  The associations themselves are still dropped on
	 * next use, when their fork generation is found stale (DESIGN.md 3.4). */
	udpc_fd_for_each_active(child_drop_inherited);
}

void udpc_assoc_init(void)
{
	(void)pthread_atfork(NULL, NULL, atfork_child);
}

/* --- type-stable allocation (D-24) ----------------------------------------- */

/* Freed associations go onto a Treiber stack and are never returned to the
 * allocator.  Pushes are lock-free.  Pops are serialised by a mutex, which is
 * what rules out the ABA problem: a node can only leave the stack through the
 * one popper holding the lock.  The mutex is only ever TRIED, so a pop from a
 * signal handler that interrupted another pop -- or from a forked child whose
 * parent held it -- falls back to a fresh allocation instead of deadlocking. */
static _Atomic(struct udpc_assoc *) g_free;
static pthread_mutex_t g_pop = PTHREAD_MUTEX_INITIALIZER;

static long now_coarse(void);

struct udpc_assoc *udpc_assoc_alloc(void)
{
	struct udpc_assoc *a = NULL;

	if (pthread_mutex_trylock(&g_pop) == 0) {
		a = atomic_load_explicit(&g_free, memory_order_acquire);
		while (a != NULL &&
		       !atomic_compare_exchange_weak_explicit(&g_free, &a, a->next_free,
		                                              memory_order_acquire,
		                                              memory_order_acquire))
			;
		pthread_mutex_unlock(&g_pop);
	}
	if (a == NULL) {
		a = calloc(1, sizeof(*a));
		if (a == NULL)
			return NULL;
	}

	/* Everything but the count first.  A reader holding a stale pointer to
	 * this object can take a reference only once the count is non-zero, and
	 * even then it will find the entry pointing elsewhere and let go. */
	a->next_free = NULL;
	a->fork_generation = udpc_fork_generation();
	{
		unsigned k;

		memset(&a->chain, 0, sizeof(a->chain));
		for (k = 0; k < UDPC_CHAIN_MAX; k++)
			a->chain.control_fd[k] = -1;
	}
	atomic_store_explicit(&a->last_used, now_coarse(), memory_order_relaxed);
	atomic_store_explicit(&a->refcount, 1, memory_order_release);
	return a;
}

static void free_push(struct udpc_assoc *a)
{
	struct udpc_assoc *head = atomic_load_explicit(&g_free, memory_order_relaxed);

	do {
		a->next_free = head;
	} while (!atomic_compare_exchange_weak_explicit(&g_free, &head, a,
	                                                memory_order_release,
	                                                memory_order_relaxed));
}

struct udpc_assoc *udpc_assoc_get(struct udpc_fdent *e)
{
	for (;;) {
		struct udpc_assoc *a =
			atomic_load_explicit(&e->assoc, memory_order_acquire);
		int rc;

		if (a == NULL || a == ASSOC_ESTABLISHING)
			return NULL;

		/* Take a reference only while the count is non-zero: zero means
		 * the object is being torn down or is on the free list, and must
		 * not be revived.  The memory itself is always valid (D-24). */
		rc = atomic_load_explicit(&a->refcount, memory_order_relaxed);
		while (rc > 0 &&
		       !atomic_compare_exchange_weak_explicit(&a->refcount, &rc, rc + 1,
		                                              memory_order_acquire,
		                                              memory_order_relaxed))
			;
		if (rc <= 0)
			continue; /* torn down under us; reload the entry */

		/* The object may have been recycled for another socket between
		 * the load and the reference.  Only if the entry still points at
		 * it is it this entry's association. */
		if (atomic_load_explicit(&e->assoc, memory_order_acquire) == a)
			return a;
		udpc_assoc_unref(a);
	}
}

void udpc_assoc_unref(struct udpc_assoc *a)
{
	if (a == NULL || a == ASSOC_ESTABLISHING)
		return;
	if (atomic_fetch_sub_explicit(&a->refcount, 1, memory_order_acq_rel) == 1) {
		/* Last reference: closing the control connections is what tells
		 * the proxies to release the association (FR-P-02). */
		atomic_thread_fence(memory_order_acquire);
		close_controls(&a->chain);
		a->chain.n = 0;
		free_push(a);
	}
}

void udpc_assoc_drop(struct udpc_fdent *e, struct udpc_assoc *a)
{
	if (a == NULL || a == ASSOC_ESTABLISHING)
		return;
	/* Only if the entry still points at THIS association: another thread
	 * may already have replaced it, and its replacement is not ours to
	 * drop.  Winning the exchange transfers the entry's own reference to
	 * us, so the object cannot be freed before the unref below. */
	if (atomic_compare_exchange_strong_explicit(&e->assoc, &a, NULL,
	                                            memory_order_acq_rel,
	                                            memory_order_acquire)) {
		udpc_assoc_unref(a);
	}
}

void udpc_assoc_invalidate(struct udpc_fdent *e)
{
	udpc_assoc_drop(e, atomic_load_explicit(&e->assoc, memory_order_acquire));
}

bool udpc_assoc_relay_of(const struct udpc_assoc *a, int family,
                         struct sockaddr_storage *out)
{
	/* The relay's family follows the control connection; the application's
	 * socket has whatever family the application chose.  An AF_INET6 socket
	 * with a proxy reached over IPv4 is entirely normal, so the relay
	 * address is adapted to something this socket can actually reach. */
	return udpc_addr_for_family((const struct sockaddr *)&a->chain.relay[0].sa,
	                            family, out) == 0;
}

void udpc_assoc_mark_used(struct udpc_assoc *a)
{
	atomic_store_explicit(&a->last_used, now_coarse(), memory_order_relaxed);
}

static long now_coarse(void)
{
	struct timespec ts;

	/* COARSE is a vDSO read of a cached value: cheap enough for the send
	 * path, and one-second granularity is all the idle probe needs. */
	if (clock_gettime(CLOCK_MONOTONIC_COARSE, &ts) != 0)
		return 0;
	return (long)ts.tv_sec;
}

/* D-05 R2: a loopback destination is resolved at the PROXY, so with a remote
 * proxy the datagram reaches the proxy host's loopback rather than this host's.
 * Silent misrouting is the same class of defect the project exists to remove,
 * so it is called out -- and can be promoted to a hard error.
 *
 * D-40: it is the EXIT hop that resolves it.  Only a chain of one can have its
 * exit on this host; a longer chain's exit is reached through other hops, so a
 * loopback destination there is always the far end's. */
static int loopback_guard(const struct udpc_config *cfg, const struct udpc_fdent *e,
                          int *out_errno)
{
	char abuf[UDPC_ADDRSTRLEN];
	const struct sockaddr *dst;

	if (cfg->nextra == 0 && cfg->proxy_is_local)
		return 0;
	if (!atomic_load_explicit(&e->connected, memory_order_acquire))
		return 0;

	dst = (const struct sockaddr *)&e->app_dst;
	if (!udpc_addr_is_loopback(dst))
		return 0;

	if (cfg->strict_loopback) {
		if (cfg->nextra > 0)
			udpc_err("refusing loopback destination %s: it would be "
			         "resolved at the chain's last hop, not here "
			         "(strict_loopback is on)",
			         udpc_addr_str(dst, abuf, sizeof(abuf)));
		else
			udpc_err("refusing loopback destination %s: the proxy is not on "
			         "this host, so it would be resolved at the proxy "
			         "(strict_loopback is on)",
			         udpc_addr_str(dst, abuf, sizeof(abuf)));
		*out_errno = ENETUNREACH;
		return -1;
	}

	if (cfg->nextra > 0)
		udpc_warn("destination %s is loopback; it will be resolved at the "
		          "chain's last hop, not here",
		          udpc_addr_str(dst, abuf, sizeof(abuf)));
	else
		udpc_warn("destination %s is loopback but the proxy is not on this "
		          "host; it will be resolved at the proxy, not here",
		          udpc_addr_str(dst, abuf, sizeof(abuf)));
	return 0;
}

/* Points the application's own fd at the relay (FR-I-07).  There is no shadow
 * socket: this is the application's descriptor, so poll/select/epoll and every
 * socket option keep working untouched. */
static int redirect_fd(int fd, int family, struct udpc_assoc *a, int *out_errno)
{
	struct sockaddr_storage relay;
	socklen_t rlen;
	char rbuf[UDPC_ADDRSTRLEN];

	if (udpc_addr_for_family((const struct sockaddr *)&a->chain.relay[0].sa,
	                         family, &relay) != 0) {
		udpc_err("proxy returned relay %s, which an %s socket cannot "
		         "reach",
		         udpc_addr_str((const struct sockaddr *)&a->chain.relay[0].sa,
		                       rbuf, sizeof(rbuf)),
		         family == AF_INET6 ? "AF_INET6" : "AF_INET");
		*out_errno = EAFNOSUPPORT;
		return -1;
	}

	rlen = udpc_sa_len((const struct sockaddr *)&relay);
	if (rlen == 0) {
		*out_errno = EAFNOSUPPORT;
		return -1;
	}
	if (REAL_CONNECT(fd, (const struct sockaddr *)&relay, rlen) != 0) {
		*out_errno = errno;
		return -1;
	}
	return 0;
}

/* Gives this process a private socket behind `fd`, for use after a fork.
 *
 * fork duplicates the descriptor TABLE but not the open file DESCRIPTION: the
 * parent and child end up pointing at the same kernel socket.  So if the child
 * simply re-pointed `fd` at its own relay, it would re-point the parent's
 * socket too, and the parent's traffic would start going to the child's
 * association.  FR-L-04 asks for isolation, and isolation here means a new
 * socket dup2'd onto the same descriptor number -- which affects only this
 * process's descriptor table.
 *
 * Socket options set by the application are not carried over; O_NONBLOCK, the
 * close-on-exec flag and a concrete bind are, because those change observable
 * behaviour rather than tuning.  A child that inherits a UDP socket, keeps
 * using it, AND depends on other socket options is beyond what this can
 * reconstruct; the README says so.
 */
static int reprivatize_socket(int fd, struct udpc_fdent *e, int *out_errno)
{
	int ns, fl, fdflags;

	ns = REAL_SOCKET(atomic_load_explicit(&e->family, memory_order_relaxed),
	                 atomic_load_explicit(&e->type, memory_order_relaxed), 0);
	if (ns < 0) {
		*out_errno = errno;
		return -1;
	}

	fl = fcntl(fd, F_GETFL);
	if (fl >= 0)
		(void)fcntl(ns, F_SETFL, fl);

	/* D-34: whatever the application bound -- a concrete address, or a
	 * wildcard with a port -- the private socket binds again.  The parent
	 * usually still holds that port, so this usually FAILS.  Carrying on
	 * as if it had not was the defect: the association would still declare
	 * the bound address to the proxy (FR-P-05), the child would send from
	 * another port, and a proxy that pins the association to its declared
	 * address would drop everything, silently.  So a failed re-bind stops
	 * the declaration, and says so once. */
	if (atomic_load_explicit(&e->rebind, memory_order_acquire)) {
		const struct sockaddr *b = (const struct sockaddr *)&e->bound;
		socklen_t blen = udpc_sa_len(b);

		if (blen != 0 && REAL_BIND(ns, b, blen) != 0) {
			static atomic_flag warned = ATOMIC_FLAG_INIT;
			char abuf[UDPC_ADDRSTRLEN];
			int berr = errno;

			atomic_store_explicit(&e->bound_set, false, memory_order_release);
			atomic_store_explicit(&e->rebind, false, memory_order_release);
			if (!atomic_flag_test_and_set(&warned))
				udpc_warn("fd %d: after fork, this process could not bind "
				          "%s again (%s) -- the parent holds it -- so its "
				          "datagrams leave from another port, and the proxy "
				          "is no longer told a source address",
				          fd, udpc_addr_str(b, abuf, sizeof(abuf)),
				          strerror(berr));
		}
	}

	/* dup2 always clears FD_CLOEXEC on the target, so capture and restore
	 * whatever the application had. */
	fdflags = fcntl(fd, F_GETFD);

	if (REAL_DUP2(ns, fd) < 0) {
		*out_errno = errno;
		REAL_CLOSE(ns);
		return -1;
	}
	REAL_CLOSE(ns);
	/* A different socket now sits behind fd, by design; without this the
	 * next call would take it for a stale entry and drop it (D-23). */
	udpc_fd_rebind_cookie(e, fd);

	if (fdflags >= 0)
		(void)fcntl(fd, F_SETFD, fdflags);

	udpc_debug("fd %d: replaced the socket inherited across fork with a "
	           "private one",
	           fd);
	return 0;
}

static int establish(int fd, struct udpc_fdent *e, const struct udpc_config *cfg,
                     int *out_errno)
{
	struct udpc_assoc *a;
	const struct sockaddr *bind_addr = NULL;
	char abuf[UDPC_ADDRSTRLEN], rbuf[UDPC_SOCKS_CHAIN_PATH_MAX];

	if (loopback_guard(cfg, e, out_errno) != 0)
		return -1;

	a = udpc_assoc_alloc();
	if (a == NULL) {
		*out_errno = ENOMEM;
		return -1;
	}

	/* FR-P-05: declare the bound address only when the application actually
	 * bound a concrete one.  Proxies pin the association to a declared
	 * address, so declaring one we will not send from breaks it. */
	if (atomic_load_explicit(&e->bound_set, memory_order_acquire))
		bind_addr = (const struct sockaddr *)&e->bound;

	/* The handshake is the shim's own traffic; the guard keeps the shim
	 * transparent to itself (guard.h). */
	UDPC_GUARD_ENTER();
	if (udpc_socks_associate_chain(cfg, bind_addr, &a->chain, out_errno) != 0) {
		UDPC_GUARD_LEAVE();
		udpc_assoc_unref(a);
		/* SEC-01: the failure is reported on the application's call.
		 * There is no fallback to a direct send. */
		return -1;
	}
	UDPC_GUARD_LEAVE();

	/* D-26: the control connections are the shim's own descriptors.
	 * Moved out of the application's way and marked, so a close-all loop
	 * in the application cannot take them -- and so this association can
	 * never close a number the application has since been given. */
	{
		unsigned k;

		for (k = 0; k < a->chain.n; k++)
			a->chain.control_fd[k] =
				udpc_fd_shim_adopt(a->chain.control_fd[k]);
	}

	if (redirect_fd(fd, atomic_load_explicit(&e->family, memory_order_relaxed),
	                a, out_errno) != 0) {
		udpc_assoc_unref(a);
		return -1;
	}

	atomic_store_explicit(&e->assoc, a, memory_order_release);

	/* FR-C-06: one line per association, naming the destination -- so the
	 * operator can see that proxying is actually happening.  The configured
	 * datagram limit is reported too, because a mismatch with the proxy's
	 * real limit shows up as silent drops (D-12).  For a chain, the relay
	 * of every hop, in order (FR-CH-12). */
	udpc_socks_chain_path(&a->chain, rbuf, sizeof(rbuf));
	if (atomic_load_explicit(&e->connected, memory_order_acquire))
		udpc_info("association up: fd %d -> %s via relay %s "
		          "(max_datagram %zu)",
		          fd,
		          udpc_addr_str((const struct sockaddr *)&e->app_dst, abuf,
		                        sizeof(abuf)),
		          rbuf, cfg->max_datagram);
	else
		udpc_info("association up: fd %d via relay %s (max_datagram %zu)",
		          fd, rbuf, cfg->max_datagram);

	return 0;
}

/* udpc_assoc_ensure, returning a reference to the association it ensured, so
 * the caller can use it without taking another (D-24).  NULL on failure. */
static struct udpc_assoc *ensure_held(int fd, struct udpc_fdent *e,
                                      const struct udpc_config *cfg,
                                      int *out_errno)
{
	struct udpc_assoc *a;
	int spins = 0;

	for (;;) {
		a = atomic_load_explicit(&e->assoc, memory_order_acquire);

		if (a != NULL && a != ASSOC_ESTABLISHING) {
			bool inherited;

			/* Read through a reference: another thread may be
			 * dropping this association right now (D-24). */
			a = udpc_assoc_get(e);
			if (a == NULL)
				continue;
			inherited = a->fork_generation != udpc_fork_generation();
			if (!inherited)
				return a; /* the caller's reference */
			udpc_assoc_unref(a);

			/* FR-L-04: an association inherited across fork belongs
			 * to the parent.  Drop it and establish our own. */
			{
				udpc_debug("fd %d: association inherited across "
				           "fork, re-establishing",
				           fd);
				udpc_assoc_invalidate(e);
				/* Must come before establishing, so the redirect
				 * lands on this process's own socket rather than
				 * the one still shared with the parent. */
				if (reprivatize_socket(fd, e, out_errno) != 0)
					return NULL;
				continue;
			}
		}

		if (a == ASSOC_ESTABLISHING) {
			if (t_establishing_fd == fd) {
				/* Re-entered on this thread, almost certainly
				 * from a signal handler, for the very fd being
				 * established.  Waiting could never succeed. */
				*out_errno = EAGAIN;
				return NULL;
			}
			if (++spins < 64)
				sched_yield();
			else {
				struct timespec ts = { 0, 1000000 }; /* 1 ms */
				nanosleep(&ts, NULL);
			}
			continue;
		}

		/* a == NULL: try to become the establishing thread. */
		if (atomic_compare_exchange_strong_explicit(
			    &e->assoc, &a, ASSOC_ESTABLISHING, memory_order_acq_rel,
			    memory_order_acquire)) {
			int rc, saved_fd = t_establishing_fd;

			t_establishing_fd = fd;
			rc = establish(fd, e, cfg, out_errno);
			t_establishing_fd = saved_fd;

			if (rc != 0) {
				/* Put the slot back so a later call may retry;
				 * this call still fails (SEC-01). */
				struct udpc_assoc *expected = ASSOC_ESTABLISHING;
				atomic_compare_exchange_strong_explicit(
					&e->assoc, &expected, NULL,
					memory_order_acq_rel, memory_order_acquire);
				return NULL;
			}
			continue; /* established: loop once to take the reference */
		}
		/* Lost the race; loop and observe the winner's result. */
	}
}

int udpc_assoc_ensure(int fd, struct udpc_fdent *e, const struct udpc_config *cfg,
                      int *out_errno)
{
	struct udpc_assoc *a = ensure_held(fd, e, cfg, out_errno);

	if (a == NULL)
		return -1;
	udpc_assoc_unref(a);
	return 0;
}

struct udpc_assoc *udpc_assoc_hold(int fd, struct udpc_fdent *e,
                                   const struct udpc_config *cfg, bool revalidate,
                                   int *out_errno)
{
	struct udpc_assoc *a = ensure_held(fd, e, cfg, out_errno);
	long last, now;

	if (a == NULL || !revalidate)
		return a;

	/* FR-P-08: an association idle long enough to have been expired is
	 * checked before the send, not discovered from a failure after it --
	 * by then the datagram has gone to a relay port that no longer exists.
	 * Busy sockets pay nothing: the check is a comparison until the
	 * association has been quiet for UDPC_IDLE_PROBE_SECS. */
	last = atomic_load_explicit(&a->last_used, memory_order_relaxed);
	now = now_coarse();
	if (now - last < UDPC_IDLE_PROBE_SECS)
		return a;
	if (udpc_socks_chain_alive(&a->chain)) {
		atomic_store_explicit(&a->last_used, now, memory_order_relaxed);
		return a;
	}

	udpc_debug("association idle for %lds and the control connection is "
	           "gone; re-associating before this send (FR-P-08)",
	           now - last);
	udpc_assoc_drop(e, a);
	udpc_assoc_unref(a);
	return ensure_held(fd, e, cfg, out_errno);
}

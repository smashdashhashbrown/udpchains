#include "assoc.h"

#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <sched.h>
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

static void atfork_child(void)
{
	/* Bump a counter and nothing else.  Tearing down inherited associations
	 * here would mean closing descriptors and touching the allocator from a
	 * context where neither is safe; the work is deferred to next use
	 * (DESIGN.md 3.4). */
	atomic_fetch_add_explicit(&g_fork_generation, 1u, memory_order_release);
}

void udpc_assoc_init(void)
{
	(void)pthread_atfork(NULL, NULL, atfork_child);
}

void udpc_assoc_ref(struct udpc_assoc *a)
{
	if (a == NULL || a == ASSOC_ESTABLISHING)
		return;
	atomic_fetch_add_explicit(&a->refcount, 1, memory_order_relaxed);
}

void udpc_assoc_unref(struct udpc_assoc *a)
{
	if (a == NULL || a == ASSOC_ESTABLISHING)
		return;
	if (atomic_fetch_sub_explicit(&a->refcount, 1, memory_order_acq_rel) == 1) {
		/* Last reference: closing the control connection is what tells
		 * the proxy to release the association (FR-P-02). */
		atomic_thread_fence(memory_order_acquire);
		udpc_socks_disconnect(&a->conn);
		free(a);
	}
}

bool udpc_assoc_relay(const struct udpc_fdent *e, struct sockaddr_storage *out)
{
	struct udpc_assoc *a =
		atomic_load_explicit(&e->assoc, memory_order_acquire);

	if (a == NULL || a == ASSOC_ESTABLISHING)
		return false;

	/* The relay's family follows the control connection; the application's
	 * socket has whatever family the application chose.  An AF_INET6 socket
	 * with a proxy reached over IPv4 is entirely normal, so the relay
	 * address is adapted to something this socket can actually reach. */
	return udpc_addr_for_family((const struct sockaddr *)&a->conn.relay,
	                            atomic_load_explicit(&e->family,
	                                                 memory_order_relaxed),
	                            out) == 0;
}

void udpc_assoc_invalidate(struct udpc_fdent *e)
{
	struct udpc_assoc *a =
		atomic_load_explicit(&e->assoc, memory_order_acquire);

	if (a == NULL || a == ASSOC_ESTABLISHING)
		return;
	if (atomic_compare_exchange_strong_explicit(&e->assoc, &a, NULL,
	                                            memory_order_acq_rel,
	                                            memory_order_acquire)) {
		atomic_store_explicit(&e->redirected, false, memory_order_release);
		udpc_assoc_unref(a);
	}
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

void udpc_assoc_touch(struct udpc_fdent *e)
{
	struct udpc_assoc *a =
		atomic_load_explicit(&e->assoc, memory_order_acquire);

	if (a == NULL || a == ASSOC_ESTABLISHING)
		return;
	atomic_store_explicit(&a->last_used, now_coarse(), memory_order_relaxed);
}

void udpc_assoc_revalidate(struct udpc_fdent *e)
{
	struct udpc_assoc *a =
		atomic_load_explicit(&e->assoc, memory_order_acquire);
	long last, now;

	if (a == NULL || a == ASSOC_ESTABLISHING)
		return;

	last = atomic_load_explicit(&a->last_used, memory_order_relaxed);
	now = now_coarse();
	if (now - last < UDPC_IDLE_PROBE_SECS)
		return;

	/* The proxy ties association lifetime to the control connection
	 * (baseline §0.5), so an expired association shows up as a closed
	 * control connection. */
	if (!udpc_socks_control_alive(&a->conn)) {
		udpc_debug("association idle for %lds and the control connection "
		           "is gone; re-associating before this send (FR-P-08)",
		           now - last);
		udpc_assoc_invalidate(e);
	} else {
		/* Still alive: do not probe again until it goes idle afresh. */
		atomic_store_explicit(&a->last_used, now, memory_order_relaxed);
	}
}

/* D-05 R2: a loopback destination is resolved at the PROXY, so with a remote
 * proxy the datagram reaches the proxy host's loopback rather than this host's.
 * Silent misrouting is the same class of defect the project exists to remove,
 * so it is called out -- and can be promoted to a hard error. */
static int loopback_guard(const struct udpc_config *cfg, const struct udpc_fdent *e,
                          int *out_errno)
{
	char abuf[UDPC_ADDRSTRLEN];
	const struct sockaddr *dst;

	if (cfg->proxy_is_local)
		return 0;
	if (!atomic_load_explicit(&e->connected, memory_order_acquire))
		return 0;

	dst = (const struct sockaddr *)&e->app_dst;
	if (!udpc_addr_is_loopback(dst))
		return 0;

	if (cfg->strict_loopback) {
		udpc_err("refusing loopback destination %s: the proxy is not on "
		         "this host, so it would be resolved at the proxy "
		         "(strict_loopback is on)",
		         udpc_addr_str(dst, abuf, sizeof(abuf)));
		*out_errno = ENETUNREACH;
		return -1;
	}

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

	if (udpc_addr_for_family((const struct sockaddr *)&a->conn.relay, family,
	                         &relay) != 0) {
		udpc_err("proxy returned relay %s, which an %s socket cannot "
		         "reach",
		         udpc_addr_str((const struct sockaddr *)&a->conn.relay, rbuf,
		                       sizeof(rbuf)),
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

	if (atomic_load_explicit(&e->bound_set, memory_order_acquire)) {
		socklen_t blen = udpc_sa_len((const struct sockaddr *)&e->bound);
		if (blen != 0)
			(void)REAL_BIND(ns, (const struct sockaddr *)&e->bound, blen);
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
	char abuf[UDPC_ADDRSTRLEN], rbuf[UDPC_ADDRSTRLEN];

	if (loopback_guard(cfg, e, out_errno) != 0)
		return -1;

	a = calloc(1, sizeof(*a));
	if (a == NULL) {
		*out_errno = ENOMEM;
		return -1;
	}
	atomic_store_explicit(&a->refcount, 1, memory_order_relaxed);
	atomic_store_explicit(&a->last_used, now_coarse(), memory_order_relaxed);
	a->fork_generation = udpc_fork_generation();
	a->conn.control_fd = -1;

	/* FR-P-05: declare the bound address only when the application actually
	 * bound a concrete one.  Proxies pin the association to a declared
	 * address, so declaring one we will not send from breaks it. */
	if (atomic_load_explicit(&e->bound_set, memory_order_acquire))
		bind_addr = (const struct sockaddr *)&e->bound;

	/* The handshake is the shim's own traffic; the guard keeps the shim
	 * transparent to itself (guard.h). */
	UDPC_GUARD_ENTER();
	if (udpc_socks_associate(cfg, bind_addr, &a->conn, out_errno) != 0) {
		UDPC_GUARD_LEAVE();
		free(a);
		/* SEC-01: the failure is reported on the application's call.
		 * There is no fallback to a direct send. */
		return -1;
	}
	UDPC_GUARD_LEAVE();

	if (redirect_fd(fd, atomic_load_explicit(&e->family, memory_order_relaxed),
	                a, out_errno) != 0) {
		udpc_socks_disconnect(&a->conn);
		free(a);
		return -1;
	}

	atomic_store_explicit(&e->redirected, true, memory_order_release);
	atomic_store_explicit(&e->assoc, a, memory_order_release);

	/* FR-C-06: one line per association, naming the destination -- so the
	 * operator can see that proxying is actually happening.  The configured
	 * datagram limit is reported too, because a mismatch with the proxy's
	 * real limit shows up as silent drops (D-12). */
	if (atomic_load_explicit(&e->connected, memory_order_acquire))
		udpc_info("association up: fd %d -> %s via relay %s "
		          "(max_datagram %zu)",
		          fd,
		          udpc_addr_str((const struct sockaddr *)&e->app_dst, abuf,
		                        sizeof(abuf)),
		          udpc_addr_str((const struct sockaddr *)&a->conn.relay,
		                        rbuf, sizeof(rbuf)),
		          cfg->max_datagram);
	else
		udpc_info("association up: fd %d via relay %s (max_datagram %zu)",
		          fd,
		          udpc_addr_str((const struct sockaddr *)&a->conn.relay,
		                        rbuf, sizeof(rbuf)),
		          cfg->max_datagram);

	return 0;
}

int udpc_assoc_ensure(int fd, struct udpc_fdent *e, const struct udpc_config *cfg,
                      int *out_errno)
{
	struct udpc_assoc *a;
	int spins = 0;

	for (;;) {
		a = atomic_load_explicit(&e->assoc, memory_order_acquire);

		if (a != NULL && a != ASSOC_ESTABLISHING) {
			/* FR-L-04: an association inherited across fork belongs
			 * to the parent.  Drop it and establish our own. */
			if (a->fork_generation != udpc_fork_generation()) {
				udpc_debug("fd %d: association inherited across "
				           "fork, re-establishing",
				           fd);
				udpc_assoc_invalidate(e);
				/* Must come before establishing, so the redirect
				 * lands on this process's own socket rather than
				 * the one still shared with the parent. */
				if (reprivatize_socket(fd, e, out_errno) != 0)
					return -1;
				continue;
			}
			return 0;
		}

		if (a == ASSOC_ESTABLISHING) {
			if (t_establishing_fd == fd) {
				/* Re-entered on this thread, almost certainly
				 * from a signal handler, for the very fd being
				 * established.  Waiting could never succeed. */
				*out_errno = EAGAIN;
				return -1;
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
				return -1;
			}
			return 0;
		}
		/* Lost the race; loop and observe the winner's result. */
	}
}

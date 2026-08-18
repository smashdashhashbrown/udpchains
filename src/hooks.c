/* hooks.c -- the exported LD_PRELOAD symbols (FR-I-01…FR-I-07).
 *
 * Every hook here is a thin wrapper.  The send variants funnel into
 * udpc_core_send and the receive variants into udpc_core_recv (core.h), which
 * is what makes FR-I-02 structural: there is no wrapping path without a
 * matching unwrapping path.
 *
 * Deliberately NOT hooked, per FR-I-07: poll, select, epoll_wait, setsockopt,
 * getsockopt.  Because the application's own fd is redirected to the relay
 * rather than shadowed, readiness and socket options work untouched.  Adding a
 * hook for any of them would be a sign the architecture had drifted.
 */
#include "compat.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "addr.h"
#include "assoc.h"
#include "core.h"
#include "fdtable.h"
#include "guard.h"
#include "log.h"
#include "real.h"
#include "shim.h"

/* --- initialisation -------------------------------------------------------- */

/* A UDP socket inherited across exec was never seen by our socket() hook, so
 * nothing would intercept its traffic and it would go direct -- the silent leak
 * this project exists to prevent (SEC-01).  Adopting such descriptors at
 * start-up closes that hole.
 *
 * Runs once, off the datagram path, so the directory walk and its allocation
 * are fine (NFR-02 concerns the per-datagram path only). */
static void adopt_inherited_fds(void)
{
	DIR *d;
	struct dirent *ent;
	int dfd;

	d = opendir("/proc/self/fd");
	if (d == NULL)
		return;
	dfd = dirfd(d);

	while ((ent = readdir(d)) != NULL) {
		int fd, domain = 0, type = 0;
		socklen_t len;
		struct udpc_fdent *e;
		char *end = NULL;
		long v;

		if (ent->d_name[0] == '.')
			continue;
		v = strtol(ent->d_name, &end, 10);
		if (end == ent->d_name || *end != '\0' || v < 0 || v > INT_MAX)
			continue;
		fd = (int)v;
		if (fd == dfd)
			continue;

		len = sizeof(domain);
		if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &len) != 0)
			continue;
		len = sizeof(type);
		if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len) != 0)
			continue;

		if (type != SOCK_DGRAM)
			continue;
		if (domain != AF_INET && domain != AF_INET6)
			continue;

		e = udpc_fd_claim(fd, domain, type);
		if (e == NULL)
			continue;
		udpc_fd_publish(e);
		udpc_debug("adopted inherited UDP descriptor %d", fd);
	}

	closedir(d);
}

__attribute__((constructor)) static void udpc_ctor(void)
{
	/* Registering the atfork handler must happen before the application can
	 * fork (FR-L-04). */
	udpc_assoc_init();

	/* Resolving configuration here rather than lazily means a
	 * misconfiguration is reported at start-up instead of at the first
	 * datagram, which is closer to FR-C-03's intent.  A failure is not
	 * fatal here -- the shim cannot refuse to run an already-running
	 * program -- but every intercepted datagram will then fail closed. */
	(void)udpc_shim_config();

	adopt_inherited_fds();
}

/* --- helpers --------------------------------------------------------------- */

static bool is_intercepted_kind(int domain, int type)
{
	/* FR-I-06: only SOCK_DGRAM in AF_INET/AF_INET6.  SOCK_NONBLOCK and
	 * SOCK_CLOEXEC ride in the type argument and must be masked off. */
	int base = type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);

	if (base != SOCK_DGRAM)
		return false;
	return domain == AF_INET || domain == AF_INET6;
}

/* --- lifecycle hooks (FR-I-04) --------------------------------------------- */

int socket(int domain, int type, int protocol)
{
	int fd = REAL_SOCKET(domain, type, protocol);
	struct udpc_fdent *e;

	if (fd < 0 || UDPC_IN_SHIM())
		return fd;
	if (!is_intercepted_kind(domain, type))
		return fd;

	/* Claim even when the shim is unconfigured.  An unclaimed socket would
	 * pass through unproxied, which is the leak SEC-01 forbids; a claimed
	 * one fails closed on first use. */
	e = udpc_fd_claim(fd, domain, type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC));
	if (e == NULL) {
		/* Cannot track it, so cannot guarantee it is proxied. */
		REAL_CLOSE(fd);
		errno = EMFILE;
		return -1;
	}
	udpc_fd_publish(e);
	udpc_debug("intercepting new %s datagram socket, fd %d",
	           domain == AF_INET6 ? "AF_INET6" : "AF_INET", fd);
	return fd;
}

int bind(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	struct udpc_fdent *e = udpc_intercept(fd);
	int rc;

	if (e == NULL)
		return REAL_BIND(fd, addr, addrlen);

	rc = REAL_BIND(fd, addr, addrlen);
	if (rc != 0)
		return rc;

	/* FR-P-05: a concrete bound address is declared in the UDP ASSOCIATE
	 * request; a wildcard one is not, because proxies pin the association
	 * to whatever is declared. */
	if (addr != NULL && udpc_sa_len(addr) != 0) {
		bool concrete = false;

		if (addr->sa_family == AF_INET) {
			const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
			concrete = (in->sin_addr.s_addr != INADDR_ANY);
		} else if (addr->sa_family == AF_INET6) {
			const struct sockaddr_in6 *in6 =
				(const struct sockaddr_in6 *)addr;
			concrete = !IN6_IS_ADDR_UNSPECIFIED(&in6->sin6_addr);
		}

		memcpy(&e->bound, addr, udpc_sa_len(addr));
		atomic_store_explicit(&e->bound_set, concrete, memory_order_release);
	}
	return 0;
}

int connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	struct udpc_fdent *e = udpc_intercept(fd);
	const struct udpc_config *cfg;
	int err = 0;

	if (e == NULL)
		return REAL_CONNECT(fd, addr, addrlen);

	/* FR-F-08: connect(AF_UNSPEC) dissolves the association, per POSIX. */
	if (addr != NULL && addrlen >= (socklen_t)sizeof(sa_family_t) &&
	    addr->sa_family == AF_UNSPEC) {
		atomic_store_explicit(&e->connected, false, memory_order_release);
		memset(&e->app_dst, 0, sizeof(e->app_dst));
		udpc_debug("fd %d: connect(AF_UNSPEC) dissolved the destination",
		           fd);
		return 0;
	}

	if (addr == NULL || udpc_sa_len(addr) == 0) {
		errno = EAFNOSUPPORT;
		return -1;
	}

	/* Record the destination the application named.  Published with release
	 * ordering so a concurrent send that observes `connected` also observes
	 * a complete address. */
	memcpy(&e->app_dst, addr, udpc_sa_len(addr));
	atomic_store_explicit(&e->connected, true, memory_order_release);

	/* FR-F-08: a second connect() re-targets.  The association is unchanged
	 * -- only the destination written into each header differs -- so there
	 * is nothing to tear down. */

	cfg = udpc_shim_config();
	if (cfg != NULL) {
		/* Point the fd at the relay now if we can (FR-F-08).  A failure
		 * here is deliberately not reported: FR-L-06 wants an
		 * unreachable proxy surfaced on the application's send, and a
		 * UDP connect() that fails with a network error would surprise
		 * every caller.  The send will fail closed. */
		if (udpc_assoc_ensure(fd, e, cfg, &err) != 0)
			udpc_debug("fd %d: connect deferred association setup (%s)",
			           fd, strerror(err));
	}
	return 0;
}

int close(int fd)
{
	if (!UDPC_IN_SHIM())
		udpc_fd_release(fd);
	return REAL_CLOSE(fd);
}

#if UDPCHAINS_HAVE_CLOSE_RANGE
int close_range(unsigned first, unsigned last, int flags)
{
	/* CLOSE_RANGE_CLOEXEC marks descriptors rather than closing them, so
	 * the entries must survive. */
	if (!UDPC_IN_SHIM() && (flags & CLOSE_RANGE_CLOEXEC) == 0) {
		unsigned fd;

		for (fd = first; fd <= last && fd < UDPC_FD_MAX; fd++) {
			udpc_fd_release((int)fd);
			if (fd == UINT_MAX)
				break;
		}
	}
	return REAL_CLOSE_RANGE(first, last, flags);
}
#endif

int dup(int oldfd)
{
	int newfd = REAL_DUP(oldfd);

	if (newfd >= 0 && !UDPC_IN_SHIM())
		udpc_fd_share(oldfd, newfd);
	return newfd;
}

int dup2(int oldfd, int newfd)
{
	int rc;

	/* dup2 implicitly closes newfd, so its entry must be released first --
	 * exactly as the kernel closes the descriptor. */
	if (!UDPC_IN_SHIM() && oldfd != newfd)
		udpc_fd_release(newfd);

	rc = REAL_DUP2(oldfd, newfd);
	if (rc >= 0 && !UDPC_IN_SHIM() && oldfd != newfd)
		udpc_fd_share(oldfd, rc);
	return rc;
}

int dup3(int oldfd, int newfd, int flags)
{
	int rc;

	if (!UDPC_IN_SHIM() && oldfd != newfd)
		udpc_fd_release(newfd);

	rc = REAL_DUP3(oldfd, newfd, flags);
	if (rc >= 0 && !UDPC_IN_SHIM() && oldfd != newfd)
		udpc_fd_share(oldfd, rc);
	return rc;
}

/* --- introspection (FR-I-05) ----------------------------------------------- */

int getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	struct udpc_fdent *e = udpc_intercept(fd);
	socklen_t want, give;

	if (e == NULL)
		return REAL_GETPEERNAME(fd, addr, addrlen);

	/* FR-I-05: report the destination the application believes it has,
	 * never the relay's -- which is what the real call would return, since
	 * the fd is connected to the relay. */
	if (!atomic_load_explicit(&e->connected, memory_order_acquire)) {
		errno = ENOTCONN;
		return -1;
	}
	if (addr == NULL || addrlen == NULL) {
		errno = EFAULT;
		return -1;
	}

	want = udpc_sa_len((const struct sockaddr *)&e->app_dst);
	give = (*addrlen < want) ? *addrlen : want;
	memcpy(addr, &e->app_dst, give);
	*addrlen = want;
	return 0;
}

int getsockname(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	struct udpc_fdent *e = udpc_intercept(fd);

	if (e == NULL)
		return REAL_GETSOCKNAME(fd, addr, addrlen);

	/* If the application bound a concrete address, that is what it believes
	 * its local address to be, and the real call would report whatever the
	 * kernel chose for talking to the relay. */
	if (atomic_load_explicit(&e->bound_set, memory_order_acquire) &&
	    addr != NULL && addrlen != NULL) {
		struct sockaddr_storage local;
		socklen_t want = udpc_sa_len((const struct sockaddr *)&e->bound);
		socklen_t give;

		memcpy(&local, &e->bound, sizeof(local));

		/* The application may have bound port 0, in which case the port
		 * it actually has is the kernel's choice -- report that. */
		if (udpc_sa_port((const struct sockaddr *)&local) == 0) {
			struct sockaddr_storage real_local;
			socklen_t rl = sizeof(real_local);

			if (REAL_GETSOCKNAME(fd, (struct sockaddr *)&real_local,
			                     &rl) == 0)
				udpc_sa_set_port(
					(struct sockaddr *)&local,
					udpc_sa_port((const struct sockaddr *)
					                     &real_local));
		}

		give = (*addrlen < want) ? *addrlen : want;
		memcpy(addr, &local, give);
		*addrlen = want;
		return 0;
	}

	/* Otherwise the real local address is the honest answer: it is the
	 * application's own socket, not the relay's. */
	return REAL_GETSOCKNAME(fd, addr, addrlen);
}

/* --- send hooks (FR-I-03) -------------------------------------------------- */

ssize_t sendto(int fd, const void *buf, size_t len, int flags,
               const struct sockaddr *dst, socklen_t dstlen)
{
	struct udpc_fdent *e = udpc_intercept(fd);
	struct iovec iov;

	if (e == NULL)
		return REAL_SENDTO(fd, buf, len, flags, dst, dstlen);

	iov.iov_base = (void *)(uintptr_t)buf;
	iov.iov_len = len;
	return udpc_core_send(fd, e, &iov, 1, dst, dstlen, flags);
}

ssize_t send(int fd, const void *buf, size_t len, int flags)
{
	/* send is sendto with no destination. */
	return sendto(fd, buf, len, flags, NULL, 0);
}

ssize_t write(int fd, const void *buf, size_t len)
{
	struct udpc_fdent *e = udpc_intercept(fd);
	struct iovec iov;

	if (e == NULL)
		return REAL_WRITE(fd, buf, len);

	iov.iov_base = (void *)(uintptr_t)buf;
	iov.iov_len = len;
	return udpc_core_send(fd, e, &iov, 1, NULL, 0, 0);
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
{
	struct udpc_fdent *e = udpc_intercept(fd);

	if (e == NULL)
		return REAL_WRITEV(fd, iov, iovcnt);
	return udpc_core_send(fd, e, iov, iovcnt, NULL, 0, 0);
}

ssize_t sendmsg(int fd, const struct msghdr *msg, int flags)
{
	struct udpc_fdent *e = udpc_intercept(fd);

	if (e == NULL)
		return REAL_SENDMSG(fd, msg, flags);
	if (msg == NULL) {
		errno = EFAULT;
		return -1;
	}

	/* Ancillary data on send describes a socket the application does not
	 * actually own (§8 of the requirements).  It is ignored rather than
	 * forwarded, since forwarding relay-relative values would be worse than
	 * dropping them. */
	if (msg->msg_controllen > 0)
		udpc_debug("fd %d: ignoring %zu bytes of ancillary data on send",
		           fd, (size_t)msg->msg_controllen);

	return udpc_core_send(fd, e, msg->msg_iov, (int)msg->msg_iovlen,
	                      (const struct sockaddr *)msg->msg_name,
	                      msg->msg_namelen, flags);
}

int sendmmsg(int fd, struct mmsghdr *msgvec, unsigned vlen, int flags)
{
	struct udpc_fdent *e = udpc_intercept(fd);
	unsigned i;

	if (e == NULL)
		return REAL_SENDMMSG(fd, msgvec, vlen, flags);
	if (msgvec == NULL) {
		errno = EFAULT;
		return -1;
	}

	/* FR-F-09: each message is handled independently and partial success is
	 * reported as the kernel does -- if message k fails after k succeeded,
	 * return k; if the first fails, return -1. */
	for (i = 0; i < vlen; i++) {
		struct msghdr *m = &msgvec[i].msg_hdr;
		ssize_t n = udpc_core_send(fd, e, m->msg_iov, (int)m->msg_iovlen,
		                           (const struct sockaddr *)m->msg_name,
		                           m->msg_namelen, flags);
		if (n < 0) {
			if (i == 0)
				return -1;
			return (int)i;
		}
		msgvec[i].msg_len = (unsigned)n;
	}
	return (int)vlen;
}

/* --- receive hooks (FR-I-03) ----------------------------------------------- */

ssize_t recvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr *src,
                 socklen_t *srclen)
{
	struct udpc_fdent *e = udpc_intercept(fd);
	struct iovec iov;

	if (e == NULL)
		return REAL_RECVFROM(fd, buf, len, flags, src, srclen);

	iov.iov_base = buf;
	iov.iov_len = len;
	return udpc_core_recv(fd, e, &iov, 1, src, srclen, flags, NULL);
}

ssize_t recv(int fd, void *buf, size_t len, int flags)
{
	/* recv is recvfrom with no source. */
	return recvfrom(fd, buf, len, flags, NULL, NULL);
}

ssize_t read(int fd, void *buf, size_t len)
{
	struct udpc_fdent *e = udpc_intercept(fd);
	struct iovec iov;

	if (e == NULL)
		return REAL_READ(fd, buf, len);

	iov.iov_base = buf;
	iov.iov_len = len;
	return udpc_core_recv(fd, e, &iov, 1, NULL, NULL, 0, NULL);
}

ssize_t readv(int fd, const struct iovec *iov, int iovcnt)
{
	struct udpc_fdent *e = udpc_intercept(fd);

	if (e == NULL)
		return REAL_READV(fd, iov, iovcnt);
	return udpc_core_recv(fd, e, iov, iovcnt, NULL, NULL, 0, NULL);
}

ssize_t recvmsg(int fd, struct msghdr *msg, int flags)
{
	struct udpc_fdent *e = udpc_intercept(fd);
	socklen_t namelen;
	int msgflags = 0;
	ssize_t n;

	if (e == NULL)
		return REAL_RECVMSG(fd, msg, flags);
	if (msg == NULL) {
		errno = EFAULT;
		return -1;
	}

	namelen = msg->msg_namelen;
	n = udpc_core_recv(fd, e, msg->msg_iov, (int)msg->msg_iovlen,
	                   (struct sockaddr *)msg->msg_name,
	                   msg->msg_name != NULL ? &namelen : NULL, flags,
	                   &msgflags);
	if (n < 0)
		return -1;

	if (msg->msg_name != NULL)
		msg->msg_namelen = namelen;

	/* FR-F-11: ancillary data is returned empty rather than carrying
	 * relay-derived values that would mislead.  MSG_CTRUNC is deliberately
	 * NOT set: nothing was truncated, because there was nothing. */
	msg->msg_controllen = 0;

	/* FR-F-04: report truncation the way the kernel does. */
	msg->msg_flags = msgflags;
	return n;
}

int recvmmsg(int fd, struct mmsghdr *msgvec, unsigned vlen, int flags,
             struct timespec *timeout)
{
	struct udpc_fdent *e = udpc_intercept(fd);
	unsigned i;
	struct timespec start;
	bool have_deadline = (timeout != NULL);

	if (e == NULL)
		return REAL_RECVMMSG(fd, msgvec, vlen, flags, timeout);
	if (msgvec == NULL) {
		errno = EFAULT;
		return -1;
	}

	if (have_deadline)
		clock_gettime(CLOCK_MONOTONIC, &start);

	for (i = 0; i < vlen; i++) {
		struct msghdr *m = &msgvec[i].msg_hdr;
		socklen_t namelen = m->msg_namelen;
		int msgflags = 0;
		int use_flags = flags;
		ssize_t n;

		/* A blocking recvmmsg waits for vlen messages; it does NOT stop
		 * at whatever happens to be queued.  Only MSG_WAITFORONE turns
		 * on MSG_DONTWAIT after the first, which is applied at the
		 * bottom of this loop. */
		n = udpc_core_recv(fd, e, m->msg_iov, (int)m->msg_iovlen,
		                   (struct sockaddr *)m->msg_name,
		                   m->msg_name != NULL ? &namelen : NULL, use_flags,
		                   &msgflags);
		if (n < 0) {
			if (i == 0)
				return -1;
			return (int)i;
		}

		if (m->msg_name != NULL)
			m->msg_namelen = namelen;
		m->msg_controllen = 0;
		m->msg_flags = msgflags;
		msgvec[i].msg_len = (unsigned)n;

		if (flags & MSG_WAITFORONE)
			flags |= MSG_DONTWAIT;

		if (have_deadline) {
			struct timespec now;
			long elapsed_ns, budget_ns;

			clock_gettime(CLOCK_MONOTONIC, &now);
			elapsed_ns = (long)(now.tv_sec - start.tv_sec) * 1000000000L +
			             (now.tv_nsec - start.tv_nsec);
			budget_ns = (long)timeout->tv_sec * 1000000000L +
			            timeout->tv_nsec;
			if (elapsed_ns >= budget_ns)
				return (int)(i + 1);
		}
	}
	return (int)vlen;
}

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
#include <poll.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
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

/* D-35: the shim is built with -fvisibility=hidden, so nothing it defines is
 * exported unless marked.  Every non-static function from here on is a hook,
 * and must be exported. */
#pragma GCC visibility push(default)

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

/* --- adoption of descriptors socket() never saw ---------------------------- */

/* A UDP socket can enter this process without passing through the socket()
 * hook or a dup: inherited across exec, or received from another process as
 * SCM_RIGHTS ancillary data.  Nothing would intercept its traffic and it would
 * go direct -- the silent leak this project exists to prevent (SEC-01).  Such
 * descriptors are adopted into the table as they arrive.
 *
 * Returns 0 if fd was adopted or is not a socket we intercept, and -1 if it is
 * one but cannot be tracked. */
/* An untrackable UDP socket is closed rather than left in the application's
 * hands, where it would send unproxied -- the same choice the socket() hook
 * makes, and the only fail-closed one.  So is a datagram socket for a protocol
 * SOCKS5 cannot carry (D-29). */
static void adopt_or_close(int fd, const char *how)
{
	int rc = udpc_fd_adopt(fd);

	if (rc > 0)
		udpc_debug("adopted %s UDP descriptor %d", how, fd);
	if (rc >= 0)
		return;
	if (rc == UDPC_ADOPT_UNPROXIABLE)
		udpc_err("%s descriptor %d is a non-UDP datagram socket (ICMP or "
		         "UDP-Lite), which SOCKS5 cannot carry; closing it rather "
		         "than leaving it unproxied",
		         how, fd);
	else
		udpc_err("cannot track %s UDP descriptor %d; closing it rather "
		         "than leaving it unproxied",
		         how, fd);
	REAL_CLOSE(fd);
}

static void adopt_inherited(int fd)
{
	/* A socket created by a hook before this constructor ran -- from
	 * another library's constructor, say -- is already tracked and must
	 * keep its state. */
	if (udpc_fd_lookup(fd) != NULL)
		return;
	adopt_or_close(fd, "inherited");
}

/* Without /proc (a minimal chroot or container) the descriptor table cannot be
 * listed, and giving up would leave every inherited UDP socket unproxied.  So
 * probe it instead: poll() with no events reports POLLNVAL for a number that is
 * not open, which tests a batch of numbers per syscall.
 *
 * The scan covers the trackable range and anything below the hard
 * RLIMIT_NOFILE.  A descriptor above both could only exist if the limit was
 * lowered after it was opened; that residual is accepted. */
static void adopt_inherited_by_probe(void)
{
	struct pollfd pfd[1024];
	struct rlimit rl;
	unsigned long limit = UDPC_FD_MAX, batch = 1024, base, i;

	if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
		if (rl.rlim_max != RLIM_INFINITY && rl.rlim_max > limit)
			limit = rl.rlim_max;
		/* poll() refuses more entries than the soft limit. */
		if (rl.rlim_cur != RLIM_INFINITY && rl.rlim_cur < batch)
			batch = rl.rlim_cur;
	}
	if (limit > (unsigned long)INT_MAX + 1)
		limit = (unsigned long)INT_MAX + 1;
	if (batch == 0)
		return;

	for (base = 0; base < limit; base += batch) {
		unsigned long n = (limit - base < batch) ? limit - base : batch;

		for (i = 0; i < n; i++) {
			pfd[i].fd = (int)(base + i);
			pfd[i].events = 0;
			pfd[i].revents = 0;
		}
		if (poll(pfd, (nfds_t)n, 0) < 0) {
			udpc_err("cannot list or probe inherited descriptors (%s); "
			         "an inherited UDP socket would be unproxied",
			         strerror(errno));
			return;
		}
		for (i = 0; i < n; i++)
			if (!(pfd[i].revents & POLLNVAL))
				adopt_inherited(pfd[i].fd);
	}
}

/* Runs once, off the datagram path, so the directory walk and its allocation
 * are fine (NFR-02 concerns the per-datagram path only). */
static void adopt_inherited_fds(void)
{
	DIR *d;
	struct dirent *ent;
	int dfd;

	d = opendir("/proc/self/fd");
	if (d == NULL) {
		adopt_inherited_by_probe();
		return;
	}
	dfd = dirfd(d);

	while ((ent = readdir(d)) != NULL) {
		char *end = NULL;
		long v;

		if (ent->d_name[0] == '.')
			continue;
		v = strtol(ent->d_name, &end, 10);
		if (end == ent->d_name || *end != '\0' || v < 0 || v > INT_MAX)
			continue;
		if ((int)v == dfd)
			continue;
		adopt_inherited((int)v);
	}

	closedir(d);
}

/* Descriptors received as SCM_RIGHTS are new numbers in this process, exactly
 * like the result of a dup, so a UDP socket among them is adopted before the
 * application can send on it. */
static void adopt_received_fds(const struct msghdr *msg)
{
	struct cmsghdr *c;
	int saved = errno;

	if (msg == NULL || msg->msg_control == NULL || msg->msg_controllen == 0 ||
	    UDPC_IN_SHIM())
		return;

	for (c = CMSG_FIRSTHDR(msg); c != NULL;
	     c = CMSG_NXTHDR((struct msghdr *)(uintptr_t)msg, c)) {
		size_t i, n;

		if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS ||
		    c->cmsg_len < CMSG_LEN(0))
			continue;
		n = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
		for (i = 0; i < n; i++) {
			int fd;

			memcpy(&fd, CMSG_DATA(c) + i * sizeof(int), sizeof(fd));
			adopt_or_close(fd, "received");
		}
	}
	errno = saved;
}

/* --- initialisation -------------------------------------------------------- */

__attribute__((constructor)) static void udpc_ctor(void)
{
	/* Before anything can log: what stderr is now is the program's
	 * stderr, and the shim writes nowhere else (D-33). */
	udpc_log_bind_stderr();

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

/* --- lifecycle hooks (FR-I-04) --------------------------------------------- */

int socket(int domain, int type, int protocol)
{
	struct udpc_fdent *e;
	int fd;

	/* D-29: a datagram socket in AF_INET/AF_INET6 that is not UDP -- ICMP
	 * "ping" sockets, UDP-Lite -- carries a protocol SOCKS5 cannot relay.
	 * Letting it through would send directly; wrapping it as UDP would
	 * send ICMP to the proxy's relay.  So it is refused, as multicast is. */
	if (!UDPC_IN_SHIM() && is_intercepted_kind(domain, type) && protocol != 0 &&
	    protocol != IPPROTO_UDP) {
		udpc_warn("refusing a datagram socket for IP protocol %d: SOCKS5 "
		          "carries only UDP, and udpchains sends nothing directly",
		          protocol);
		errno = EPROTONOSUPPORT;
		return -1;
	}

	fd = REAL_SOCKET(domain, type, protocol);
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
	 * to whatever is declared.  The kernel accepted addrlen, and the copy
	 * reads no more than it (L1). */
	{
		struct sockaddr_storage ss;
		bool concrete = false;

		if (udpc_sa_copy(addr, addrlen, &ss) != 0)
			return 0;
		if (ss.ss_family == AF_INET) {
			const struct sockaddr_in *in = (const struct sockaddr_in *)&ss;
			concrete = (in->sin_addr.s_addr != INADDR_ANY);
		} else {
			const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)&ss;
			concrete = !IN6_IS_ADDR_UNSPECIFIED(&in6->sin6_addr);
		}

		memcpy(&e->bound, &ss, sizeof(e->bound));
		/* A wildcard bind that names a port still fixes the socket's
		 * port, which a forked child's private socket must keep (D-34). */
		atomic_store_explicit(&e->rebind,
		                      concrete || udpc_sa_port((const struct sockaddr *)&ss) != 0,
		                      memory_order_relaxed);
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

	/* L1: checked against addrlen as the kernel would, since the real
	 * connect() never sees this address.  A short one is EINVAL, never a
	 * read past the caller's buffer. */
	{
		struct sockaddr_storage ss;

		if (addr == NULL) {
			errno = EFAULT;
			return -1;
		}
		if (udpc_sa_copy(addr, addrlen, &ss) != 0)
			return -1;

		/* Record the destination the application named.  Published with
		 * release ordering so a concurrent send that observes `connected`
		 * also observes a complete address. */
		memcpy(&e->app_dst, &ss, sizeof(e->app_dst));
	}
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
	if (!UDPC_IN_SHIM()) {
		/* D-26: the shim's own descriptor.  The application never opened
		 * it -- the kernel gave it to the shim -- so to the application
		 * it is not open, and closing it is EBADF.  Letting it through
		 * would drop a live association, and the shim would later close
		 * whatever the application had put at that number. */
		if (udpc_fd_is_shim(fd)) {
			udpc_debug("fd %d belongs to the shim; not closing it", fd);
			errno = EBADF;
			return -1;
		}
		udpc_fd_release(fd);
	}
	return REAL_CLOSE(fd);
}

#if UDPCHAINS_HAVE_CLOSE_RANGE
/* close_range, split around the shim's own descriptors (D-26).  Almost always
 * a single call: shim descriptors sit in one band, and most ranges miss it. */
static int close_range_around_shim(unsigned first, unsigned last, int flags)
{
	unsigned lo = first;
	int rc = 0, err = 0;

	while (lo <= last) {
		long s = udpc_fd_next_shim(lo, last);

		if (s >= 0 && !udpc_fd_is_shim((int)s))
			continue; /* a stale mark, now cleared: look again */
		if (s < 0 || (unsigned)s > lo) {
			unsigned hi = s < 0 ? last : (unsigned)s - 1;

			if (REAL_CLOSE_RANGE(lo, hi, flags) != 0) {
				rc = -1;
				err = errno;
			}
		}
		if (s < 0 || (unsigned)s == UINT_MAX)
			break;
		lo = (unsigned)s + 1;
	}
	if (rc != 0)
		errno = err;
	return rc;
}

int close_range(unsigned first, unsigned last, int flags)
{
	/* CLOSE_RANGE_CLOEXEC marks descriptors rather than closing them, so
	 * the entries must survive -- and the shim's are close-on-exec already,
	 * so there is nothing to protect. */
	if (UDPC_IN_SHIM() || (flags & CLOSE_RANGE_CLOEXEC))
		return REAL_CLOSE_RANGE(first, last, flags);

	udpc_fd_release_range(first, last);
	return close_range_around_shim(first, last, flags);
}

/* glibc's closefrom calls its internal close_range, which no hook sees: every
 * UDP socket above lowfd was left stranded in the table (D-23), and every
 * control connection above it was closed from under its association (D-26). */
void closefrom(int lowfd)
{
	(void)close_range(lowfd < 0 ? 0u : (unsigned)lowfd, ~0u, 0);
}
#endif

/* Finishes a duplication the kernel has already made.  Returns newfd, or -1
 * with EMFILE having closed it: a duplicate of an intercepted socket that the
 * table cannot track would send directly (SEC-01). */
static int track_dup(int oldfd, int newfd)
{
	if (udpc_fd_share(oldfd, newfd) == 0)
		return newfd;
	REAL_CLOSE(newfd);
	errno = EMFILE;
	return -1;
}

int dup(int oldfd)
{
	int newfd = REAL_DUP(oldfd);

	if (newfd < 0 || UDPC_IN_SHIM())
		return newfd;
	return track_dup(oldfd, newfd);
}

/* newfd's entry changes only once the kernel has actually replaced newfd.
 * Releasing it beforehand, as dup2's implicit close suggests, left a FAILED
 * dup2 -- EBADF on oldfd, say -- with newfd still open, still a UDP socket and
 * no longer tracked, so its next send went direct.  udpc_fd_share replaces or
 * releases the entry once the call has succeeded. */
/* D-26: dup2 onto the shim's own descriptor would close it silently.  Refused
 * with EBUSY, the one error dup2 already has for "that number cannot be used
 * right now".  The shim's descriptors sit in a band a program rarely names. */
static bool onto_shim(int oldfd, int newfd)
{
	if (UDPC_IN_SHIM() || oldfd == newfd || !udpc_fd_is_shim(newfd))
		return false;
	udpc_debug("refusing to dup onto fd %d: it belongs to the shim", newfd);
	errno = EBUSY;
	return true;
}

int dup2(int oldfd, int newfd)
{
	int rc;

	if (onto_shim(oldfd, newfd))
		return -1;
	rc = REAL_DUP2(oldfd, newfd);
	if (rc < 0 || UDPC_IN_SHIM() || oldfd == newfd)
		return rc;
	return track_dup(oldfd, rc);
}

int dup3(int oldfd, int newfd, int flags)
{
	int rc;

	if (onto_shim(oldfd, newfd))
		return -1;
	rc = REAL_DUP3(oldfd, newfd, flags);

	if (rc < 0 || UDPC_IN_SHIM() || oldfd == newfd)
		return rc;
	return track_dup(oldfd, rc);
}

/* fcntl(F_DUPFD) and F_DUPFD_CLOEXEC duplicate a descriptor exactly as dup
 * does, and are how several runtimes do it -- Python's socket.dup() and
 * os.dup() among them.  Unhooked, the copy of an intercepted socket was
 * untracked and sent directly.
 *
 * glibc exports one implementation as both fcntl and fcntl64, and a program
 * built with _FILE_OFFSET_BITS=64 calls the latter, so both are hooked.
 *
 * The third argument is read as a pointer whether or not the command takes
 * one, which is how glibc forwards it too: every command's argument is an int,
 * a long or a pointer, and each travels in the slot a pointer occupies. */
static int fcntl_common(udpc_fcntl_fn real, int fd, int cmd, void *arg)
{
	int rc = real(fd, cmd, arg);

	if (rc < 0 || UDPC_IN_SHIM() || (cmd != F_DUPFD && cmd != F_DUPFD_CLOEXEC))
		return rc;
	return track_dup(fd, rc);
}

int fcntl(int fd, int cmd, ...)
{
	va_list ap;
	void *arg;

	va_start(ap, cmd);
	arg = va_arg(ap, void *);
	va_end(ap);
	return fcntl_common(REAL_FCNTL, fd, cmd, arg);
}

int fcntl64(int fd, int cmd, ...)
{
	va_list ap;
	void *arg;

	va_start(ap, cmd);
	arg = va_arg(ap, void *);
	va_end(ap);
	return fcntl_common(REAL_FCNTL64, fd, cmd, arg);
}

/* syscall() is how some runtimes reach the kernel without libc's wrappers --
 * libuv closes descriptors this way, which is what stranded dig's table entries
 * (D-17, D-23).  The descriptor-lifecycle calls are routed to the hooks above,
 * so a socket created, duplicated or closed through syscall() is tracked like
 * any other.  Everything else, including sends and receives, goes straight to
 * the kernel: data calls through syscall() are unsupported, as the README says.
 *
 * Six arguments are read whatever the call, as glibc's own syscall() does; no
 * Linux system call takes more. */
long syscall(long number, ...)
{
	va_list ap;
	long a0, a1, a2, a3, a4, a5;

	va_start(ap, number);
	a0 = va_arg(ap, long);
	a1 = va_arg(ap, long);
	a2 = va_arg(ap, long);
	a3 = va_arg(ap, long);
	a4 = va_arg(ap, long);
	a5 = va_arg(ap, long);
	va_end(ap);

	if (!UDPC_IN_SHIM()) {
		switch (number) {
		case SYS_close:
			return close((int)a0);
#if UDPCHAINS_HAVE_CLOSE_RANGE && defined(SYS_close_range)
		case SYS_close_range:
			return close_range((unsigned)a0, (unsigned)a1, (int)a2);
#endif
		case SYS_dup:
			return dup((int)a0);
#ifdef SYS_dup2
		case SYS_dup2:
			return dup2((int)a0, (int)a1);
#endif
		case SYS_dup3:
			return dup3((int)a0, (int)a1, (int)a2);
		case SYS_fcntl:
			return fcntl((int)a0, (int)a1, (void *)(uintptr_t)a2);
		case SYS_socket:
			return socket((int)a0, (int)a1, (int)a2);
		default:
			break;
		}
	}
	return REAL_SYSCALL(number, a0, a1, a2, a3, a4, a5);
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

/* L2: msg_iovlen is a size_t, and the core takes an int.  Anything above
 * IOV_MAX is EMSGSIZE in the kernel too, and checking before the cast stops a
 * huge value wrapping into a small one. */
static bool iovlen_ok(const struct msghdr *m)
{
	if (m->msg_iovlen > (size_t)IOV_MAX) {
		errno = EMSGSIZE;
		return false;
	}
	return true;
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
	if (!iovlen_ok(msg))
		return -1;
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
		ssize_t n = !iovlen_ok(m) ? -1
		          : udpc_core_send(fd, e, m->msg_iov, (int)m->msg_iovlen,
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

/* --- fortified receive entry points (FR-I-02) ------------------------------ */

/* A program built with _FORTIFY_SOURCE -- the default for distribution
 * packages -- calls these instead of recv, recvfrom and read whenever the
 * buffer's size is known at compile time and the length is not.  glibc
 * implements them by calling its own internal receive functions, which no
 * preloaded library can interpose on.  Left unhooked, they handed the
 * application its datagram with the SOCKS header still attached: the Proxando
 * failure (baseline §0.3.2), arriving by a door the matrix never opened.
 *
 * Each makes the same bounds check glibc's does, then funnels into the ordinary
 * hook and so into the one receive path.  Declared here rather than taken from
 * <bits/socket2.h>, which only declares them in a fortified build. */
extern void __chk_fail(void) __attribute__((noreturn));
ssize_t __recv_chk(int fd, void *buf, size_t len, size_t buflen, int flags);
ssize_t __recvfrom_chk(int fd, void *buf, size_t len, size_t buflen, int flags,
                       struct sockaddr *src, socklen_t *srclen);
ssize_t __read_chk(int fd, void *buf, size_t len, size_t buflen);

ssize_t __recv_chk(int fd, void *buf, size_t len, size_t buflen, int flags)
{
	if (len > buflen)
		__chk_fail();
	return recv(fd, buf, len, flags);
}

ssize_t __recvfrom_chk(int fd, void *buf, size_t len, size_t buflen, int flags,
                       struct sockaddr *src, socklen_t *srclen)
{
	if (len > buflen)
		__chk_fail();
	return recvfrom(fd, buf, len, flags, src, srclen);
}

ssize_t __read_chk(int fd, void *buf, size_t len, size_t buflen)
{
	if (len > buflen)
		__chk_fail();
	return read(fd, buf, len);
}

ssize_t recvmsg(int fd, struct msghdr *msg, int flags)
{
	struct udpc_fdent *e = udpc_intercept(fd);
	socklen_t namelen;
	int msgflags = 0;
	ssize_t n;

	if (e == NULL) {
		/* Not ours -- but it may be a unix socket carrying descriptors,
		 * and a UDP socket among them must be adopted. */
		n = REAL_RECVMSG(fd, msg, flags);
		if (n >= 0)
			adopt_received_fds(msg);
		return n;
	}
	if (msg == NULL) {
		errno = EFAULT;
		return -1;
	}

	if (!iovlen_ok(msg))
		return -1;
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

	if (e == NULL) {
		int rc = REAL_RECVMMSG(fd, msgvec, vlen, flags, timeout);

		for (i = 0; rc > 0 && i < (unsigned)rc; i++)
			adopt_received_fds(&msgvec[i].msg_hdr);
		return rc;
	}
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
		n = !iovlen_ok(m) ? -1
		  : udpc_core_recv(fd, e, m->msg_iov, (int)m->msg_iovlen,
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

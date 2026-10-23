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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "addr.h"
#include "assoc.h"
#include "config.h"
#include "core.h"
#include "dgram.h"
#include "fdtable.h"
#include "guard.h"
#include "log.h"
#include "real.h"
#include "scratch.h"
#include "shim.h"

/* D-35: the shim is built with -fvisibility=hidden, so nothing it defines is
 * exported unless marked.  Every non-static function from here on is a hook,
 * and must be exported. */
#pragma GCC visibility push(default)

/* Hooks defined below that glibc declares only in newer headers, or not at
 * all, but that syscall() routes to before their definitions. */
#ifdef SYS_pidfd_getfd
int pidfd_getfd(int pidfd, int targetfd, unsigned int flags);
#endif

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

/* D-36: raw and packet sockets reach the network below UDP, where SOCKS5 cannot
 * follow.  SOCK_PACKET is the obsolete packet interface in AF_INET. */
static bool is_raw_kind(int domain, int type)
{
	int base = type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);

	if (domain == AF_PACKET)
		return true;
	return (domain == AF_INET || domain == AF_INET6) &&
	       (base == SOCK_RAW || base == SOCK_PACKET);
}

/* --- adoption of descriptors socket() never saw ---------------------------- */

/* A UDP socket can enter this process without passing through the socket()
 * hook or a dup: inherited across exec, or received from another process as
 * SCM_RIGHTS ancillary data.  Nothing would intercept its traffic and it would
 * go direct -- the silent leak this project exists to prevent (SEC-01).  Such
 * descriptors are adopted into the table as they arrive.  So is one copied out
 * of another process with pidfd_getfd (D-36).
 *
 * Returns udpc_fd_adopt's result: negative if fd was closed. */
/* An untrackable UDP socket is closed rather than left in the application's
 * hands, where it would send unproxied -- the same choice the socket() hook
 * makes, and the only fail-closed one.  So is a datagram socket for a protocol
 * SOCKS5 cannot carry (D-29). */
static int adopt_or_close(int fd, const char *how)
{
	int rc = udpc_fd_adopt(fd);

	if (rc > 0)
		udpc_debug("adopted %s UDP descriptor %d", how, fd);
	if (rc >= 0)
		return rc;
	if (rc == UDPC_ADOPT_UNPROXIABLE)
		udpc_err("%s descriptor %d is a raw, packet, ICMP or UDP-Lite "
		         "socket, which SOCKS5 cannot carry; closing it rather "
		         "than leaving it unproxied",
		         how, fd);
	else
		udpc_err("cannot track %s UDP descriptor %d; closing it rather "
		         "than leaving it unproxied",
		         how, fd);
	REAL_CLOSE(fd);
	return rc;
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

	/* D-36: a raw or packet socket would send directly, below anything the
	 * shim can wrap.  EPERM is what a program without CAP_NET_RAW already
	 * gets, so programs take the fallback they would take unprivileged. */
	if (!UDPC_IN_SHIM() && is_raw_kind(domain, type)) {
		udpc_warn("refusing a raw socket (%s): it reaches the network "
		          "below UDP, where SOCKS5 cannot follow, and udpchains "
		          "sends nothing directly",
		          domain == AF_PACKET ? "AF_PACKET" :
		          domain == AF_INET6 ? "AF_INET6" : "AF_INET");
		errno = EPERM;
		return -1;
	}

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
 * (D-17, D-23).  Every call a hook exists for is routed to that hook: the
 * descriptor lifecycle, and since D-36 the socket calls and sends and receives
 * too, so a UDP socket used through syscall() is proxied like any other.
 * Everything else goes straight to the kernel.  A program that makes its own
 * system calls without libc's syscall() -- Go, inline assembly -- is beyond
 * any preload.
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
		case SYS_connect:
			return connect((int)a0, (const struct sockaddr *)a1,
			               (socklen_t)a2);
		case SYS_bind:
			return bind((int)a0, (const struct sockaddr *)a1,
			            (socklen_t)a2);
		case SYS_getpeername:
			return getpeername((int)a0, (struct sockaddr *)a1,
			                   (socklen_t *)a2);
		case SYS_getsockname:
			return getsockname((int)a0, (struct sockaddr *)a1,
			                   (socklen_t *)a2);
		case SYS_sendto:
			return sendto((int)a0, (const void *)a1, (size_t)a2,
			              (int)a3, (const struct sockaddr *)a4,
			              (socklen_t)a5);
		case SYS_sendmsg:
			return sendmsg((int)a0, (const struct msghdr *)a1, (int)a2);
		case SYS_sendmmsg:
			return sendmmsg((int)a0, (struct mmsghdr *)a1, (unsigned)a2,
			                (int)a3);
		case SYS_write:
			return write((int)a0, (const void *)a1, (size_t)a2);
		case SYS_writev:
			return writev((int)a0, (const struct iovec *)a1, (int)a2);
		case SYS_recvfrom:
			return recvfrom((int)a0, (void *)a1, (size_t)a2, (int)a3,
			                (struct sockaddr *)a4, (socklen_t *)a5);
		case SYS_recvmsg:
			return recvmsg((int)a0, (struct msghdr *)a1, (int)a2);
		case SYS_recvmmsg:
			return recvmmsg((int)a0, (struct mmsghdr *)a1, (unsigned)a2,
			                (int)a3, (struct timespec *)a4);
		case SYS_read:
			return read((int)a0, (void *)a1, (size_t)a2);
		case SYS_readv:
			return readv((int)a0, (const struct iovec *)a1, (int)a2);
#if __SIZEOF_LONG__ == 8
		/* The offset is split across two arguments; on a 64-bit
		 * kernel the first holds all of it. */
		case SYS_pwritev2:
			return pwritev2((int)a0, (const struct iovec *)a1, (int)a2,
			                (off_t)a3, (int)a5);
		case SYS_preadv2:
			return preadv2((int)a0, (const struct iovec *)a1, (int)a2,
			               (off_t)a3, (int)a5);
#endif
		case SYS_sendfile:
			return sendfile((int)a0, (int)a1, (off_t *)a2, (size_t)a3);
		case SYS_splice:
			return splice((int)a0, (loff_t *)a1, (int)a2, (loff_t *)a3,
			              (size_t)a4, (unsigned)a5);
#ifdef SYS_pidfd_getfd
		case SYS_pidfd_getfd:
			return pidfd_getfd((int)a0, (int)a1, (unsigned)a2);
#endif
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

/* D-36: GSO would split one buffer into datagrams without headers. */
static bool refuse_gso(int fd, const struct msghdr *m)
{
	if (!udpc_dgram_wants_gso(fd, m))
		return false;
	errno = EOPNOTSUPP;
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
	if (!iovlen_ok(msg) || refuse_gso(fd, msg))
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
		ssize_t n = !iovlen_ok(m) || refuse_gso(fd, m) ? -1
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

/* --- routes around the send and receive hooks (D-36) ----------------------- */

/* These calls move data through a descriptor without passing through any of the
 * send or receive hooks above: the kernel does the work (sendfile, splice), or
 * glibc does it through internal calls (stdio).  On a UDP socket the data would
 * go out without a SOCKS header -- directly, if the kernel socket has a
 * destination of its own, or to the relay to be discarded.  Where the call can
 * be carried out through the shim, it is; where it cannot, it is refused. */

static struct udpc_ratelimit g_rl_unhookable;

static int refuse_unhookable(int fd, const char *what)
{
	char note[80];
	unsigned n = udpc_ratelimit(&g_rl_unhookable);

	if (n != 0)
		udpc_warn("refusing %s on UDP descriptor %d: it sends without "
		          "passing through udpchains, so the data could not be "
		          "proxied%s",
		          what, fd, udpc_ratelimit_note(n, note, sizeof(note)));
	errno = EINVAL;
	return -1;
}

ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
{
	if (udpc_intercept(out_fd) != NULL)
		return refuse_unhookable(out_fd, "sendfile");
	return REAL_SENDFILE(out_fd, in_fd, offset, count);
}

ssize_t sendfile64(int out_fd, int in_fd, off64_t *offset, size_t count)
{
	if (udpc_intercept(out_fd) != NULL)
		return refuse_unhookable(out_fd, "sendfile");
	return REAL_SENDFILE64(out_fd, in_fd, offset, count);
}

/* Refused in both directions: splicing out of a UDP socket would hand the
 * program the SOCKS header as data. */
ssize_t splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len,
               unsigned int flags)
{
	if (udpc_intercept(fd_in) != NULL)
		return refuse_unhookable(fd_in, "splice");
	if (udpc_intercept(fd_out) != NULL)
		return refuse_unhookable(fd_out, "splice");
	return REAL_SPLICE(fd_in, off_in, fd_out, off_out, len, flags);
}

/* A stream on a UDP socket reads and writes through glibc's internal calls,
 * which no hook sees.  Refusing the stream is the only point at which stdio
 * can be stopped. */
FILE *fdopen(int fd, const char *mode)
{
	if (udpc_intercept(fd) != NULL) {
		refuse_unhookable(fd, "a stdio stream (fdopen)");
		return NULL;
	}
	return REAL_FDOPEN(fd, mode);
}

/* pwritev2 and preadv2 with an offset of -1 act on the current position, which
 * on a socket makes them writev and readv.  Any other offset is ESPIPE on a
 * socket, as it is unhooked. */
static ssize_t pwritev2_common(udpc_pwritev2_fn real, int fd, const struct iovec *iov,
                               int iovcnt, off_t offset, int flags)
{
	if (udpc_intercept(fd) == NULL)
		return real(fd, iov, iovcnt, offset, flags);
	if (offset != -1) {
		errno = ESPIPE;
		return -1;
	}
	if (flags != 0) {
		errno = EOPNOTSUPP;
		return -1;
	}
	return writev(fd, iov, iovcnt);
}

static ssize_t preadv2_common(udpc_preadv2_fn real, int fd, const struct iovec *iov,
                              int iovcnt, off_t offset, int flags)
{
	if (udpc_intercept(fd) == NULL)
		return real(fd, iov, iovcnt, offset, flags);
	if (offset != -1) {
		errno = ESPIPE;
		return -1;
	}
	if (flags != 0) {
		errno = EOPNOTSUPP;
		return -1;
	}
	return readv(fd, iov, iovcnt);
}

ssize_t pwritev2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags)
{
	return pwritev2_common(REAL_PWRITEV2, fd, iov, iovcnt, offset, flags);
}

ssize_t pwritev64v2(int fd, const struct iovec *iov, int iovcnt, off64_t offset,
                    int flags)
{
	return pwritev2_common(REAL_PWRITEV64V2, fd, iov, iovcnt, offset, flags);
}

ssize_t preadv2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags)
{
	return preadv2_common(REAL_PREADV2, fd, iov, iovcnt, offset, flags);
}

ssize_t preadv64v2(int fd, const struct iovec *iov, int iovcnt, off64_t offset,
                   int flags)
{
	return preadv2_common(REAL_PREADV64V2, fd, iov, iovcnt, offset, flags);
}

/* dprintf formats into a stream glibc writes through an internal call.  On a
 * UDP socket the output is formatted here instead, into this thread's scratch
 * buffer, and sent through the shim as one datagram. */
int __vsnprintf_chk(char *s, size_t maxlen, int flag, size_t slen,
                    const char *fmt, va_list ap);
int __dprintf_chk(int fd, int flag, const char *fmt, ...);
int __vdprintf_chk(int fd, int flag, const char *fmt, va_list ap);

static int dprintf_through_shim(int fd, struct udpc_fdent *e, int flag,
                                const char *fmt, va_list ap)
{
	const struct udpc_config *cfg = udpc_shim_config();
	struct udpc_tls *tls;
	struct iovec iov;
	ssize_t sent;
	int n;

	if (cfg == NULL) {
		errno = udpc_shim_failure_errno();
		return -1;
	}
	tls = udpc_tls_get(cfg->max_datagram + UDPC_SOCKS_HDR_MAX);
	if (tls == NULL) {
		errno = ENOMEM;
		return -1;
	}
	n = flag > 0 ? __vsnprintf_chk((char *)tls->buf, tls->buflen, flag,
	                               tls->buflen, fmt, ap)
	             : vsnprintf((char *)tls->buf, tls->buflen, fmt, ap);
	if (n < 0)
		return -1;
	if ((size_t)n >= tls->buflen) {
		errno = EMSGSIZE;
		return -1;
	}
	iov.iov_base = tls->buf;
	iov.iov_len = (size_t)n;
	sent = udpc_core_send(fd, e, &iov, 1, NULL, 0, 0);
	return sent < 0 ? -1 : (int)sent;
}

int vdprintf(int fd, const char *fmt, va_list ap)
{
	struct udpc_fdent *e = udpc_intercept(fd);

	if (e == NULL)
		return REAL_VDPRINTF(fd, fmt, ap);
	return dprintf_through_shim(fd, e, 0, fmt, ap);
}

int __vdprintf_chk(int fd, int flag, const char *fmt, va_list ap)
{
	struct udpc_fdent *e = udpc_intercept(fd);

	if (e == NULL)
		return REAL_VDPRINTF_CHK(fd, flag, fmt, ap);
	return dprintf_through_shim(fd, e, flag, fmt, ap);
}

int dprintf(int fd, const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vdprintf(fd, fmt, ap);
	va_end(ap);
	return n;
}

int __dprintf_chk(int fd, int flag, const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = __vdprintf_chk(fd, flag, fmt, ap);
	va_end(ap);
	return n;
}

#ifdef SYS_pidfd_getfd
/* A socket copied out of another process is a new descriptor here, like one
 * received over SCM_RIGHTS, and is adopted the same way.  Made through
 * syscall() rather than glibc's wrapper, which is newer than the 2.34 floor
 * (NFR-01a). */
int pidfd_getfd(int pidfd, int targetfd, unsigned int flags)
{
	int fd = (int)REAL_SYSCALL(SYS_pidfd_getfd, (long)pidfd, (long)targetfd,
	                           (long)flags, 0L, 0L, 0L);
	int rc;

	if (fd < 0 || UDPC_IN_SHIM())
		return fd;
	rc = adopt_or_close(fd, "copied");
	if (rc < 0) {
		/* Closed: as socket() fails for each of these. */
		errno = rc == UDPC_ADOPT_UNTRACKABLE ? EMFILE : EPERM;
		return -1;
	}
	return fd;
}
#endif

/* glibc also exports some calls under a second, underscored name, kept for old
 * binaries.  A program can link against these directly, so each is the hook by
 * another name.  (glibc's own internal calls bind inside libc and never reach
 * here.) */
ssize_t __write(int fd, const void *buf, size_t len);
ssize_t __read(int fd, void *buf, size_t len);
ssize_t __send(int fd, const void *buf, size_t len, int flags);
int __connect(int fd, const struct sockaddr *addr, socklen_t addrlen);
int __close(int fd);
int __dup2(int oldfd, int newfd);
int __fcntl(int fd, int cmd, ...);

ssize_t __write(int fd, const void *buf, size_t len)
{
	return write(fd, buf, len);
}

ssize_t __read(int fd, void *buf, size_t len)
{
	return read(fd, buf, len);
}

ssize_t __send(int fd, const void *buf, size_t len, int flags)
{
	return send(fd, buf, len, flags);
}

int __connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	return connect(fd, addr, addrlen);
}

int __close(int fd)
{
	return close(fd);
}

int __dup2(int oldfd, int newfd)
{
	return dup2(oldfd, newfd);
}

int __fcntl(int fd, int cmd, ...)
{
	va_list ap;
	void *arg;

	va_start(ap, cmd);
	arg = va_arg(ap, void *);
	va_end(ap);
	return fcntl(fd, cmd, arg);
}

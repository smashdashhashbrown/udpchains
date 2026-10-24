/* svcall.c -- answering the program's calls in supervisor mode (D-48 to D-54).
 *
 * Each call reaches the supervisor stopped in the kernel before it runs, in
 * one of two ways (D-54).  A call on a descriptor in the range stops its thread
 * through ptrace (svtrace.c): it is handled while the thread cannot run, so
 * what is done for it and what it returns cannot be parted by a signal.  The
 * rest -- making and placing descriptors, and checking calls below the range
 * -- arrive by user notification, where a thread interrupted while the
 * supervisor holds its call discards the answer.
 *
 * A call on a UDP socket the supervisor made is performed here, on the
 * supervisor's own descriptor for the same socket: the payload read from the
 * program's memory, wrapped, and sent to the relay; a datagram taken, checked,
 * unwrapped and written into the program.  A receive with nothing queued waits
 * in the program's own kernel, natively.  Every other call is let through to
 * the kernel, or refused.
 *
 * For a notified call, every read of the program's memory is followed by a
 * check that the call is still pending before the bytes are used
 * (seccomp_unotify(2)): a call the program abandoned is never acted on, and a
 * thread number that was reused is never mistaken for the caller.  A traced
 * call cannot be abandoned.
 *
 * Written from the man pages only: seccomp_unotify(2), ptrace(2),
 * pidfd_getfd(2), process_vm_readv(2) (D-01).
 */
#include "svint.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/kcmp.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>

#include "addr.h"
#include "dgram.h"
#include "log.h"

#ifndef AF_PACKET
#define AF_PACKET 17
#endif
#ifndef SOCK_TYPE_MASK
#define SOCK_TYPE_MASK 0xf
#endif
#ifndef IOV_MAX
#define IOV_MAX 1024
#endif

/* The calls sendmmsg and recvmmsg take at most this many messages, as the
 * kernel caps them (UIO_MAXIOV). */
#define MMSG_MAX 1024

/* Control data read from a send, to look for UDP_SEGMENT; more than this is
 * not looked through. */
#define CONTROL_MAX 4096

/* --- the call being answered ----------------------------------------------*/

struct call {
	struct sv *sv;
	const struct seccomp_notif *req; /* for a traced call, made from its registers */
	pid_t tgid;  /* 0 until looked up */
	int pidfd;   /* -1 until looked up; the cache's, never closed here */
	bool own_pidfd;    /* pidfd is this call's, a thread's: closed after it */
	bool own_table;    /* a thread with a table of its own, unreachable */
	bool traced; /* stopped by ptrace (D-54), not notified */
	bool native; /* traced: to run in the kernel as made */
	long long ret;     /* traced: the result, or -errno */
	int wait_copy;     /* traced, SV_PARKED: the socket the thread waits on */
	uint64_t wait_cookie;
};

/* A traced call cannot have gone: its thread is stopped until it is
 * resumed. */
static bool still_pending(const struct call *c)
{
	return c->traced ||
	       ioctl(c->sv->listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &c->req->id) == 0;
}

static enum sv_outcome answer(struct call *c, long long val, int err)
{
	struct seccomp_notif_resp *resp = c->sv->resp;

	if (c->traced) {
		c->ret = err != 0 ? -(long long)err : val;
		return SV_ANSWER;
	}
	memset(resp, 0, c->sv->sizes.seccomp_notif_resp);
	resp->id = c->req->id;
	resp->val = err != 0 ? 0 : val;
	resp->error = err != 0 ? -err : 0;
	return SV_ANSWER;
}

static enum sv_outcome let_through(struct call *c)
{
	if (c->traced) {
		c->native = true;
		return SV_ANSWER;
	}
	answer(c, 0, 0);
	c->sv->resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
	return SV_ANSWER;
}

/* --- diagnostics ----------------------------------------------------------*/

/* D-33: once a second for each reason, so that one kind of refusal never hides
 * another: a refused raw socket does not silence a refused io_uring. */
enum {
	WHY_RAW, WHY_ICMP, WHY_URING, WHY_PIDFD, WHY_UNKNOWN_FD, WHY_RECEIVED_FD,
	WHY_DUP_OUT, WHY_NOT_INSPECTABLE, WHY_OWN_TABLE, WHY_NO_DNS, WHY_DNS_TCP, WHY_COUNT
};
static struct udpc_ratelimit g_rl_refuse[WHY_COUNT];

static const char *call_name(int nr)
{
	switch (nr) {
	case SYS_socket: return "socket";
	case SYS_connect: return "connect";
	case SYS_sendto: return "sendto";
	case SYS_sendmsg: return "sendmsg";
	case SYS_sendmmsg: return "sendmmsg";
	case SYS_sendfile: return "sendfile";
	case SYS_splice: return "splice";
	case SYS_io_uring_setup: return "io_uring_setup";
	case SYS_pidfd_getfd: return "pidfd_getfd";
	case SYS_read: return "read";
	case SYS_write: return "write";
	case SYS_readv: return "readv";
	case SYS_writev: return "writev";
	case SYS_recvfrom: return "recvfrom";
	case SYS_recvmsg: return "recvmsg";
	case SYS_recvmmsg: return "recvmmsg";
	case SYS_dup2: return "dup2";
	case SYS_dup3: return "dup3";
	default: return "a call";
	}
}

static void refused(const struct call *c, int reason, const char *why)
{
	char note[64];
	unsigned n = udpc_ratelimit(&g_rl_refuse[reason]);

	if (n == 0)
		return;
	udpc_err("process %u: %s refused: %s%s", c->req->pid, call_name(c->req->data.nr), why,
	         udpc_ratelimit_note(n, note, sizeof(note)));
}

/* D-48: the kernel refuses the supervisor ptrace-level access to a process
 * that has made itself non-dumpable (or under a stricter Yama setting).  Its
 * calls that need inspecting are refused, never let through unchecked, and
 * the diagnostic says why, so the cause is not mistaken for a fault. */
static void refused_uninspectable(const struct call *c)
{
	if (c->own_table) {
		refused(c, WHY_OWN_TABLE, "the thread has a descriptor table of its own "
		                          "(unshare(CLONE_FILES)), which this kernel lets the "
		                          "supervisor reach only from Linux 6.9, so the call is "
		                          "not let through unchecked");
		return;
	}
	refused(c, WHY_NOT_INSPECTABLE, "the process cannot be inspected: it has made "
	                                "itself non-dumpable, or ptrace access to it is "
	                                "restricted, so the call is not let through "
	                                "unchecked (D-48)");
}

/* --- the program's descriptors --------------------------------------------*/

bool sv_uncarriable(int fd)
{
	int domain = 0, type = 0;
	socklen_t len = sizeof(domain);

	if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &len) != 0)
		return false; /* not a socket */
	if (domain == AF_PACKET)
		return true;
	if (domain != AF_INET && domain != AF_INET6)
		return false;
	len = sizeof(type);
	if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len) != 0)
		return true; /* an inet socket it cannot classify: refuse */
	return type == SOCK_DGRAM || type == SOCK_RAW || type == SOCK_PACKET;
}

/* The thread group of a thread: a notification names the thread that made
 * the call, and pidfd_open() needs its process. */
static pid_t tgid_of(pid_t tid)
{
	char path[64], line[128];
	FILE *f;
	pid_t tgid = -1;

	snprintf(path, sizeof(path), "/proc/%d/status", (int)tid);
	f = fopen(path, "re");
	if (f == NULL)
		return -1;
	while (fgets(line, sizeof(line), f) != NULL)
		if (sscanf(line, "Tgid: %d", &tgid) == 1)
			break;
	fclose(f);
	return tgid;
}

/* Process descriptors, kept rather than opened for every call.  A cached one
 * is used only for its own process: a pidfd names one process for life, so if
 * that process has gone, pidfd_getfd() fails with ESRCH and the entry is
 * replaced -- it never reaches another process that reused the number. */
#define NPIDFD 32
static struct {
	pid_t tgid;
	int pidfd;
} g_pidfd[NPIDFD];
static unsigned g_pidfd_next;

static int cached_pidfd(pid_t tgid)
{
	unsigned k;

	for (k = 0; k < NPIDFD; k++)
		if (g_pidfd[k].tgid == tgid && g_pidfd[k].pidfd > 0)
			return g_pidfd[k].pidfd;
	return -1;
}

static void forget_pidfd(pid_t tgid)
{
	unsigned k;

	for (k = 0; k < NPIDFD; k++)
		if (g_pidfd[k].tgid == tgid && g_pidfd[k].pidfd > 0) {
			close(g_pidfd[k].pidfd);
			g_pidfd[k].pidfd = 0;
			g_pidfd[k].tgid = 0;
		}
}

#ifndef PIDFD_THREAD
#define PIDFD_THREAD O_EXCL /* Linux 6.9 */
#endif

/* Whether a thread's descriptor table is not its process's: 1 if it has one
 * of its own (unshare(CLONE_FILES)), 0 if they share one, -1 if it cannot be
 * told (kcmp(2), which needs CONFIG_KCMP). */
static int own_table(pid_t tgid, pid_t tid)
{
	long r = syscall(SYS_kcmp, tgid, tid, KCMP_FILES, 0, 0);

	return r < 0 ? -1 : r != 0;
}

/* A thread with its own descriptor table is reached through a pidfd for the
 * thread itself, which pidfd_getfd() reads that table through (Linux 6.9).
 * Returns it, or -1 with own_table set if the thread has its own table and
 * cannot be reached, or -1 alone if the answer is to use the process's. */
static int thread_pidfd(struct call *c, pid_t tid)
{
	int differs = own_table(c->tgid, tid), fd;

	if (differs == 0)
		return -1;
	fd = (int)syscall(SYS_pidfd_open, tid, PIDFD_THREAD);
	if (fd >= 0) {
		c->own_pidfd = true;
		return fd;
	}
	/* Without kcmp, every thread is taken to share its process's table,
	 * as before Linux 6.9 there is no other way to reach it. */
	c->own_table = differs == 1;
	return -1;
}

/* The calling thread's process, and a descriptor for it: for a thread with a
 * table of its own, a descriptor for the thread.  -1 if it has gone, or with
 * own_table set if its table cannot be reached. */
static int process_of(struct call *c)
{
	pid_t tid = (pid_t)c->req->pid;
	int fd;
	unsigned k;

	if (c->pidfd >= 0)
		return c->pidfd;
	if (c->own_table)
		return -1;
	/* Most calls come from a process's first thread, whose number is the
	 * process's. */
	fd = cached_pidfd(tid);
	if (fd >= 0) {
		c->tgid = tid;
		c->pidfd = fd;
		return fd;
	}
	c->tgid = tgid_of(tid);
	if (c->tgid <= 0)
		return -1;
	fd = thread_pidfd(c, tid);
	if (fd >= 0) {
		c->pidfd = fd;
		return fd;
	}
	if (c->own_table)
		return -1;
	fd = cached_pidfd(c->tgid);
	if (fd < 0) {
		fd = (int)syscall(SYS_pidfd_open, c->tgid, 0);
		if (fd < 0)
			return -1;
		fcntl(fd, F_SETFD, FD_CLOEXEC);
		k = g_pidfd_next++ % NPIDFD;
		if (g_pidfd[k].pidfd > 0)
			close(g_pidfd[k].pidfd);
		g_pidfd[k].tgid = c->tgid;
		g_pidfd[k].pidfd = fd;
	}
	c->pidfd = fd;
	return fd;
}

/* The supervisor's own descriptor for the program's descriptor fd: the same
 * open file.  Returns it, or -EBADF if fd is not open, -ENOENT if the call has
 * gone, or another -errno if it cannot be had. */
static int copy_of(struct call *c, int fd)
{
	int attempt, copy = -1;

	for (attempt = 0; attempt < 2; attempt++) {
		int pidfd = process_of(c);

		if (pidfd < 0 && c->own_table)
			return -EPERM;
		if (pidfd < 0)
			return still_pending(c) ? -ESRCH : -ENOENT;
		copy = (int)syscall(SYS_pidfd_getfd, pidfd, fd, 0);
		if (copy >= 0)
			break;
		if (errno != ESRCH || c->own_pidfd)
			return -errno;
		/* The cached process has gone; look again. */
		forget_pidfd(c->tgid);
		c->pidfd = -1;
	}
	if (copy < 0)
		return -ESRCH;
	/* seccomp_unotify(2): the thread may have gone, and its number been
	 * reused, between the notification and the copy.  Still pending means
	 * the copy is the caller's. */
	if (!still_pending(c)) {
		close(copy);
		return -ENOENT;
	}
	return copy;
}

static uint64_t cookie_of(int fd)
{
	uint64_t cookie = 0;
	socklen_t len = sizeof(cookie);

	if (getsockopt(fd, SOL_SOCKET, SO_COOKIE, &cookie, &len) != 0)
		return 0;
	return cookie;
}

/* The lowest free descriptor number at or above from in the caller's process,
 * below its RLIMIT_NOFILE.  The range is not shared with the program's own
 * lowest-free allocations unless it has the range's start of descriptors
 * open; D-50 records the narrow race that leaves.  Returns the number, or
 * -errno. */
static int free_number(struct call *c, unsigned from)
{
	struct rlimit rl;
	unsigned long n, limit = 1u << 20;
	int pidfd = process_of(c);

	if (pidfd < 0)
		return c->own_table ? -EPERM : -ESRCH;
	if (prlimit(c->tgid, RLIMIT_NOFILE, NULL, &rl) == 0 && rl.rlim_cur < limit)
		limit = (unsigned long)rl.rlim_cur;
	if (from < c->sv->range)
		from = c->sv->range;
	for (n = from; n < limit; n++) {
		int probe = (int)syscall(SYS_pidfd_getfd, pidfd, (int)n, 0);

		if (probe >= 0) {
			close(probe);
			continue;
		}
		if (errno == EBADF)
			return (int)n;
		return -errno;
	}
	return -EMFILE;
}

/* Installs the supervisor's src in the caller's process at number newfd, and
 * answers the call with that number, in one step (SECCOMP_ADDFD_FLAG_SEND, the
 * reason for the Linux 5.14 floor, D-53): a socket is never left in the
 * program by a call that was interrupted.  0, or -errno: -ENOENT if the call
 * has gone, in which case nothing was installed. */
static int install(struct call *c, int src, int newfd, bool cloexec)
{
	struct seccomp_notif_addfd a;

	memset(&a, 0, sizeof(a));
	a.id = c->req->id;
	a.flags = SECCOMP_ADDFD_FLAG_SETFD | SECCOMP_ADDFD_FLAG_SEND;
	a.srcfd = (unsigned)src;
	a.newfd = (unsigned)newfd;
	a.newfd_flags = cloexec ? O_CLOEXEC : 0;
	if (ioctl(c->sv->listener, SECCOMP_IOCTL_NOTIF_ADDFD, &a) < 0)
		return errno == ESRCH ? -ENOENT : -errno;
	return 0;
}

/* --- the program's memory -------------------------------------------------*/

static struct iovec g_riov[IOV_MAX];
static uint8_t g_hdr[UDPC_SOCKS_CHAIN_HDR_MAX];
static uint8_t g_control[CONTROL_MAX];

/* 0, or EFAULT if the whole of it cannot be read. */
static int mem_read(const struct call *c, uint64_t addr, void *buf, size_t len)
{
	struct iovec local = { buf, len }, remote = { (void *)(uintptr_t)addr, len };

	if (len == 0)
		return 0;
	if (addr == 0)
		return EFAULT;
	return process_vm_readv((pid_t)c->req->pid, &local, 1, &remote, 1, 0) ==
	               (ssize_t)len
	               ? 0
	               : EFAULT;
}

static int mem_write(const struct call *c, uint64_t addr, const void *buf, size_t len)
{
	struct iovec local = { (void *)(uintptr_t)buf, len },
		     remote = { (void *)(uintptr_t)addr, len };

	if (len == 0)
		return 0;
	if (addr == 0)
		return EFAULT;
	return process_vm_writev((pid_t)c->req->pid, &local, 1, &remote, 1, 0) ==
	               (ssize_t)len
	               ? 0
	               : EFAULT;
}

/* Reads the program's iovec array into g_riov.  Returns 0 and the total of its
 * lengths (saturating), or an errno: iovcnt is checked as the kernel checks
 * it, with toobig for one above IOV_MAX (EINVAL for readv and writev,
 * EMSGSIZE for sendmsg and recvmsg). */
static int read_iovecs(const struct call *c, uint64_t addr, unsigned long long iovcnt,
                       int toobig, size_t *total)
{
	unsigned long k;

	*total = 0;
	if (iovcnt > IOV_MAX)
		return toobig;
	if (mem_read(c, addr, g_riov, (size_t)iovcnt * sizeof(struct iovec)) != 0)
		return EFAULT;
	for (k = 0; k < iovcnt; k++) {
		if (g_riov[k].iov_len > SIZE_MAX - *total)
			*total = SIZE_MAX;
		else
			*total += g_riov[k].iov_len;
	}
	return 0;
}

/* A sockaddr from the program, as the kernel would take it: L1, checked
 * against its length, never read past it. */
static int read_sockaddr(const struct call *c, uint64_t addr, socklen_t len,
                         struct sockaddr_storage *out)
{
	struct sockaddr_storage raw;

	if ((size_t)len > sizeof(raw))
		return EINVAL;
	memset(&raw, 0, sizeof(raw));
	if (mem_read(c, addr, &raw, len) != 0)
		return EFAULT;
	if (udpc_sa_copy((const struct sockaddr *)&raw, len, out) != 0)
		return errno;
	return 0;
}

/* Writes an address to the program as the kernel does: as much as fits in its
 * buffer, and the full length to *lenaddr. */
static int write_sockaddr(const struct call *c, uint64_t addr, uint64_t lenaddr,
                          const struct sockaddr_storage *sa, socklen_t salen)
{
	socklen_t room;

	if (mem_read(c, lenaddr, &room, sizeof(room)) != 0)
		return EFAULT;
	if ((int)room < 0)
		return EINVAL;
	if (salen > 0 && room > 0 &&
	    mem_write(c, addr, sa, room < salen ? room : salen) != 0)
		return EFAULT;
	return mem_write(c, lenaddr, &salen, sizeof(salen));
}

/* --- sends ----------------------------------------------------------------*/

/* One datagram, its payload already in sv->buf, through s's association to
 * dst.  Returns 0, or an errno.  There is no path from here to a direct send
 * (SEC-01). */
static int send_via(struct call *c, struct sv_sock *s, int copy, int fd,
                    const struct sockaddr *dst, size_t paylen, int flags)
{
	const struct udpc_config *cfg = c->sv->cfg;
	struct sockaddr_storage relay;
	struct iovec iov[2];
	struct msghdr m;
	ssize_t hlen, n;
	size_t inner;
	int attempt;

	for (attempt = 0; attempt < 2; attempt++) {
		int err = svsock_hold(cfg, s, copy, true, c->tgid ? c->tgid : (pid_t)c->req->pid,
		                      fd);

		if (err != 0)
			return err;
		if (udpc_addr_for_family((const struct sockaddr *)&s->chain.relay[0].sa,
		                         s->family, &relay) != 0)
			return ENETUNREACH;
		hlen = udpc_socks_encode_chain(g_hdr, sizeof(g_hdr), &s->chain, dst, &inner);
		if (hlen < 0)
			return errno;

		iov[0].iov_base = g_hdr;
		iov[0].iov_len = (size_t)hlen;
		iov[1].iov_base = c->sv->buf;
		iov[1].iov_len = paylen;
		memset(&m, 0, sizeof(m));
		m.msg_name = &relay;
		m.msg_namelen = udpc_sa_len((const struct sockaddr *)&relay);
		m.msg_iov = iov;
		m.msg_iovlen = 2;

		/* Never blocking the supervisor: a full send buffer on a socket
		 * the program made blocking is waited for, briefly. */
		n = sendmsg(copy, &m, flags | MSG_DONTWAIT | MSG_NOSIGNAL);
		if (n < 0 && errno == EAGAIN && !(flags & MSG_DONTWAIT) &&
		    !(fcntl(copy, F_GETFL) & O_NONBLOCK)) {
			struct pollfd p = { copy, POLLOUT, 0 };

			if (poll(&p, 1, 1000) > 0)
				n = sendmsg(copy, &m, flags | MSG_DONTWAIT | MSG_NOSIGNAL);
		}
		if (n < 0) {
			err = errno;
			/* FR-P-08: the proxy expired the association.  Once,
			 * transparently, as in shim mode. */
			if (udpc_dgram_assoc_dead(err) && attempt == 0) {
				udpc_debug("process %u fd %d: association appears expired "
				           "(%s); re-associating",
				           c->req->pid, fd, strerror(err));
				svsock_drop_assoc(s);
				continue;
			}
			return err;
		}
		if (udpc_log_level() >= UDPC_DEBUG) {
			char dbuf[UDPC_ADDRSTRLEN], rbuf[UDPC_ADDRSTRLEN];

			/* Addresses, lengths and the ATYP byte only; never
			 * payload (NFR-05). */
			udpc_debug("process %u fd %d: sent %zu payload bytes to %s (ATYP "
			           "0x%02x) via relay %s, %zd bytes on the wire",
			           c->req->pid, fd, paylen, udpc_addr_str(dst, dbuf, sizeof(dbuf)),
			           g_hdr[inner + 3],
			           udpc_addr_str((const struct sockaddr *)&relay, rbuf,
			                         sizeof(rbuf)),
			           n);
		}
		/* FR-F-01: the program's length, and a short write is an
		 * error, never reported as a success. */
		if ((size_t)n != (size_t)hlen + paylen)
			return EIO;
		svsock_used(s);
		return 0;
	}
	return ENETUNREACH;
}

/* One message: g_riov holds iovcnt of the program's iovecs, totalling total.
 * name and control are its address and ancillary data, if any.  Returns 0
 * with the payload length in *sent, or an errno. */
static int send_one(struct call *c, struct sv_sock *s, int copy, int fd,
                    unsigned long iovcnt, size_t total, uint64_t name,
                    socklen_t namelen, uint64_t control, size_t controllen, int flags,
                    size_t *sent)
{
	struct sockaddr_storage dst;
	int err;

	/* D-36: MSG_MORE would join this send to the next, each with its own
	 * header. */
	if (flags & MSG_MORE)
		return udpc_dgram_refuse_cork();
	if (controllen > 0) {
		struct msghdr m;

		/* D-36: GSO is refused; other ancillary data on send is
		 * ignored, as in shim mode (FR-F-11). */
		if (controllen > sizeof(g_control))
			controllen = sizeof(g_control);
		if (mem_read(c, control, g_control, controllen) != 0)
			return EFAULT;
		memset(&m, 0, sizeof(m));
		m.msg_control = g_control;
		m.msg_controllen = controllen;
		if (udpc_dgram_wants_gso(fd, &m))
			return EOPNOTSUPP;
	}

	/* The destination: the one given, else the connected one (FR-F-08). */
	if (name != 0 && namelen > 0) {
		err = read_sockaddr(c, name, namelen, &dst);
		if (err != 0)
			return err;
	} else if (s->connected) {
		dst = s->app_dst;
	} else {
		return EDESTADDRREQ;
	}
	if (udpc_sa_len((const struct sockaddr *)&dst) == 0)
		return EAFNOSUPPORT;
	err = udpc_dgram_unrepresentable((const struct sockaddr *)&dst);
	if (err != 0)
		return err;

	/* D-52: a query to the system resolver goes to dns instead, through
	 * the proxy; its reply is reported as from the address asked.  With no
	 * dns, it fails, as lookups do in shim mode (D-22). */
	if (svdns_system_resolver((const struct sockaddr *)&dst)) {
		if (!c->sv->cfg->dns_set) {
			refused(c, WHY_NO_DNS, "a query to the system resolver, with no dns "
			                       "configured; set dns, or UDPCHAINS_DNS (D-52)");
			return ENETUNREACH;
		}
		s->dns_asked = dst;
		s->dns_redirected = true;
		dst = c->sv->cfg->dns;
	}

	/* FR-F-07 / D-12: the limit is configured; above it is EMSGSIZE, never
	 * a silent drop. */
	if (total > c->sv->cfg->max_datagram)
		return EMSGSIZE;
	if (total > 0 &&
	    process_vm_readv((pid_t)c->req->pid,
	                     &(struct iovec){ c->sv->buf, total }, 1, g_riov, iovcnt,
	                     0) != (ssize_t)total)
		return EFAULT;
	if (!still_pending(c))
		return ENOENT;

	err = send_via(c, s, copy, fd, (const struct sockaddr *)&dst, total, flags);
	if (err == 0)
		*sent = total;
	return err;
}

static enum sv_outcome do_send(struct call *c, struct sv_sock *s, int copy, int fd)
{
	const __u64 *a = c->req->data.args;
	size_t total = 0, sent = 0;
	int err = 0;

	switch (c->req->data.nr) {
	case SYS_sendto:
	case SYS_write:
		g_riov[0].iov_base = (void *)(uintptr_t)a[1];
		g_riov[0].iov_len = (size_t)a[2];
		err = send_one(c, s, copy, fd, 1, (size_t)a[2],
		               c->req->data.nr == SYS_sendto ? a[4] : 0,
		               c->req->data.nr == SYS_sendto ? (socklen_t)a[5] : 0, 0, 0,
		               c->req->data.nr == SYS_sendto ? (int)a[3] : 0, &sent);
		break;
	case SYS_writev:
	case SYS_pwritev2:
		if ((int)a[2] < 0)
			err = EINVAL;
		else
			err = read_iovecs(c, a[1], (unsigned)(int)a[2], EINVAL, &total);
		if (err == 0)
			err = send_one(c, s, copy, fd, (unsigned)(int)a[2], total, 0, 0, 0, 0, 0,
			               &sent);
		break;
	case SYS_sendmsg: {
		struct msghdr m;

		if (mem_read(c, a[1], &m, sizeof(m)) != 0)
			err = EFAULT;
		else
			err = read_iovecs(c, (uint64_t)(uintptr_t)m.msg_iov, m.msg_iovlen,
			                  EMSGSIZE, &total);
		if (err == 0) {
			if (m.msg_controllen > 0)
				udpc_debug("process %u fd %d: ignoring %zu bytes of "
				           "ancillary data on send",
				           c->req->pid, fd, (size_t)m.msg_controllen);
			err = send_one(c, s, copy, fd, (unsigned long)m.msg_iovlen, total,
			               (uint64_t)(uintptr_t)m.msg_name, m.msg_namelen,
			               (uint64_t)(uintptr_t)m.msg_control,
			               m.msg_controllen, (int)a[2], &sent);
		}
		break;
	}
	case SYS_sendmmsg: {
		/* FR-F-09: each message on its own; a failure after k have gone
		 * returns k, and only a failure of the first is an error. */
		unsigned vlen = (unsigned)a[2], i;

		if (vlen > MMSG_MAX)
			vlen = MMSG_MAX;
		for (i = 0; i < vlen; i++) {
			uint64_t at = a[1] + (uint64_t)i * sizeof(struct mmsghdr);
			struct msghdr m;
			unsigned len;

			if (mem_read(c, at, &m, sizeof(m)) != 0)
				err = EFAULT;
			else
				err = read_iovecs(c, (uint64_t)(uintptr_t)m.msg_iov,
				                  m.msg_iovlen, EMSGSIZE, &total);
			if (err == 0)
				err = send_one(c, s, copy, fd, (unsigned long)m.msg_iovlen,
				               total, (uint64_t)(uintptr_t)m.msg_name,
				               m.msg_namelen, (uint64_t)(uintptr_t)m.msg_control,
				               m.msg_controllen, (int)a[3], &sent);
			if (err == 0) {
				len = (unsigned)sent;
				err = mem_write(c, at + offsetof(struct mmsghdr, msg_len), &len,
				                sizeof(len));
			}
			if (err != 0)
				break;
		}
		close(copy);
		if (err == ENOENT)
			return SV_ANSWERED;
		return i > 0 ? answer(c, i, 0) : answer(c, 0, err);
	}
	}
	close(copy);
	if (err == ENOENT)
		return SV_ANSWERED; /* gone */
	return err != 0 ? answer(c, 0, err) : answer(c, (long long)sent, 0);
}

/* --- receives (D-54) ------------------------------------------------------*/

/* Where a receive puts what it returns. */
struct recv_dest {
	unsigned long iovcnt;  /* in g_riov */
	size_t capacity;
	int flags;
	uint64_t name, namelen;   /* the source and its length's address, or 0 */
	uint64_t msghdr;          /* recvmsg's and recvmmsg's, or 0 */
	uint64_t msg_len;         /* recvmmsg's msg_len, or 0 */
};

/* Decodes a receive's arguments: for recvmmsg, those of its message i.  0, or
 * an errno for the call. */
static int recv_dest_of(const struct call *c, unsigned i, struct recv_dest *d)
{
	const __u64 *a = c->req->data.args;
	struct msghdr m;
	int err;

	memset(d, 0, sizeof(*d));
	switch (c->req->data.nr) {
	case SYS_recvfrom:
		g_riov[0].iov_base = (void *)(uintptr_t)a[1];
		g_riov[0].iov_len = (size_t)a[2];
		d->iovcnt = 1;
		d->capacity = (size_t)a[2];
		d->flags = (int)a[3];
		/* As in shim mode: a source with no length to say how much
		 * room it has is not written. */
		if (a[4] != 0 && a[5] != 0) {
			d->name = a[4];
			d->namelen = a[5];
		}
		return 0;
	case SYS_read:
		g_riov[0].iov_base = (void *)(uintptr_t)a[1];
		g_riov[0].iov_len = (size_t)a[2];
		d->iovcnt = 1;
		d->capacity = (size_t)a[2];
		return 0;
	case SYS_readv:
	case SYS_preadv2:
		if ((int)a[2] < 0)
			return EINVAL;
		d->iovcnt = (unsigned)(int)a[2];
		return read_iovecs(c, a[1], d->iovcnt, EINVAL, &d->capacity);
	case SYS_recvmsg:
	case SYS_recvmmsg:
		if (c->req->data.nr == SYS_recvmmsg) {
			if ((unsigned)a[2] == 0)
				return EINVAL;
			d->msghdr = a[1] + (uint64_t)i * sizeof(struct mmsghdr);
			d->msg_len = d->msghdr + offsetof(struct mmsghdr, msg_len);
		} else {
			d->msghdr = a[1];
		}
		d->flags = (int)a[c->req->data.nr == SYS_recvmsg ? 2 : 3];
		if (mem_read(c, d->msghdr, &m, sizeof(m)) != 0)
			return EFAULT;
		err = read_iovecs(c, (uint64_t)(uintptr_t)m.msg_iov, m.msg_iovlen, EMSGSIZE,
		                  &d->capacity);
		if (err != 0)
			return err;
		d->iovcnt = (unsigned long)m.msg_iovlen;
		if (m.msg_name != NULL) {
			d->name = (uint64_t)(uintptr_t)m.msg_name;
			d->namelen = d->msghdr + offsetof(struct msghdr, msg_namelen);
		}
		return 0;
	}
	return EINVAL;
}

/* The peer a connected socket accepts datagrams from (NULL if it is not
 * connected): the one it connected to, or for the system resolver, dns, where
 * its queries went (D-52). */
static const struct sockaddr_storage *peer_of(const struct sv *sv, const struct sv_sock *s)
{
	if (!s->connected)
		return NULL;
	if (sv->cfg->dns_set && svdns_system_resolver((const struct sockaddr *)&s->app_dst))
		return &sv->cfg->dns;
	return &s->app_dst;
}

/* Delivers the datagram at sv->buf + hlen into the program.  0, or an
 * errno. */
static int deliver(struct call *c, struct sv_sock *s, const struct recv_dest *d,
                   const struct udpc_socks_hdr *hdr, ssize_t hlen, size_t paylen,
                   size_t *copied)
{
	struct sockaddr_storage src;
	socklen_t srclen;

	*copied = paylen < d->capacity ? paylen : d->capacity;
	if (*copied > 0 &&
	    process_vm_writev((pid_t)c->req->pid,
	                      &(struct iovec){ c->sv->buf + hlen, *copied }, 1, g_riov,
	                      d->iovcnt, 0) != (ssize_t)*copied)
		return EFAULT;
	/* FR-F-02: the true origin, never the relay. */
	if (d->name != 0) {
		srclen = udpc_dgram_source(hdr, s->family, peer_of(c->sv, s), &src);
		/* D-52: dns answers for the system resolver it stood in for. */
		if (srclen > 0 && s->dns_redirected &&
		    svdns_same((const struct sockaddr *)&src,
		               (const struct sockaddr *)&c->sv->cfg->dns) &&
		    udpc_addr_for_family((const struct sockaddr *)&s->dns_asked, s->family,
		                         &src) == 0)
			srclen = udpc_sa_len((const struct sockaddr *)&src);
		if (write_sockaddr(c, d->name, d->namelen, &src, srclen) != 0)
			return EFAULT;
	}
	if (d->msghdr != 0) {
		/* FR-F-11: no ancillary data, rather than the relay's; FR-F-04:
		 * truncation reported as the kernel reports it. */
		size_t controllen = 0;
		int msgflags = paylen > d->capacity ? MSG_TRUNC : 0;

		if (mem_write(c, d->msghdr + offsetof(struct msghdr, msg_controllen),
		              &controllen, sizeof(controllen)) != 0 ||
		    mem_write(c, d->msghdr + offsetof(struct msghdr, msg_flags), &msgflags,
		              sizeof(msgflags)) != 0)
			return EFAULT;
	}
	if (d->msg_len != 0) {
		unsigned len = (unsigned)((d->flags & MSG_TRUNC) ? paylen : *copied);

		if (mem_write(c, d->msg_len, &len, sizeof(len)) != 0)
			return EFAULT;
	}
	return 0;
}

static void consume(struct sv *sv, int copy)
{
	(void)recv(copy, sv->buf, sv->buflen, MSG_DONTWAIT | MSG_TRUNC);
}

/* Takes the next datagram queued on s, without waiting, and delivers it into
 * the program as d says.  Returns what the call returns for it -- the length
 * copied, or with MSG_TRUNC the datagram's -- or -errno: -EAGAIN with nothing
 * queued.  The thread is stopped (D-54), so a datagram taken here is the
 * program's: no signal can come between taking it and the call returning
 * it. */
static long long take(struct call *c, struct sv_sock *s, int copy, int fd,
                      const struct recv_dest *d)
{
	struct udpc_socks_hdr hdr;
	bool reassociated = false;
	int err;

	for (;;) {
		ssize_t n, hlen;
		size_t paylen, copied;

		n = recv(copy, c->sv->buf, c->sv->buflen, MSG_PEEK | MSG_TRUNC | MSG_DONTWAIT);
		if (n < 0) {
			err = errno == EWOULDBLOCK ? EAGAIN : errno;
			if (err == EAGAIN)
				return -EAGAIN;
			/* FR-P-08: an expired association shows up as a
			 * pending ICMP error. */
			if (udpc_dgram_assoc_dead(err) && !reassociated) {
				reassociated = true;
				svsock_drop_assoc(s);
				err = svsock_hold(c->sv->cfg, s, copy, false,
				                  c->tgid ? c->tgid : (pid_t)c->req->pid, fd);
				if (err == 0)
					continue;
			}
			return -(long long)err;
		}
		hlen = udpc_dgram_unwrap(c->sv->buf, n, c->sv->buflen, c->sv->cfg, &s->chain,
		                         s->family, peer_of(c->sv, s), &hdr);
		if (hlen < 0) {
			/* Never delivered; consumed at once, as in shim mode. */
			consume(c->sv, copy);
			continue;
		}
		paylen = (size_t)n - (size_t)hlen;
		err = deliver(c, s, d, &hdr, hlen, paylen, &copied);
		/* A buffer that cannot be written loses the datagram, as it
		 * does on a native socket, which takes it before copying. */
		if (!(d->flags & MSG_PEEK))
			consume(c->sv, copy);
		if (err != 0)
			return -(long long)err;
		svsock_used(s);
		return (d->flags & MSG_TRUNC) ? (long long)paylen : (long long)copied;
	}
}

/* A receive's datagrams, without waiting: one, or for recvmmsg as many as are
 * queued, up to its vlen (D-54).  Returns the call's result, or -errno. */
static long long recv_all(struct call *c, struct sv_sock *s, int copy, int fd)
{
	unsigned vlen = 1, i;
	long long r = 0;

	if (c->req->data.nr == SYS_recvmmsg) {
		vlen = (unsigned)c->req->data.args[2];
		if (vlen > MMSG_MAX)
			vlen = MMSG_MAX;
	}
	for (i = 0; i < vlen; i++) {
		struct recv_dest d;
		int err = recv_dest_of(c, i, &d);

		r = err != 0 ? -(long long)err : take(c, s, copy, fd, &d);
		if (r < 0)
			break;
	}
	if (c->req->data.nr != SYS_recvmmsg)
		return r;
	/* As sendmmsg (FR-F-09): what came before a failure is returned, and
	 * only a failure of the first is an error. */
	return i > 0 ? (long long)i : r;
}

/* Performs a receive on s, or finds nothing queued for a call that may wait
 * (SV_PARKED): the thread then waits in its own kernel (D-54). */
static enum sv_outcome do_recv(struct call *c, struct sv_sock *s, int copy, int fd)
{
	struct recv_dest d;
	bool nonblocking;
	long long r;
	int err;

	err = recv_dest_of(c, 0, &d);
	if (err != 0)
		return answer(c, 0, err);
	/* Nothing ever arrives on the error queue of a proxied socket: the
	 * relay's errors are not the program's. */
	if (d.flags & MSG_ERRQUEUE)
		return answer(c, 0, EAGAIN);
	nonblocking = (d.flags & MSG_DONTWAIT) || (fcntl(copy, F_GETFL) & O_NONBLOCK);

	/* A receive is a use of the socket, so it sets up the association if
	 * there is not one yet (FR-P-01). */
	err = svsock_hold(c->sv->cfg, s, copy, false, c->tgid ? c->tgid : (pid_t)c->req->pid,
	                  fd);
	if (err != 0)
		return answer(c, 0, err);
	r = recv_all(c, s, copy, fd);
	if (r == -EAGAIN && !nonblocking)
		return SV_PARKED;
	return r < 0 ? answer(c, 0, (int)-r) : answer(c, r, 0);
}

/* --- the rest of a carried socket's calls ---------------------------------*/

static enum sv_outcome do_connect(struct call *c, struct sv_sock *s, int copy, int fd)
{
	const __u64 *a = c->req->data.args;
	struct sockaddr_storage dst;
	sa_family_t family = AF_UNSPEC;
	int err;

	if ((socklen_t)a[2] >= sizeof(family) && mem_read(c, a[1], &family, sizeof(family)) != 0)
		err = EFAULT;
	else if ((socklen_t)a[2] >= sizeof(family) && family == AF_UNSPEC)
		err = -1;
	else
		err = read_sockaddr(c, a[1], (socklen_t)a[2], &dst);
	if (!still_pending(c)) {
		close(copy);
		return SV_ANSWERED;
	}
	if (err > 0) {
		close(copy);
		return answer(c, 0, err);
	}
	if (err < 0) {
		/* FR-F-08: connect(AF_UNSPEC) dissolves the destination. */
		s->connected = false;
		memset(&s->app_dst, 0, sizeof(s->app_dst));
		close(copy);
		return answer(c, 0, 0);
	}
	/* FR-F-08: the destination the program named; the socket itself stays
	 * pointed at the relay.  A second connect() re-targets. */
	s->app_dst = dst;
	s->connected = true;
	/* Set up now if possible.  A failure is reported on the first send,
	 * not here (FR-L-06), as in shim mode. */
	err = svsock_hold(c->sv->cfg, s, copy, false, c->tgid ? c->tgid : (pid_t)c->req->pid,
	                  fd);
	if (err != 0)
		udpc_debug("process %u fd %d: connect deferred association setup (%s)",
		           c->req->pid, fd, strerror(err));
	close(copy);
	return answer(c, 0, 0);
}

static enum sv_outcome do_bind(struct call *c, struct sv_sock *s, int copy)
{
	const __u64 *a = c->req->data.args;
	struct sockaddr_storage addr;
	int err = read_sockaddr(c, a[1], (socklen_t)a[2], &addr);

	if (!still_pending(c)) {
		close(copy);
		return SV_ANSWERED;
	}
	/* Performed here, on the same socket, so the address checked is the
	 * address bound. */
	if (err == 0 && bind(copy, (const struct sockaddr *)&addr,
	                     udpc_sa_len((const struct sockaddr *)&addr)) != 0)
		err = errno;
	if (err == 0) {
		const struct sockaddr *sa = (const struct sockaddr *)&addr;
		bool concrete = sa->sa_family == AF_INET
		                        ? ((const struct sockaddr_in *)sa)->sin_addr.s_addr !=
		                                  INADDR_ANY
		                        : !IN6_IS_ADDR_UNSPECIFIED(
		                                  &((const struct sockaddr_in6 *)sa)->sin6_addr);

		/* FR-P-05: a concrete address is declared to the proxy. */
		s->bound = addr;
		s->bound_set = concrete;
	}
	close(copy);
	return answer(c, 0, err);
}

/* FR-I-05: what the program believes, never the relay. */
static enum sv_outcome do_name(struct call *c, struct sv_sock *s, int copy)
{
	const __u64 *a = c->req->data.args;
	struct sockaddr_storage sa;
	socklen_t len = sizeof(sa);
	int err = 0;

	memset(&sa, 0, sizeof(sa));
	if (c->req->data.nr == SYS_getpeername) {
		if (s->connected) {
			sa = s->app_dst;
			len = udpc_sa_len((const struct sockaddr *)&sa);
		} else {
			err = ENOTCONN;
		}
	} else if (s->bound_set) {
		struct sockaddr_storage real;
		socklen_t rl = sizeof(real);

		/* A concrete address bound with port 0 has the port the
		 * kernel chose. */
		sa = s->bound;
		len = udpc_sa_len((const struct sockaddr *)&sa);
		if (udpc_sa_port((const struct sockaddr *)&sa) == 0 &&
		    getsockname(copy, (struct sockaddr *)&real, &rl) == 0)
			udpc_sa_set_port((struct sockaddr *)&sa,
			                 udpc_sa_port((const struct sockaddr *)&real));
	} else if (getsockname(copy, (struct sockaddr *)&sa, &len) != 0) {
		/* Otherwise the socket's own address is the honest answer: it
		 * is the program's socket, not the relay's. */
		err = errno;
	}
	close(copy);
	if (err == 0 && (a[1] == 0 || a[2] == 0))
		err = EFAULT;
	if (err == 0) {
		if (!still_pending(c))
			return SV_ANSWERED;
		err = write_sockaddr(c, a[1], a[2], &sa, len);
	}
	return answer(c, 0, err);
}

/* dup, and fcntl's F_DUPFD and F_DUPFD_CLOEXEC: the duplicate is placed in the
 * range too (FR-SV-04). */
static enum sv_outcome do_dup(struct call *c, int copy, unsigned from, bool cloexec)
{
	int n, rc;

	if (c->traced) {
		close(copy);
		return SV_TO_INSTALL; /* by notification, as socket() */
	}
	n = free_number(c, from);
	if (n < 0) {
		close(copy);
		return answer(c, 0, -n);
	}
	rc = install(c, copy, n, cloexec);
	close(copy);
	if (rc == -ENOENT)
		return SV_ANSWERED;
	if (rc < 0)
		return answer(c, 0, rc == -EBADF ? EMFILE : -rc);
	return SV_ANSWERED;
}

static enum sv_outcome on_carried(struct call *c, struct sv_sock *s, int copy, int fd)
{
	const __u64 *a = c->req->data.args;

	switch (c->req->data.nr) {
	case SYS_sendto:
	case SYS_sendmsg:
	case SYS_sendmmsg:
	case SYS_write:
	case SYS_writev:
		return do_send(c, s, copy, fd);
	case SYS_pwritev2:
		/* At an offset, the kernel refuses it on a socket itself. */
		if ((int64_t)a[3] != -1)
			break;
		return do_send(c, s, copy, fd);
	case SYS_preadv2:
		if ((int64_t)a[3] != -1)
			break;
		/* fall through */
	case SYS_recvfrom:
	case SYS_recvmsg:
	case SYS_recvmmsg:
	case SYS_read:
	case SYS_readv: {
		enum sv_outcome o = do_recv(c, s, copy, fd);

		if (o == SV_PARKED) {
			/* Kept for when the wait ends: the descriptor the
			 * program waits on may be closed or replaced by
			 * then. */
			c->wait_copy = copy;
			c->wait_cookie = s->cookie;
			return o;
		}
		close(copy);
		return o;
	}
	case SYS_connect:
		return do_connect(c, s, copy, fd);
	case SYS_bind:
		return do_bind(c, s, copy);
	case SYS_getsockname:
	case SYS_getpeername:
		return do_name(c, s, copy);
	case SYS_dup:
		return do_dup(c, copy, c->sv->range, false);
	case SYS_fcntl:
		if ((int)a[1] == F_DUPFD || (int)a[1] == F_DUPFD_CLOEXEC) {
			if ((int)a[2] < 0) {
				close(copy);
				return answer(c, 0, EINVAL);
			}
			return do_dup(c, copy, (unsigned)a[2], (int)a[1] == F_DUPFD_CLOEXEC);
		}
		close(copy);
		return let_through(c);
	case SYS_sendfile:
	case SYS_splice:
		/* D-36, D-50: the kernel would move bytes without a header. */
		close(copy);
		return answer(c, 0, EINVAL);
	}
	close(copy);
	return let_through(c);
}

/* --- deciding -------------------------------------------------------------*/

static enum sv_outcome decide_socket(struct call *c)
{
	const __u64 *a = c->req->data.args;
	int domain = (int)a[0], type = (int)a[1], proto = (int)a[2];
	int kind = type & SOCK_TYPE_MASK, s, n, rc;
	struct sv_sock *e;
	uint64_t cookie;
	struct stat st;

	/* Arguments are values, not pointers, so a check here cannot be raced. */
	if (domain == AF_PACKET || kind == SOCK_RAW || kind == SOCK_PACKET) {
		refused(c, WHY_RAW, "raw and packet sockets cannot be carried by SOCKS5 (D-36)");
		return answer(c, 0, EPERM);
	}
	if (kind == SOCK_DGRAM && (proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6 ||
	                           proto == IPPROTO_UDPLITE)) {
		refused(c, WHY_ICMP, "ICMP and UDP-Lite sockets cannot be carried by SOCKS5 "
		                     "(D-29)");
		return answer(c, 0, EPROTONOSUPPORT);
	}
	if (kind != SOCK_DGRAM)
		return let_through(c); /* TCP and the rest: not carried */
	/* Installed by notification, the call made again marked (D-54). */
	if (c->traced)
		return SV_TO_INSTALL;

	/* D-50: a UDP socket is made here, and placed in the program at a
	 * number in the reserved range, where every call on it comes to the
	 * supervisor. */
	s = socket(domain, SOCK_DGRAM | (type & SOCK_NONBLOCK) | SOCK_CLOEXEC, proto);
	if (s < 0)
		return answer(c, 0, errno);
	cookie = cookie_of(s);
	if (cookie == 0 || fstat(s, &st) != 0) {
		close(s);
		return answer(c, 0, ENOMEM);
	}
	n = free_number(c, c->sv->range);
	if (n < 0) {
		close(s);
		if (n == -EPERM)
			refused_uninspectable(c);
		return n == -ENOENT ? SV_ANSWERED : answer(c, 0, -n);
	}
	e = svsock_add(cookie, (unsigned long)st.st_ino, domain);
	if (e == NULL) {
		close(s);
		return answer(c, 0, ENOMEM);
	}
	rc = install(c, s, n, (type & SOCK_CLOEXEC) != 0);
	close(s);
	if (rc < 0) {
		svsock_remove(e);
		if (rc == -ENOENT)
			return SV_ANSWERED;
		return answer(c, 0, rc == -EBADF ? EMFILE : -rc);
	}
	udpc_debug("process %u: made a %s UDP socket at fd %d", c->req->pid,
	           domain == AF_INET6 ? "AF_INET6" : "AF_INET", n);
	return SV_ANSWERED;
}

/* dup2 and dup3 name the new number themselves. */
static enum sv_outcome decide_dup2(struct call *c)
{
	int oldfd = (int)c->req->data.args[0];
	unsigned newfd = (unsigned)c->req->data.args[1];
	int copy;

	if (newfd >= c->sv->range) {
		/* Into the range: whatever lands there is checked when used,
		 * and a carried socket it replaces is noticed by the sweep. */
		sv_sweep_soon(c->sv);
		return let_through(c);
	}
	if ((unsigned)oldfd < c->sv->range)
		return let_through(c); /* the filter sends only a range number */
	copy = copy_of(c, oldfd);
	if (copy == -ENOENT)
		return SV_ANSWERED;
	if (copy == -EBADF)
		return let_through(c); /* not open: the kernel says so */
	if (copy < 0) {
		/* Cannot tell whether a carried socket would leave the range. */
		if (copy == -EPERM)
			refused_uninspectable(c);
		else
			refused(c, WHY_UNKNOWN_FD, "cannot tell what the descriptor is, so "
			                           "cannot let it through");
		return answer(c, 0, EPERM);
	}
	if (svsock_find(cookie_of(copy)) != NULL) {
		close(copy);
		refused(c, WHY_DUP_OUT, "a carried UDP socket duplicated below the reserved "
		                        "range would escape the supervisor (D-50)");
		return answer(c, 0, EPERM);
	}
	close(copy);
	return let_through(c);
}

/* A call on a descriptor that is not a socket the supervisor carries: through
 * to the kernel, unless it is a UDP, raw or packet socket it did not make
 * (D-50) and the call would send, connect or move data on it. */
/* D-52: whether a call connects a stream socket to the system resolver's port
 * 53, by connect(), or by a sendto() or sendmsg() naming it (TCP Fast Open). */
static bool stream_to_system_resolver(struct call *c, int copy)
{
	const __u64 *a = c->req->data.args;
	struct sockaddr_storage dst;
	uint64_t name;
	socklen_t namelen, len;
	int type = 0, domain = 0;

	len = sizeof(type);
	if (getsockopt(copy, SOL_SOCKET, SO_TYPE, &type, &len) != 0 || type != SOCK_STREAM)
		return false;
	len = sizeof(domain);
	if (getsockopt(copy, SOL_SOCKET, SO_DOMAIN, &domain, &len) != 0 ||
	    (domain != AF_INET && domain != AF_INET6))
		return false;
	switch (c->req->data.nr) {
	case SYS_connect:
		name = a[1];
		namelen = (socklen_t)a[2];
		break;
	case SYS_sendto:
		name = a[4];
		namelen = (socklen_t)a[5];
		break;
	case SYS_sendmsg: {
		struct msghdr m;

		if (mem_read(c, a[1], &m, sizeof(m)) != 0)
			return false;
		name = (uint64_t)(uintptr_t)m.msg_name;
		namelen = m.msg_namelen;
		break;
	}
	default:
		return false;
	}
	if (name == 0 || namelen == 0 || read_sockaddr(c, name, namelen, &dst) != 0)
		return false;
	return svdns_system_resolver((const struct sockaddr *)&dst);
}

/* TCP Fast Open's data, after its connection has been made: sent on the
 * program's socket as the call would have sent it.  Returns the count sent, or
 * -errno. */
static long long fastopen_data(struct call *c, int copy)
{
	const __u64 *a = c->req->data.args;
	unsigned long iovcnt = 1;
	size_t total;
	ssize_t n;
	int flags, err;

	if (c->req->data.nr == SYS_sendto) {
		g_riov[0].iov_base = (void *)(uintptr_t)a[1];
		g_riov[0].iov_len = (size_t)a[2];
		total = (size_t)a[2];
		flags = (int)a[3];
	} else {
		struct msghdr m;

		if (mem_read(c, a[1], &m, sizeof(m)) != 0)
			return -EFAULT;
		err = read_iovecs(c, (uint64_t)(uintptr_t)m.msg_iov, m.msg_iovlen, EMSGSIZE,
		                  &total);
		if (err != 0)
			return -err;
		iovcnt = (unsigned long)m.msg_iovlen;
		flags = (int)a[2];
	}
	/* A stream may send less than asked; the program sends the rest. */
	if (total > c->sv->buflen)
		total = c->sv->buflen;
	if (total > 0 &&
	    process_vm_readv((pid_t)c->req->pid, &(struct iovec){ c->sv->buf, total }, 1,
	                     g_riov, iovcnt, 0) != (ssize_t)total)
		return -EFAULT;
	n = send(copy, c->sv->buf, total,
	         (flags & ~MSG_FASTOPEN) | MSG_DONTWAIT | MSG_NOSIGNAL);
	return n < 0 ? -(long long)errno : (long long)n;
}

/* D-52: a TCP connection to the system resolver's port 53 is made to dns
 * instead, by SOCKS5 CONNECT through the proxy, on the program's own socket.
 * The program then reads and writes it natively, its epoll registrations and
 * options as they were.  connect() returns 0 once the tunnel is up, even on a
 * non-blocking socket; a send with MSG_FASTOPEN connects so, then sends its
 * data.  A failure leaves the socket unconnected, as a failed connect does,
 * and a signal abandons the setup, the call made again once it is handled. */
static enum sv_outcome dns_over_tcp(struct call *c, int copy)
{
	const struct udpc_config *cfg = c->sv->cfg;
	const __u64 *a = c->req->data.args;
	int nr = c->req->data.nr, proto = 0, flags, err;
	struct tcp_info ti;
	socklen_t len;
	long long sent = 0;

	len = sizeof(proto);
	memset(&ti, 0, sizeof(ti));
	if (getsockopt(copy, SOL_SOCKET, SO_PROTOCOL, &proto, &len) != 0 ||
	    proto != IPPROTO_TCP ||
	    getsockopt(copy, IPPROTO_TCP, TCP_INFO, &ti, &(socklen_t){ sizeof(ti) }) != 0) {
		close(copy);
		refused(c, WHY_DNS_TCP, "a stream connection other than TCP to the system "
		                        "resolver's port 53, which would send queries "
		                        "around the proxy (D-52)");
		return answer(c, 0, ECONNREFUSED);
	}

	/* Only a socket not connected yet connects.  On any other the kernel
	 * fails the connect, or sends on the connection the socket has; and a
	 * send without MSG_FASTOPEN never connects. */
	flags = nr == SYS_sendto ? (int)a[3] : nr == SYS_sendmsg ? (int)a[2] : 0;
	if (ti.tcpi_state != TCP_CLOSE || (nr != SYS_connect && !(flags & MSG_FASTOPEN))) {
		close(copy);
		return let_through(c);
	}
	if (!cfg->dns_set) {
		close(copy);
		refused(c, WHY_NO_DNS, "a TCP query to the system resolver, with no dns "
		                       "configured; set dns, or UDPCHAINS_DNS (D-52)");
		return answer(c, 0, ENETUNREACH);
	}

	udpc_debug("process %u fd %d: a TCP query to the system resolver, carried to dns "
	           "by CONNECT through the proxy",
	           c->req->pid, (int)a[0]);
	if (udpc_socks_connect_on(cfg, copy, (const struct sockaddr *)&cfg->dns, &err) != 0) {
		struct sockaddr unspec = { .sa_family = AF_UNSPEC };

		/* connect(2): AF_UNSPEC dissolves the association, so the socket
		 * can connect again. */
		(void)connect(copy, &unspec, sizeof(unspec));
		close(copy);
		if (err != EINTR) {
			char why[160];

			snprintf(why, sizeof(why), "a TCP query to the system resolver, which "
			                           "could not be carried to dns: %s (D-52)",
			         strerror(err));
			refused(c, WHY_DNS_TCP, why);
		}
		return answer(c, 0, err);
	}
	if (nr != SYS_connect)
		sent = fastopen_data(c, copy);
	close(copy);
	return sent < 0 ? answer(c, 0, (int)-sent) : answer(c, sent, 0);
}

static enum sv_outcome decide_other(struct call *c, int copy)
{
	int nr = c->req->data.nr;
	bool moves_data = nr != SYS_close && nr != SYS_bind && nr != SYS_getsockname &&
	                  nr != SYS_getpeername && nr != SYS_dup && nr != SYS_fcntl;

	/* D-52: the local resolver would send the queries upstream itself,
	 * around the proxy; the connection goes to dns instead. */
	if ((nr == SYS_connect || nr == SYS_sendto || nr == SYS_sendmsg) &&
	    stream_to_system_resolver(c, copy))
		return dns_over_tcp(c, copy);
	if (moves_data && sv_uncarriable(copy)) {
		close(copy);
		refused(c, WHY_RECEIVED_FD, "a UDP, raw or packet socket the supervisor did "
		                            "not make, received from another process (D-50)");
		return answer(c, 0, (nr == SYS_sendfile || nr == SYS_splice) ? EINVAL : EPERM);
	}
	close(copy);
	return let_through(c);
}

/* One call, notified or traced. */
static enum sv_outcome decide(struct call *c)
{
	struct sv *sv = c->sv;
	const __u64 *a = c->req->data.args;
	int nr = c->req->data.nr, fd, copy;
	struct sv_sock *s;

	switch (nr) {
	case SYS_socket:
		return decide_socket(c);
	case SYS_io_uring_setup:
		refused(c, WHY_URING, "io_uring would send around the supervisor (D-53)");
		return answer(c, 0, ENOSYS);
	case SYS_pidfd_getfd:
		refused(c, WHY_PIDFD, "a descriptor copied from another process would escape "
		                      "the supervisor (D-53)");
		return answer(c, 0, EPERM);
	case SYS_close:
	case SYS_close_range:
		/* The kernel closes; the sweep notices what went.  A traced
		 * close runs only once its thread is resumed, so a signal can
		 * no longer leave the descriptor open (D-54). */
		sv_sweep_soon(sv);
		return let_through(c);
	case SYS_dup2:
	case SYS_dup3:
		return decide_dup2(c);
	case SYS_splice:
		/* Either end on a carried socket moves bytes without a header;
		 * the destination is checked as a send's is. */
		if ((unsigned)a[0] >= sv->range) {
			copy = copy_of(c, (int)a[0]);
			if (copy == -ENOENT)
				return SV_ANSWERED;
			if (copy >= 0) {
				s = svsock_find(cookie_of(copy));
				close(copy);
				if (s != NULL)
					return answer(c, 0, EINVAL);
			}
		}
		fd = (int)a[2];
		break;
	case SYS_fcntl:
		/* The filter sends only F_DUPFD and F_DUPFD_CLOEXEC; below the
		 * range none duplicates a carried socket. */
		if ((unsigned)a[0] < sv->range)
			return let_through(c);
		fd = (int)a[0];
		break;
	default:
		fd = (int)a[0];
		break;
	}

	copy = copy_of(c, fd);
	if (copy == -ENOENT)
		return SV_ANSWERED; /* gone: nothing to answer */
	if (copy == -EBADF)
		return let_through(c); /* not open: the kernel will say so */
	if (copy < 0) {
		/* Cannot tell what the descriptor is: refused, since a call
		 * that might send is never let through unchecked. */
		if (nr == SYS_close || nr == SYS_getsockname || nr == SYS_getpeername)
			return let_through(c);
		if (copy == -EPERM)
			refused_uninspectable(c);
		else
			refused(c, WHY_UNKNOWN_FD, "cannot tell what the descriptor is, so "
			                           "cannot let it through");
		return answer(c, 0, (nr == SYS_sendfile || nr == SYS_splice) ? EINVAL : EPERM);
	}
	s = svsock_find(cookie_of(copy));
	if (s != NULL)
		return on_carried(c, s, copy, fd);
	return decide_other(c, copy);
}

/* After a call: a thread's own pidfd is not cached. */
static void done(struct call *c)
{
	if (c->own_pidfd)
		close(c->pidfd);
}

enum sv_outcome svcall_decide(struct sv *sv)
{
	struct call c = { sv, sv->req, 0, -1, false, false, false, false, 0, -1, 0 };
	enum sv_outcome o = decide(&c);

	done(&c);
	if (o == SV_PARKED) {
		/* The filter traces every receive in the range (D-54), so none
		 * can wait here; were one to, it would be told to try again
		 * rather than held. */
		close(c.wait_copy);
		return answer(&c, 0, EAGAIN);
	}
	return o;
}

/* A call context for a traced call, its notification made from the stopped
 * thread's registers. */
static void traced_call(struct sv *sv, const struct sv_traced *t, struct seccomp_notif *req,
                        struct call *c)
{
	memset(req, 0, sizeof(*req));
	req->pid = (__u32)t->tid;
	req->data.nr = t->nr;
	memcpy(req->data.args, t->args, sizeof(req->data.args));
	*c = (struct call){ sv, req, 0, -1, false, false, true, false, -ENOSYS, -1, 0 };
}

void svcall_traced(struct sv *sv, struct sv_traced *t)
{
	struct seccomp_notif req;
	struct call c;
	enum sv_outcome o;

	traced_call(sv, t, &req, &c);
	o = decide(&c);
	done(&c);
	t->copy = -1;
	if (o == SV_PARKED) {
		t->verdict = SV_WAIT;
		t->copy = c.wait_copy;
		t->cookie = c.wait_cookie;
	} else if (o == SV_TO_INSTALL) {
		t->verdict = SV_INSTALL;
	} else if (c.native) {
		t->verdict = SV_NATIVE;
	} else {
		t->verdict = SV_RETURN;
		t->ret = c.ret;
	}
}

void svcall_waited(struct sv *sv, struct sv_traced *t, long long peeked)
{
	struct seccomp_notif req;
	struct sv_sock *s;
	struct call c;
	long long r;
	int fd = (int)t->args[0];

	traced_call(sv, t, &req, &c);
	s = svsock_find(t->cookie);
	t->verdict = SV_RETURN;
	if (s == NULL) {
		/* Forgotten while it waited: no supervised process holds it. */
		t->ret = -EBADF;
		return;
	}
	if (peeked < 0) {
		int err;

		/* FR-P-08: the peek found the expired association's ICMP
		 * error.  Set up again, and the call made again. */
		if (!udpc_dgram_assoc_dead((int)-peeked)) {
			/* EAGAIN at SO_RCVTIMEO, EINTR, or a restart the
			 * kernel makes of the program's own call. */
			t->ret = peeked;
			return;
		}
		svsock_drop_assoc(s);
		err = svsock_hold(sv->cfg, s, t->copy, false, (pid_t)t->tid, fd);
		if (err == 0)
			t->verdict = SV_AGAIN;
		else
			t->ret = -(long long)err;
		return;
	}
	r = recv_all(&c, s, t->copy, fd);
	done(&c);
	if (r == -EAGAIN)
		t->verdict = SV_AGAIN; /* another reader took it: wait again */
	else
		t->ret = r;
}

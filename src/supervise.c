/* supervise.c -- supervisor mode: the filter, the notification loop, and the
 * program's exit status and signals (D-48 to D-53, step 2 of
 * docs/FUTURE-STATIC-BINARIES.md §7).
 *
 * The wrapper forks.  The child sets no_new_privs, installs a seccomp filter
 * with a user-notification listener, and execs the program.  The parent takes a
 * copy of the listener and becomes the supervisor: the kernel stops the
 * program at each call the filter selects, and the supervisor answers it --
 * lets it continue, or fails it with an errno and a diagnostic.
 *
 * Not yet: carrying UDP.  Until step 3 does, a UDP socket is refused when the
 * program asks for one, so supervisor mode fails closed at every step of its
 * construction: nothing the filter selects is let through unchecked.
 *
 * Written from the man pages only: seccomp(2), seccomp_unotify(2),
 * pidfd_open(2), pidfd_getfd(2) (D-01).
 */
#include "supervise.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include "log.h"

/* D-53: SECCOMP_ADDFD_FLAG_SEND, which step 3 needs to install a socket and
 * answer the call in one step. */
#define FLOOR_MAJOR 5
#define FLOOR_MINOR 14

#ifndef AF_PACKET
#define AF_PACKET 17
#endif
#ifndef SOCK_TYPE_MASK
#define SOCK_TYPE_MASK 0xf
#endif

bool udpc_kernel_at_least(const char *release, int major, int minor)
{
	char *end;
	long maj, min;

	errno = 0;
	maj = strtol(release, &end, 10);
	if (errno != 0 || end == release || *end != '.')
		return false;
	release = end + 1;
	min = strtol(release, &end, 10);
	if (errno != 0 || end == release)
		return false;
	return maj > major || (maj == major && min >= minor);
}

/* --- the filter (D-48, D-50, D-53) -----------------------------------------
 *
 * One ABI: x86-64, without x32's call numbers (seccomp(2): x32 shares x86-64's
 * arch value, and is told apart by __X32_SYSCALL_BIT).  A call from any other
 * ABI fails with ENOSYS, never runs.  Then the calls the supervisor answers:
 * socket() for the families it must see, and on every descriptor the calls
 * that could send on, or connect, a socket it did not make. */

#if defined(__x86_64__)
#define FILTER_ARCH AUDIT_ARCH_X86_64
#define X32_BIT 0x40000000u
#else
#define FILTER_ARCH 0
#define X32_BIT 0u
#endif

/* Calls sent to the supervisor whatever their arguments. */
static const int g_notified[] = {
	SYS_connect, SYS_sendto, SYS_sendmsg, SYS_sendmmsg, SYS_sendfile,
	SYS_splice, SYS_io_uring_setup, SYS_pidfd_getfd,
};

/* socket() families sent to the supervisor; any other family runs. */
static const unsigned g_families[] = { AF_INET, AF_INET6, AF_PACKET };

#define NNOTIFIED (sizeof(g_notified) / sizeof(g_notified[0]))
#define NFAMILIES (sizeof(g_families) / sizeof(g_families[0]))
/* arch check (3), call number and x32 check (3), socket (1), the list, allow
 * (1), the socket() family block (1 + families + 1), notify (1). */
#define FILTER_LEN (3 + 3 + 1 + NNOTIFIED + 1 + 1 + NFAMILIES + 1 + 1)

/* Builds the filter.  BPF jumps only forward, so the one "notify" return is
 * last, and every match jumps to it. */
static void build_filter(struct sock_filter *f)
{
	const unsigned notify = FILTER_LEN - 1;
	const unsigned sockblk = 7 + NNOTIFIED + 1;
	unsigned i = 0, k;

	f[i++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
	                                      offsetof(struct seccomp_data, arch));
	f[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, FILTER_ARCH, 1, 0);
	f[i++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS);
	f[i++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
	                                      offsetof(struct seccomp_data, nr));
	f[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, X32_BIT, 0, 1);
	f[i++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS);
	/* i == 6 */
	f[i] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_socket,
	                                    (unsigned char)(sockblk - i - 1), 0);
	i++;
	for (k = 0; k < NNOTIFIED; k++, i++)
		f[i] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
		                                    (unsigned)g_notified[k],
		                                    (unsigned char)(notify - i - 1), 0);
	f[i++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
	/* i == sockblk: socket()'s family, the low word of its first argument
	 * on a little-endian machine. */
	f[i++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
	                                      offsetof(struct seccomp_data, args[0]));
	for (k = 0; k < NFAMILIES; k++, i++)
		f[i] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, g_families[k],
		                                    (unsigned char)(notify - i - 1), 0);
	f[i++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
	f[i] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF);
}

/* --- descriptors -----------------------------------------------------------*/

/* A socket the supervisor cannot carry: UDP, which it will carry only when it
 * made the socket itself (D-50), and raw and packet sockets (D-36), which it
 * never carries.  ICMP and UDP-Lite datagram sockets are refused when made
 * (D-29), so any other inet datagram socket is UDP. */
static bool uncarriable(int fd)
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

/* D-50: the program must not start holding a socket the supervisor cannot
 * carry.  It could not be moved into the reserved range without changing the
 * number the program expects, so the run is refused.  A close-on-exec
 * descriptor is not inherited, and is skipped. */
static int refuse_inherited(void)
{
	DIR *d = opendir("/proc/self/fd");
	struct dirent *e;
	int bad = -1;

	if (d == NULL) {
		udpc_err("cannot list this process's descriptors (%s), so cannot "
		         "check what the program would inherit; refusing to run it "
		         "(FR-SV-02)",
		         strerror(errno));
		return -1;
	}
	while ((e = readdir(d)) != NULL) {
		char *end;
		long fd = strtol(e->d_name, &end, 10);
		int fl;

		if (*end != '\0' || end == e->d_name || fd == dirfd(d))
			continue;
		fl = fcntl((int)fd, F_GETFD);
		if (fl < 0 || (fl & FD_CLOEXEC))
			continue;
		if (uncarriable((int)fd)) {
			bad = (int)fd;
			break;
		}
	}
	closedir(d);
	if (bad < 0)
		return 0;
	udpc_err("descriptor %d is a UDP, raw or packet socket the program would "
	         "inherit; supervisor mode cannot carry it, so refuses to run the "
	         "program (D-50).  Close it before running udpchains",
	         bad);
	return -1;
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

/* --- answering a call ------------------------------------------------------*/

struct sv {
	int listener;
	int sigfd;
	pid_t child;      /* the program */
	int child_status; /* once it has exited */
	bool child_done;
	struct seccomp_notif *req;
	struct seccomp_notif_resp *resp;
	struct seccomp_notif_sizes sizes;
};

/* D-33: once a second for each reason, so that one kind of refusal never
 * hides another: a refused UDP socket does not silence a refused raw one. */
enum {
	WHY_UDP, WHY_RAW, WHY_ICMP, WHY_URING, WHY_PIDFD, WHY_UNKNOWN_FD,
	WHY_RECEIVED_FD, WHY_COUNT
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
	default: return "a call";
	}
}

static void refused(const struct seccomp_notif *req, int reason, const char *why)
{
	char note[64];
	unsigned n = udpc_ratelimit(&g_rl_refuse[reason]);

	if (n == 0)
		return;
	udpc_err("process %u: %s refused: %s%s", req->pid, call_name(req->data.nr), why,
	         udpc_ratelimit_note(n, note, sizeof(note)));
}

/* Whether the program's descriptor fd is a socket the supervisor cannot
 * carry.  Returns 1 if it is, 0 if not (or if fd is not open, which the
 * kernel will report itself), and -1 if it cannot be told. */
static int program_fd_uncarriable(struct sv *sv, int fd)
{
	pid_t tgid = tgid_of((pid_t)sv->req->pid);
	int pidfd, copy, rc;

	if (tgid <= 0)
		return -1;
	pidfd = (int)syscall(SYS_pidfd_open, tgid, 0);
	if (pidfd < 0)
		return -1;
	/* seccomp_unotify(2): the thread named in the notification may have
	 * gone, and its number been reused, between the notification and the
	 * pidfd.  Still valid here means the pidfd is the program's. */
	if (ioctl(sv->listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &sv->req->id) != 0) {
		close(pidfd);
		return 0; /* gone: nothing to answer */
	}
	copy = (int)syscall(SYS_pidfd_getfd, pidfd, fd, 0);
	close(pidfd);
	if (copy < 0)
		return errno == EBADF ? 0 : -1;
	rc = uncarriable(copy) ? 1 : 0;
	close(copy);
	return rc;
}

/* Decides one notification: fills in sv->resp. */
static void decide(struct sv *sv)
{
	const struct seccomp_notif *req = sv->req;
	struct seccomp_notif_resp *resp = sv->resp;
	int nr = req->data.nr, fd = -1, rc;

	resp->id = req->id;
	resp->val = 0;
	resp->error = 0;
	resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;

	switch (nr) {
	case SYS_socket: {
		/* Arguments are values, not pointers, so continuing after the
		 * check cannot be raced. */
		int domain = (int)req->data.args[0];
		int type = (int)req->data.args[1] & SOCK_TYPE_MASK;
		int proto = (int)req->data.args[2];

		if (domain == AF_PACKET || type == SOCK_RAW || type == SOCK_PACKET) {
			refused(req, WHY_RAW, "raw and packet sockets cannot be carried by "
			             "SOCKS5 (D-36)");
			resp->error = -EPERM;
		} else if (type == SOCK_DGRAM &&
		           (proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6 ||
		            proto == IPPROTO_UDPLITE)) {
			refused(req, WHY_ICMP, "ICMP and UDP-Lite sockets cannot be carried by "
			             "SOCKS5 (D-29)");
			resp->error = -EPROTONOSUPPORT;
		} else if (type == SOCK_DGRAM) {
			refused(req, WHY_UDP, "supervisor mode does not carry UDP yet, so the "
			             "socket is not made, rather than send directly");
			resp->error = -EPROTONOSUPPORT;
		}
		break;
	}
	case SYS_io_uring_setup:
		refused(req, WHY_URING, "io_uring would send around the supervisor (D-53)");
		resp->error = -ENOSYS;
		break;
	case SYS_pidfd_getfd:
		refused(req, WHY_PIDFD, "a descriptor copied from another process would "
		             "escape the supervisor (D-53)");
		resp->error = -EPERM;
		break;
	case SYS_splice:
		fd = (int)req->data.args[2];
		/* fall through */
	default:
		if (fd < 0)
			fd = (int)req->data.args[0]; /* connect, send*, sendfile */
		rc = program_fd_uncarriable(sv, fd);
		if (rc == 0)
			break;
		if (rc < 0)
			refused(req, WHY_UNKNOWN_FD, "cannot tell what the descriptor is, so "
			             "cannot let it through");
		else
			refused(req, WHY_RECEIVED_FD, "a UDP, raw or packet socket the supervisor "
			             "did not make, received from another process "
			             "(D-50)");
		resp->error = (nr == SYS_sendfile || nr == SYS_splice) ? -EINVAL : -EPERM;
		break;
	}
	if (resp->error != 0)
		resp->flags = 0;
}

static void serve_one(struct sv *sv)
{
	memset(sv->req, 0, sv->sizes.seccomp_notif);
	if (ioctl(sv->listener, SECCOMP_IOCTL_NOTIF_RECV, sv->req) != 0)
		return; /* EINTR or ENOENT: the call has gone */
	memset(sv->resp, 0, sv->sizes.seccomp_notif_resp);
	decide(sv);
	/* ENOENT: interrupted by a signal, or the program has gone. */
	(void)ioctl(sv->listener, SECCOMP_IOCTL_NOTIF_SEND, sv->resp);
}

/* --- signals and exit ------------------------------------------------------*/

/* Signals the supervisor forwards to the program when another process sends
 * them to it.  The terminal sends its own (^C, ^\, a resize) to the whole
 * foreground group, which includes the program, so those are not sent twice:
 * they arrive with si_code SI_KERNEL, while kill(), sigqueue() and tgkill()
 * give SI_USER, SI_QUEUE and SI_TKILL, all at or below zero. */
static const int g_forwarded[] = {
	SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1, SIGUSR2, SIGALRM, SIGWINCH,
};

static void reap(struct sv *sv, bool *none_left)
{
	int st;
	pid_t p;

	while ((p = waitpid(-1, &st, WNOHANG)) > 0) {
		if (p == sv->child) {
			sv->child_status = st;
			sv->child_done = true;
		}
	}
	if (p < 0 && errno == ECHILD)
		*none_left = true;
}

static void on_signal(struct sv *sv, bool *none_left)
{
	struct signalfd_siginfo si;

	while (read(sv->sigfd, &si, sizeof(si)) == (ssize_t)sizeof(si)) {
		if (si.ssi_signo == SIGCHLD) {
			reap(sv, none_left);
			continue;
		}
		if (si.ssi_code <= 0 && !sv->child_done)
			kill(sv->child, (int)si.ssi_signo);
	}
}

/* The program's status, as the wrapper's own.  Killed by a signal, the
 * supervisor dies of the same one, so whatever ran udpchains sees what it
 * would have seen running the program -- without a core of the supervisor. */
static int pass_on_status(int st)
{
	if (WIFEXITED(st))
		return WEXITSTATUS(st);
	if (WIFSIGNALED(st)) {
		int sig = WTERMSIG(st);
		struct rlimit none = { 0, 0 };
		sigset_t set;

		setrlimit(RLIMIT_CORE, &none);
		signal(sig, SIG_DFL);
		sigemptyset(&set);
		sigaddset(&set, sig);
		sigprocmask(SIG_UNBLOCK, &set, NULL);
		raise(sig);
		return 128 + sig;
	}
	return 1;
}

/* --- start-up --------------------------------------------------------------*/

/* What the child tells the parent over a pipe: its listener, or why it could
 * not run the program. */
struct child_msg {
	int kind; /* MSG_* */
	int value;
};
enum { MSG_LISTENER = 1, MSG_FILTER_FAILED, MSG_EXEC_FAILED };

static void tell(int fd, int kind, int value)
{
	struct child_msg m = { kind, value };
	ssize_t n;

	do
		n = write(fd, &m, sizeof(m));
	while (n < 0 && errno == EINTR);
}

static int hear(int fd, struct child_msg *m)
{
	ssize_t n;

	do
		n = read(fd, m, sizeof(*m));
	while (n < 0 && errno == EINTR);
	return n == (ssize_t)sizeof(*m) ? 1 : 0;
}

/* In the child: the filter, then the program.  Never returns. */
static void run_child(const char *program, char **argv, const sigset_t *orig,
                      int up, int down)
{
	struct sock_filter filter[FILTER_LEN];
	struct sock_fprog prog = { FILTER_LEN, filter };
	int listener;
	char ack;

	sigprocmask(SIG_SETMASK, orig, NULL);
	build_filter(filter);
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
		tell(up, MSG_FILTER_FAILED, errno);
		_exit(1);
	}
	listener = (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
	                        SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
	if (listener < 0) {
		tell(up, MSG_FILTER_FAILED, errno);
		_exit(1);
	}
	/* The parent takes its copy; the program must never hold one, or it
	 * could answer its own calls.  The listener is close-on-exec as well. */
	tell(up, MSG_LISTENER, listener);
	if (read(down, &ack, 1) != 1)
		_exit(1);
	close(listener);
	close(down);

	execv(program, argv);
	if (errno == ENOEXEC) {
		/* As the shim's path does: a file with no #! line is run by sh. */
		int n = 0, k;
		char **shargv;

		while (argv[n] != NULL)
			n++;
		shargv = calloc((size_t)n + 2, sizeof(*shargv));
		if (shargv != NULL) {
			shargv[0] = (char *)(uintptr_t)"sh";
			shargv[1] = (char *)(uintptr_t)program;
			for (k = 1; k < n; k++)
				shargv[k + 1] = argv[k];
			execv("/bin/sh", shargv);
		}
	}
	tell(up, MSG_EXEC_FAILED, errno);
	_exit(127);
}

int udpc_supervise(const char *program, char **argv)
{
	struct sv sv;
	struct utsname u;
	sigset_t fwd, orig;
	int up[2], down[2];
	struct child_msg m = { 0, 0 };
	size_t k;
	bool none_left = false;

	memset(&sv, 0, sizeof(sv));

	if (FILTER_ARCH == 0) {
		udpc_err("supervisor mode supports x86-64 only so far; refusing to "
		         "run the program (FR-SV-02)");
		return 1;
	}
	if (uname(&u) != 0 ||
	    !udpc_kernel_at_least(u.release, FLOOR_MAJOR, FLOOR_MINOR)) {
		udpc_err("supervisor mode needs Linux %d.%d or later (this is %s); "
		         "refusing to run the program (D-53)",
		         FLOOR_MAJOR, FLOOR_MINOR, uname(&u) == 0 ? u.release : "unknown");
		return 1;
	}
	if (refuse_inherited() != 0)
		return 1;
	if (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sv.sizes) != 0) {
		udpc_err("seccomp user notification is not available (%s); refusing "
		         "to run the program (FR-SV-02)",
		         strerror(errno));
		return 1;
	}

	/* Blocked before the fork, so none is lost in between; the child
	 * restores the mask before it runs the program. */
	sigemptyset(&fwd);
	for (k = 0; k < sizeof(g_forwarded) / sizeof(g_forwarded[0]); k++)
		sigaddset(&fwd, g_forwarded[k]);
	sigaddset(&fwd, SIGCHLD);
	sigprocmask(SIG_BLOCK, &fwd, &orig);
	sv.sigfd = signalfd(-1, &fwd, SFD_CLOEXEC | SFD_NONBLOCK);

	/* FR-SV-11: a descendant orphaned by the program becomes the
	 * supervisor's child, so it is waited for and its calls still
	 * answered. */
	if (sv.sigfd < 0 || prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0 ||
	    pipe2(up, O_CLOEXEC) != 0 || pipe2(down, O_CLOEXEC) != 0) {
		udpc_err("cannot set up the supervisor: %s", strerror(errno));
		return 1;
	}

	sv.child = fork();
	if (sv.child < 0) {
		udpc_err("cannot fork: %s", strerror(errno));
		return 1;
	}
	if (sv.child == 0) {
		close(up[0]);
		close(down[1]);
		run_child(program, argv, &orig, up[1], down[0]);
	}
	close(up[1]);
	close(down[0]);

	if (!hear(up[0], &m) || m.kind != MSG_LISTENER) {
		int err = m.kind == MSG_FILTER_FAILED ? m.value : 0;

		waitpid(sv.child, NULL, 0);
		udpc_err("cannot install the seccomp filter%s%s; refusing to run the "
		         "program (FR-SV-02).  A container's own seccomp profile "
		         "can forbid it",
		         err ? ": " : "", err ? strerror(err) : "");
		return 1;
	}
	{
		int pidfd = (int)syscall(SYS_pidfd_open, sv.child, 0);

		sv.listener = pidfd < 0 ? -1
		                        : (int)syscall(SYS_pidfd_getfd, pidfd, m.value, 0);
		if (sv.listener < 0) {
			int err = errno;

			kill(sv.child, SIGKILL);
			waitpid(sv.child, NULL, 0);
			udpc_err("cannot take the program's listener: %s; refusing to "
			         "run it (FR-SV-02).  A Yama ptrace_scope above 1 "
			         "forbids a parent this access",
			         strerror(err));
			return 1;
		}
		if (pidfd >= 0)
			close(pidfd);
		fcntl(sv.listener, F_SETFD, FD_CLOEXEC);
	}
	if (write(down[1], "", 1) != 1) {
		kill(sv.child, SIGKILL);
		waitpid(sv.child, NULL, 0);
		return 1;
	}
	close(down[1]);
	if (hear(up[0], &m) && m.kind == MSG_EXEC_FAILED) {
		waitpid(sv.child, NULL, 0);
		udpc_err("cannot exec %s: %s", argv[0], strerror(m.value));
		return m.value == ENOENT ? 127 : 126;
	}
	close(up[0]);

	sv.req = calloc(1, sv.sizes.seccomp_notif);
	sv.resp = calloc(1, sv.sizes.seccomp_notif_resp);
	if (sv.req == NULL || sv.resp == NULL) {
		kill(sv.child, SIGKILL);
		waitpid(sv.child, NULL, 0);
		udpc_err("out of memory");
		return 1;
	}
	udpc_debug("supervising %s as process %d", program, (int)sv.child);

	/* Until no supervised process is left: the listener reports end of file
	 * once the last one has gone and been reaped (seccomp_unotify(2)), and
	 * waitpid() reports no children once every descendant has been. */
	while (!none_left) {
		struct pollfd p[2] = {
			{ sv.listener, POLLIN, 0 },
			{ sv.sigfd, POLLIN, 0 },
		};

		if (poll(p, 2, -1) < 0) {
			if (errno == EINTR)
				continue;
			udpc_err("poll: %s", strerror(errno));
			break;
		}
		if (p[1].revents & POLLIN)
			on_signal(&sv, &none_left);
		if (p[0].revents & POLLIN)
			serve_one(&sv);
		if (p[0].revents & (POLLHUP | POLLERR))
			break;
	}
	free(sv.req);
	free(sv.resp);
	close(sv.listener);
	if (!sv.child_done) {
		waitpid(sv.child, &sv.child_status, 0);
		sv.child_done = true;
	}
	return pass_on_status(sv.child_status);
}

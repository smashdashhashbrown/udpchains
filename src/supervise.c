/* supervise.c -- supervisor mode: the filter, start-up, the notification
 * loop, and the program's exit status and signals (D-48 to D-53).
 *
 * The wrapper forks.  The child sets no_new_privs, installs a seccomp filter
 * with a user-notification listener, and execs the program.  The parent takes a
 * copy of the listener and becomes the supervisor: the kernel stops the
 * program at each call the filter selects, and svcall.c answers it -- performs
 * it, lets it continue, or fails it with an errno and a diagnostic.
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
#include <time.h>
#include <unistd.h>

#include "dgram.h"
#include "log.h"
#include "svint.h"

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
 *
 *   - socket() for the families it must see;
 *   - on every descriptor, the calls that could send on, or connect, a socket
 *     it did not make, and the routes around it (D-50, D-53);
 *   - on a descriptor in the reserved range, where every UDP socket lives,
 *     the calls that move data or change what the number refers to.  Below
 *     the range, file and TCP I/O never leaves the kernel (D-50);
 *   - dup2 and dup3 to or from the range, close_range reaching it, and fcntl
 *     on it or duplicating anything.
 */

#if defined(__x86_64__)
#define FILTER_ARCH AUDIT_ARCH_X86_64
#define X32_BIT 0x40000000u
#else
#define FILTER_ARCH 0
#define X32_BIT 0u
#endif

/* Sent to the supervisor whatever their arguments. */
static const int g_always[] = {
	SYS_connect, SYS_sendto, SYS_sendmsg, SYS_sendmmsg, SYS_sendfile,
	SYS_splice, SYS_io_uring_setup, SYS_pidfd_getfd,
};

/* Sent to the supervisor when their first argument, a descriptor, is in the
 * range.  pread64, pwrite64, preadv and pwritev are not: the kernel refuses
 * them on a socket itself. */
static const int g_in_range[] = {
	SYS_read, SYS_write, SYS_readv, SYS_writev, SYS_preadv2, SYS_pwritev2,
	SYS_recvfrom, SYS_recvmsg, SYS_recvmmsg, SYS_bind, SYS_getsockname,
	SYS_getpeername, SYS_close, SYS_dup,
};

/* socket() families sent to the supervisor; any other family runs. */
static const unsigned g_families[] = { AF_INET, AF_INET6, AF_PACKET };

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))
#define FILTER_MAX 96

enum { L_NOTIFY, L_SOCKET, L_FD0, L_DUP, L_CLOSE_RANGE, L_FCNTL, L_COUNT };

/* A small assembler: BPF jumps only forward, by at most 255, so every jump
 * names a label placed later, and is resolved once all are placed. */
struct bpf {
	struct sock_filter f[FILTER_MAX];
	unsigned n;
	unsigned label[L_COUNT];
	unsigned fix_at[FILTER_MAX];
	int fix_to[FILTER_MAX];
	unsigned nfix;
};

static void stmt(struct bpf *b, unsigned short code, unsigned k)
{
	b->f[b->n++] = (struct sock_filter)BPF_STMT(code, k);
}

static void load_word(struct bpf *b, unsigned off)
{
	stmt(b, BPF_LD | BPF_W | BPF_ABS, off);
}

/* If the accumulator compares (op) with k, jump to label; else fall through. */
static void jump_if(struct bpf *b, unsigned short op, unsigned k, int label)
{
	b->fix_at[b->nfix] = b->n;
	b->fix_to[b->nfix++] = label;
	b->f[b->n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | op | BPF_K, k, 0, 0);
}

static void place(struct bpf *b, int label)
{
	b->label[label] = b->n;
}

/* The low word of a call's argument k: a descriptor, an int, on a
 * little-endian machine. */
#define ARG(k) (unsigned)offsetof(struct seccomp_data, args[k])

/* Builds the filter for a range starting at range.  Returns its length. */
static unsigned build_filter(struct bpf *b, unsigned range)
{
	const unsigned allow = SECCOMP_RET_ALLOW;
	unsigned k;

	memset(b, 0, sizeof(*b));
	load_word(b, offsetof(struct seccomp_data, arch));
	b->f[b->n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, FILTER_ARCH, 1, 0);
	stmt(b, BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS);
	load_word(b, offsetof(struct seccomp_data, nr));
	b->f[b->n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, X32_BIT, 0, 1);
	stmt(b, BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS);

	jump_if(b, BPF_JEQ, SYS_socket, L_SOCKET);
	for (k = 0; k < COUNT(g_always); k++)
		jump_if(b, BPF_JEQ, (unsigned)g_always[k], L_NOTIFY);
	for (k = 0; k < COUNT(g_in_range); k++)
		jump_if(b, BPF_JEQ, (unsigned)g_in_range[k], L_FD0);
	jump_if(b, BPF_JEQ, SYS_dup2, L_DUP);
	jump_if(b, BPF_JEQ, SYS_dup3, L_DUP);
	jump_if(b, BPF_JEQ, SYS_close_range, L_CLOSE_RANGE);
	jump_if(b, BPF_JEQ, SYS_fcntl, L_FCNTL);
	stmt(b, BPF_RET | BPF_K, allow);

	place(b, L_SOCKET);
	load_word(b, ARG(0));
	for (k = 0; k < COUNT(g_families); k++)
		jump_if(b, BPF_JEQ, g_families[k], L_NOTIFY);
	stmt(b, BPF_RET | BPF_K, allow);

	/* Unsigned: a negative descriptor compares above the range, and is
	 * answered with the kernel's own EBADF. */
	place(b, L_FD0);
	load_word(b, ARG(0));
	jump_if(b, BPF_JGE, range, L_NOTIFY);
	stmt(b, BPF_RET | BPF_K, allow);

	place(b, L_DUP);
	load_word(b, ARG(0));
	jump_if(b, BPF_JGE, range, L_NOTIFY);
	load_word(b, ARG(1));
	jump_if(b, BPF_JGE, range, L_NOTIFY);
	stmt(b, BPF_RET | BPF_K, allow);

	place(b, L_CLOSE_RANGE);
	load_word(b, ARG(1)); /* the last descriptor it closes */
	jump_if(b, BPF_JGE, range, L_NOTIFY);
	stmt(b, BPF_RET | BPF_K, allow);

	place(b, L_FCNTL);
	load_word(b, ARG(0));
	jump_if(b, BPF_JGE, range, L_NOTIFY);
	load_word(b, ARG(1));
	jump_if(b, BPF_JEQ, F_DUPFD, L_NOTIFY);
	jump_if(b, BPF_JEQ, F_DUPFD_CLOEXEC, L_NOTIFY);
	stmt(b, BPF_RET | BPF_K, allow);

	place(b, L_NOTIFY);
	stmt(b, BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF);

	for (k = 0; k < b->nfix; k++)
		b->f[b->fix_at[k]].jt =
			(unsigned char)(b->label[b->fix_to[k]] - b->fix_at[k] - 1);
	return b->n;
}

/* --- descriptors -----------------------------------------------------------*/

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
		if (sv_uncarriable((int)fd)) {
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

/* --- the loop --------------------------------------------------------------*/

/* How soon after a descriptor in the range closes the sweep looks, so that a
 * burst of closes costs one; and how often it looks regardless, for sockets
 * that went with a process or an exec. */
#define SWEEP_SOON_MS 200
#define SWEEP_EVERY_MS 5000
/* How often parked receives are asked whether their calls are still pending,
 * when nothing else wakes the loop. */
#define PRUNE_EVERY_MS 1000

long long sv_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void sv_sweep_soon(struct sv *sv)
{
	long long at = sv_now_ms() + SWEEP_SOON_MS;

	if (sv->sweep_at_ms == 0 || sv->sweep_at_ms > at)
		sv->sweep_at_ms = at;
}

static void serve_one(struct sv *sv)
{
	memset(sv->req, 0, sv->sizes.seccomp_notif);
	if (ioctl(sv->listener, SECCOMP_IOCTL_NOTIF_RECV, sv->req) != 0)
		return; /* EINTR or ENOENT: the call has gone */
	memset(sv->resp, 0, sv->sizes.seccomp_notif_resp);
	if (svcall_decide(sv) == SV_ANSWER)
		/* ENOENT: interrupted by a signal, or the program has gone. */
		(void)ioctl(sv->listener, SECCOMP_IOCTL_NOTIF_SEND, sv->resp);
}

/* Whether the poll set says fd is readable, or has an error to report. */
static bool ready(const struct pollfd *p, size_t np, int fd)
{
	size_t i;

	for (i = 0; i < np; i++)
		if (p[i].fd == fd)
			return (p[i].revents & (POLLIN | POLLERR | POLLHUP)) != 0;
	return false;
}

/* Retries every parked receive whose socket is readable or whose deadline has
 * passed, and forgets those answered or gone.  Matched by descriptor, since
 * answering a call may have parked or pruned others since the poll. */
static void serve_parked(struct sv *sv, const struct pollfd *p, size_t np, long long now)
{
	struct sv_parked **pp = &sv->parked;

	while (*pp != NULL) {
		struct sv_parked *q = *pp;
		bool due = ready(p, np, q->copy) ||
		           (q->deadline_ms != 0 && now >= q->deadline_ms);

		if (due && svcall_retry_parked(sv, q, now)) {
			*pp = q->next;
			close(q->copy);
			free(q);
			continue;
		}
		pp = &q->next;
	}
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
			sv_sweep_soon(sv);
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
                      unsigned range, int up, int down)
{
	static struct bpf filter;
	struct sock_fprog prog;
	int listener;
	char ack;

	sigprocmask(SIG_SETMASK, orig, NULL);
	prog.len = (unsigned short)build_filter(&filter, range);
	prog.filter = filter.f;
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

/* D-50: where the reserved range starts.  As D-26's band: 768, or half the
 * soft RLIMIT_NOFILE when that is below 1024.  A higher limit does not move it
 * up, since the kernel sizes a descriptor table to the highest number in
 * use. */
static unsigned range_start(void)
{
	struct rlimit rl;

	if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY &&
	    rl.rlim_cur < 1024)
		return (unsigned)(rl.rlim_cur / 2);
	return 768;
}

/* The loop's poll set: the listener, the signals, and each parked receive's
 * socket.  Returns how many, or 0 if out of memory. */
static size_t poll_set(struct sv *sv, struct pollfd **p, size_t *cap)
{
	struct sv_parked *q;
	size_t n = 2;

	for (q = sv->parked; q != NULL; q = q->next)
		n++;
	if (n > *cap) {
		struct pollfd *more = realloc(*p, n * sizeof(**p));

		if (more == NULL)
			return 0;
		*p = more;
		*cap = n;
	}
	(*p)[0] = (struct pollfd){ sv->listener, POLLIN, 0 };
	(*p)[1] = (struct pollfd){ sv->sigfd, POLLIN, 0 };
	n = 2;
	for (q = sv->parked; q != NULL; q = q->next)
		(*p)[n++] = (struct pollfd){ q->copy, POLLIN, 0 };
	return n;
}

/* How long the loop may sleep: until the next sweep, parked deadline or
 * prune, or for ever. */
static int poll_timeout(const struct sv *sv, long long now)
{
	const struct sv_parked *q;
	long long until = -1;

	if (sv->sweep_at_ms != 0)
		until = sv->sweep_at_ms;
	for (q = sv->parked; q != NULL; q = q->next)
		if (q->deadline_ms != 0 && (until < 0 || q->deadline_ms < until))
			until = q->deadline_ms;
	if (sv->parked != NULL && (until < 0 || until > now + PRUNE_EVERY_MS))
		until = now + PRUNE_EVERY_MS;
	if (until < 0)
		return -1;
	return until <= now ? 0 : (int)(until - now);
}

int udpc_supervise(const struct udpc_config *cfg, const char *program, char **argv)
{
	struct sv sv;
	struct utsname u;
	sigset_t fwd, orig;
	int up[2], down[2];
	struct child_msg m = { 0, 0 };
	struct pollfd *p = NULL;
	size_t k, pcap = 0;
	bool none_left = false;
	long long last_prune = 0;

	memset(&sv, 0, sizeof(sv));
	sv.cfg = cfg;
	sv.range = range_start();

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
		run_child(program, argv, &orig, sv.range, up[1], down[0]);
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
	sv.buflen = udpc_dgram_scratch_need(cfg);
	sv.buf = malloc(sv.buflen);
	if (sv.req == NULL || sv.resp == NULL || sv.buf == NULL) {
		kill(sv.child, SIGKILL);
		waitpid(sv.child, NULL, 0);
		udpc_err("out of memory");
		return 1;
	}
	/* The supervisor holds a control connection per hop for every socket
	 * the program has: as many descriptors as it may have, raised in the
	 * supervisor alone.  The program keeps the limit it was given. */
	{
		struct rlimit rl;

		if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur < rl.rlim_max) {
			rl.rlim_cur = rl.rlim_max;
			(void)setrlimit(RLIMIT_NOFILE, &rl);
		}
	}
	udpc_debug("supervising %s as process %d; UDP sockets at fd %u and up", program,
	           (int)sv.child, sv.range);

	/* Until no supervised process is left: the listener reports end of file
	 * once the last one has gone and been reaped (seccomp_unotify(2)), and
	 * waitpid() reports no children once every descendant has been. */
	while (!none_left) {
		size_t np = poll_set(&sv, &p, &pcap);
		long long now = sv_now_ms();
		int rc;

		if (np == 0) {
			udpc_err("out of memory");
			break;
		}
		rc = poll(p, (nfds_t)np, poll_timeout(&sv, now));
		if (rc < 0 && errno != EINTR) {
			udpc_err("poll: %s", strerror(errno));
			break;
		}
		now = sv_now_ms();
		if (rc > 0 && (p[1].revents & POLLIN))
			on_signal(&sv, &none_left);
		if (rc > 0 && (p[0].revents & POLLIN))
			serve_one(&sv);
		if (rc > 0 && (p[0].revents & (POLLHUP | POLLERR)))
			break;
		if (sv.parked != NULL) {
			serve_parked(&sv, rc > 0 ? p + 2 : NULL, rc > 0 ? np - 2 : 0, now);
			if (now - last_prune >= PRUNE_EVERY_MS) {
				svcall_prune_parked(&sv, 0);
				last_prune = now;
			}
		}
		if (sv.sweep_at_ms != 0 && now >= sv.sweep_at_ms) {
			sv.sweep_at_ms = 0;
			svsock_sweep(sv.range);
		}
		if (sv.sweep_at_ms == 0 && svsock_count() > 0)
			sv.sweep_at_ms = now + SWEEP_EVERY_MS;
	}
	free(p);
	free(sv.req);
	free(sv.resp);
	free(sv.buf);
	close(sv.listener);
	if (!sv.child_done) {
		waitpid(sv.child, &sv.child_status, 0);
		sv.child_done = true;
	}
	return pass_on_status(sv.child_status);
}

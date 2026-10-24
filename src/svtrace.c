/* svtrace.c -- the program's threads, stopped by ptrace (D-54).
 *
 * The supervisor attaches to the program before it runs, and to every thread
 * and process it makes, as they are made.  The filter sends each call on a
 * descriptor in the range here (SECCOMP_RET_TRACE): its thread stops at the
 * call's entry, and stays stopped while svcall.c handles it.  A signal sent
 * meanwhile is only queued, and is delivered after the call has returned what
 * the supervisor set, so what was done for a call and what it returns cannot
 * be parted -- which user notification cannot promise (D-54).
 *
 * A receive with nothing queued is not waited for here, where a signal would
 * have to wait with it: the call is rewritten as a zero-length peek on the same
 * descriptor, so the thread waits in its own kernel, natively, with
 * SO_RCVTIMEO, EINTR and SA_RESTART as a receive has them.  When the peek
 * returns, the thread stops again, the program's registers are put back, and
 * the datagram is delivered while it cannot run.
 *
 * Everything else the kernel reports is passed on: signals are handed back to
 * the program, and a group-stop is held with PTRACE_LISTEN so that SIGSTOP and
 * SIGCONT behave as they do unsupervised.
 *
 * Written from the man pages only: ptrace(2), seccomp(2), proc(5) (D-01).
 */
#include "svint.h"

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "socks5.h"

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

/* --- registers --------------------------------------------------------------
 *
 * x86-64 only, as the filter is (FR-SV-03): a call's number is orig_rax, its
 * arguments rdi, rsi, rdx, r10, r8 and r9, its result rax.  At a call's entry
 * rip is already past the two-byte syscall instruction. */

typedef struct user_regs_struct regs_t;

static int get_regs(pid_t tid, regs_t *r)
{
	return ptrace(PTRACE_GETREGS, tid, 0, r) == 0 ? 0 : -1;
}

static void set_regs(pid_t tid, const regs_t *r)
{
	(void)ptrace(PTRACE_SETREGS, tid, 0, r);
}

static void call_of(const regs_t *r, struct sv_traced *t)
{
	t->nr = (int)r->orig_rax;
	t->args[0] = r->rdi;
	t->args[1] = r->rsi;
	t->args[2] = r->rdx;
	t->args[3] = r->r10;
	t->args[4] = r->r8;
	t->args[5] = r->r9;
}

/* At a call's entry: skipped, returning ret (seccomp(2): the call number set
 * to -1, and the result where a result goes). */
static void skip_returning(regs_t *r, long long ret)
{
	r->orig_rax = (unsigned long long)-1;
	r->rax = (unsigned long long)ret;
}

/* Made again: the syscall instruction is run once more, with the call's
 * number and arguments, after any signal waiting has been handled.  At its
 * entry the call is skipped first, so the kernel makes nothing of it. */
static void again_at_entry(regs_t *r)
{
	unsigned long long nr = r->orig_rax;

	r->orig_rax = (unsigned long long)-1;
	r->rax = nr;
	r->rip -= 2;
}

static void again_at_exit(regs_t *r)
{
	r->rax = r->orig_rax;
	r->rip -= 2;
}

/* A call to be installed by notification: marked in its sixth argument. */
static void mark_install(regs_t *r)
{
	r->r9 = SV_INSTALL_MARK;
}

/* A result that says a call was interrupted before it could be answered:
 * EINTR, or one of the kernel's restart codes (ERESTARTSYS to
 * ERESTART_RESTARTBLOCK, 512 to 516), seen at a syscall-exit stop. */
static bool interrupted(long long ret)
{
	return ret == -EINTR || (ret <= -512 && ret >= -516);
}

/* The receive's wait, in the program's own kernel: a zero-length peek on the
 * same descriptor blocks until a datagram is queued, and takes nothing. */
static void as_peek(regs_t *r)
{
	r->orig_rax = SYS_recvfrom;
	r->rsi = 0;
	r->rdx = 0;
	r->r10 = MSG_PEEK | MSG_TRUNC;
	r->r8 = 0;
	r->r9 = 0;
}

/* --- calls waiting ----------------------------------------------------------*/

/* A thread let go on with its call rewritten or marked, until the call
 * returns: its registers as the program made the call, put back then, and
 * the call as svcall_traced left it. */
struct waiting {
	regs_t regs;
	struct sv_traced t;
	uint64_t mask;   /* SV_INSTALL: the thread's own signal mask */
	struct waiting *next;
};

#define NWAIT 64
static struct waiting *g_wait[NWAIT];

static struct waiting **wait_slot(pid_t tid)
{
	struct waiting **pp = &g_wait[(unsigned)tid % NWAIT];

	while (*pp != NULL && (*pp)->t.tid != tid)
		pp = &(*pp)->next;
	return pp;
}

static void forget(pid_t tid)
{
	struct waiting **pp = wait_slot(tid), *w = *pp;

	if (w == NULL)
		return;
	*pp = w->next;
	if (w->t.copy >= 0)
		close(w->t.copy);
	free(w);
}

/* --- signals waiting --------------------------------------------------------*/

/* Signals whose default is to be ignored: pending, they interrupt nothing
 * unless the program catches them. */
#define BIT(sig) (1ULL << ((sig) - 1))
#define DEFAULT_IGNORED (BIT(SIGCHLD) | BIT(SIGCONT) | BIT(SIGURG) | BIT(SIGWINCH))

/* True if tid has a signal waiting that would interrupt a call: pending for it
 * or its process, not blocked, and neither ignored nor ignored by default.  A
 * thread stopped by ptrace keeps a signal sent to it pending (proc(5)). */
static bool signal_waiting(pid_t tid)
{
	unsigned long long pnd = 0, shd = 0, blk = 0, ign = 0, cgt = 0;
	char path[64], line[128];
	FILE *f;

	snprintf(path, sizeof(path), "/proc/%d/status", (int)tid);
	f = fopen(path, "re");
	if (f == NULL)
		return false;
	while (fgets(line, sizeof(line), f) != NULL) {
		if (sscanf(line, "SigPnd: %llx", &pnd) == 1 ||
		    sscanf(line, "ShdPnd: %llx", &shd) == 1 ||
		    sscanf(line, "SigBlk: %llx", &blk) == 1 ||
		    sscanf(line, "SigIgn: %llx", &ign) == 1)
			continue;
		if (sscanf(line, "SigCgt: %llx", &cgt) == 1)
			break;
	}
	fclose(f);
	return ((pnd | shd) & ~blk & ~ign & ~(DEFAULT_IGNORED & ~cgt)) != 0;
}

/* The thread whose call is being handled, while an association it needs is
 * set up: a signal arriving for it abandons the setup (D-54). */
static pid_t g_for;
static bool g_abandoned;

static bool abandon(void *arg)
{
	(void)arg;
	if (!signal_waiting(g_for))
		return false;
	g_abandoned = true;
	return true;
}

/* Runs decide for t with setup abandoned on a signal.  An abandoned setup
 * returns EINTR from deep inside the call's handling; nothing was sent, and
 * the call is made again once the signal has been handled. */
static void with_abandon(struct sv *sv, struct sv_traced *t, long long peeked, bool waited)
{
	g_for = t->tid;
	g_abandoned = false;
	udpc_socks_set_cancel(abandon, NULL);
	if (waited)
		svcall_waited(sv, t, peeked);
	else
		svcall_traced(sv, t);
	udpc_socks_set_cancel(NULL, NULL);
	if (g_abandoned && t->verdict == SV_RETURN && t->ret == -EINTR)
		t->verdict = SV_AGAIN;
}

/* --- stops ------------------------------------------------------------------*/

/* Every signal but SIGKILL and SIGSTOP, which cannot be blocked. */
static const uint64_t g_all_blocked = ~0ULL;

/* Lets tid go on with its call as r now has it, until the call returns:
 * stopped again then, at its exit (PTRACE_SYSCALL).  False if out of
 * memory. */
static bool let_go_until_return(pid_t tid, const regs_t *program, const regs_t *r,
                                const struct sv_traced *t, uint64_t mask)
{
	struct waiting *w = calloc(1, sizeof(*w));

	if (w == NULL)
		return false;
	forget(tid);
	w->regs = *program;
	w->t = *t;
	w->mask = mask;
	w->next = g_wait[(unsigned)tid % NWAIT];
	g_wait[(unsigned)tid % NWAIT] = w;
	set_regs(tid, r);
	(void)ptrace(PTRACE_SYSCALL, tid, 0, 0);
	return true;
}

/* A traced call's entry. */
static void on_entry(struct sv *sv, pid_t tid)
{
	struct sv_traced t;
	uint64_t mask = 0;
	regs_t r, program;

	if (get_regs(tid, &r) != 0)
		return; /* killed while stopped */
	memset(&t, 0, sizeof(t));
	t.tid = tid;
	t.copy = -1;
	call_of(&r, &t);
	with_abandon(sv, &t, 0, false);
	program = r;

	switch (t.verdict) {
	case SV_RETURN:
		skip_returning(&r, t.ret);
		break;
	case SV_NATIVE:
		(void)ptrace(PTRACE_CONT, tid, 0, 0);
		return;
	case SV_AGAIN:
		again_at_entry(&r);
		break;
	case SV_WAIT:
		as_peek(&r);
		/* Stopped again when the peek returns. */
		if (let_go_until_return(tid, &program, &r, &t, 0))
			return;
		close(t.copy);
		r = program;
		skip_returning(&r, -ENOMEM);
		break;
	case SV_INSTALL:
		/* No signal can interrupt the notification, so none can
		 * part the descriptor installed from the call returning it.
		 * SIGSTOP and SIGKILL, which cannot be blocked, still can: the
		 * call is then made again (on_exit_stop). */
		if (ptrace(PTRACE_GETSIGMASK, tid, (void *)sizeof(mask), &mask) == 0 &&
		    ptrace(PTRACE_SETSIGMASK, tid, (void *)sizeof(g_all_blocked),
		           &g_all_blocked) == 0) {
			mark_install(&r);
			if (let_go_until_return(tid, &program, &r, &t, mask))
				return;
			(void)ptrace(PTRACE_SETSIGMASK, tid, (void *)sizeof(mask), &mask);
		}
		r = program;
		skip_returning(&r, -ENOMEM);
		break;
	}
	set_regs(tid, &r);
	(void)ptrace(PTRACE_CONT, tid, 0, 0);
}

/* A call let go on until it returned has returned: a waiting receive's peek,
 * or an install's notification. */
static void on_exit_stop(struct sv *sv, pid_t tid)
{
	struct waiting **pp = wait_slot(tid), *w = *pp;
	regs_t r;

	if (w == NULL || get_regs(tid, &r) != 0) {
		(void)ptrace(PTRACE_CONT, tid, 0, 0);
		return;
	}
	if (w->t.verdict == SV_INSTALL) {
		long long ret = (long long)r.rax;

		/* Interrupted before it was answered, by a signal pending
		 * from before its mask was set, or by SIGSTOP: nothing was
		 * installed, and the call is made again once the signal is
		 * handled -- as socket() natively never fails with EINTR. */
		r = w->regs;
		if (interrupted(ret))
			again_at_exit(&r);
		else
			r.rax = (unsigned long long)ret;
		set_regs(tid, &r);
		(void)ptrace(PTRACE_SETSIGMASK, tid, (void *)sizeof(w->mask), &w->mask);
		forget(tid);
		(void)ptrace(PTRACE_CONT, tid, 0, 0);
		return;
	}
	with_abandon(sv, &w->t, (long long)r.rax, true);
	/* The program's registers, call number included: it keeps its
	 * arguments across a call, and a restart makes its own call again. */
	r = w->regs;
	if (w->t.verdict == SV_AGAIN)
		again_at_exit(&r);
	else
		r.rax = (unsigned long long)w->t.ret;
	set_regs(tid, &r);
	forget(tid);
	(void)ptrace(PTRACE_CONT, tid, 0, 0);
}

static bool stopping_signal(int sig)
{
	return sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU;
}

static void on_stop(struct sv *sv, pid_t tid, int st)
{
	int sig = WSTOPSIG(st), event = (unsigned)st >> 16;

	if (sig == SIGTRAP && event == PTRACE_EVENT_SECCOMP) {
		on_entry(sv, tid);
		return;
	}
	if (sig == (SIGTRAP | 0x80)) {
		on_exit_stop(sv, tid);
		return;
	}
	if (event == PTRACE_EVENT_STOP) {
		/* A group-stop is held until SIGCONT ends it; anything else
		 * is a new thread or process starting, or a group-stop
		 * ending. */
		if (stopping_signal(sig))
			(void)ptrace(PTRACE_LISTEN, tid, 0, 0);
		else
			(void)ptrace(PTRACE_CONT, tid, 0, 0);
		return;
	}
	if (event != 0) {
		/* fork, vfork, clone or exec.  An exec ends every other
		 * thread, and may give the execing one the leader's number;
		 * and it closes the close-on-exec descriptors, which the
		 * sweep notices (FR-SV-11). */
		if (event == PTRACE_EVENT_EXEC) {
			forget(tid);
			sv_sweep_soon(sv);
		}
		(void)ptrace(PTRACE_CONT, tid, 0, 0);
		return;
	}
	/* The program's own signal, handed back to it. */
	(void)ptrace(PTRACE_CONT, tid, 0, sig);
}

/* --- attaching and reaping --------------------------------------------------*/

int svtrace_attach(pid_t child)
{
	/* EXITKILL: should the supervisor die, every traced process dies with
	 * it, never continuing untraced (FR-SV-13). */
	long opts = PTRACE_O_TRACESECCOMP | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE |
	            PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXEC |
	            PTRACE_O_EXITKILL;

	if (ptrace(PTRACE_SEIZE, child, 0, (void *)opts) != 0)
		return errno;
	return 0;
}

void svtrace_reap(struct sv *sv, bool *none_left)
{
	int st;
	pid_t p;

	/* __WALL: threads are reported too, as their tracer. */
	while ((p = waitpid(-1, &st, WNOHANG | __WALL)) > 0) {
		if (WIFSTOPPED(st)) {
			on_stop(sv, p, st);
			continue;
		}
		forget(p);
		sv_sweep_soon(sv);
		if (p == sv->child) {
			sv->child_status = st;
			sv->child_done = true;
		}
	}
	if (p < 0 && errno == ECHILD)
		*none_left = true;
}

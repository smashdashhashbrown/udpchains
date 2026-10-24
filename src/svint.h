/* svint.h -- the supervisor's internals, shared by supervise.c (the filter,
 * start-up and the loop), svtrace.c (the program's threads, stopped by
 * ptrace), svcall.c (answering each call) and svsock.c (the sockets it
 * carries).  Wrapper-only, like the rest of the supervisor.
 */
#ifndef UDPCHAINS_SVINT_H
#define UDPCHAINS_SVINT_H

#include "compat.h"

#include <linux/seccomp.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "config.h"
#include "socks5.h"

/* --- the sockets the supervisor carries (D-50) ---------------------------
 *
 * One entry per UDP socket the supervisor made, keyed by the kernel's socket
 * cookie, which is never reused.  Every descriptor for the socket, in every
 * supervised process -- duplicated, inherited across fork, kept across exec --
 * finds the same entry, as they share one socket in the kernel.  Nothing is
 * kept per process or per descriptor number, so nothing about them can go
 * stale. */
struct sv_sock {
	uint64_t cookie;
	unsigned long ino;   /* the socket's inode, as /proc/<pid>/fd shows it */
	int family;          /* AF_INET or AF_INET6 */

	bool connected;      /* the destination the program connect()ed to */
	struct sockaddr_storage app_dst;
	bool bound_set;      /* a concrete address the program bound (FR-P-05) */
	struct sockaddr_storage bound;

	bool associated;     /* the chain is up and the socket points at hop 1 */
	struct udpc_socks_chain chain;
	long last_used;      /* CLOCK_MONOTONIC seconds, for FR-P-08 */

	bool seen;           /* by the sweep in progress */
	struct sv_sock *next;
};

struct sv_sock *svsock_find(uint64_t cookie);

/* A new entry for a socket just made, or NULL if out of memory. */
struct sv_sock *svsock_add(uint64_t cookie, unsigned long ino, int family);

/* Forgets s, closing its association: what tells the proxy to release it. */
void svsock_remove(struct sv_sock *s);

unsigned svsock_count(void);

/* Forgets every socket no supervised process holds any longer in the range:
 * the supervisor is not told when the program's last descriptor for a socket
 * closes, so it looks.  Supervised processes are the supervisor's descendants
 * (it is their subreaper, so an orphan stays one). */
void svsock_sweep(unsigned range_start);

/* Ensures s has an association: the chain set up and the socket, through copy
 * (the supervisor's descriptor for it), pointed at hop 1's relay (FR-I-07).
 * With revalidate, one idle long enough to have been expired is checked and
 * replaced (FR-P-08).  pid and fd name it in diagnostics.  0, or an errno for
 * the program's call: never a direct send (SEC-01). */
int svsock_hold(const struct udpc_config *cfg, struct sv_sock *s, int copy,
                bool revalidate, pid_t pid, int fd);

/* Records a datagram sent or received on s, for the idle check. */
void svsock_used(struct sv_sock *s);

/* Closes s's association, so the next use sets up a new one. */
void svsock_drop_assoc(struct sv_sock *s);

/* --- the supervisor ------------------------------------------------------*/

struct sv {
	const struct udpc_config *cfg;
	int listener;
	int sigfd;
	pid_t child;      /* the program */
	int child_status; /* once it has exited */
	bool child_done;
	unsigned range;   /* the reserved range starts here (D-50) */
	struct seccomp_notif *req;
	struct seccomp_notif_resp *resp;
	struct seccomp_notif_sizes sizes;

	uint8_t *buf;     /* one datagram, wrapped: udpc_dgram_scratch_need */
	size_t buflen;

	long long sweep_at_ms; /* when the next sweep is due; 0 for none */
};

/* How a call was answered. */
enum sv_outcome {
	SV_ANSWER,   /* answered: resp filled in for the loop to send, or for a
	              * traced call, its result decided */
	SV_ANSWERED, /* already answered, or gone: nothing to send */
	SV_PARKED    /* a traced receive that must wait for a datagram */
};

/* Fills in sv->resp for sv->req, or answers it: a call the filter sent by user
 * notification (D-48). */
enum sv_outcome svcall_decide(struct sv *sv);

/* --- traced calls (D-54) --------------------------------------------------
 *
 * A call on a descriptor in the range stops its thread, through ptrace, and is
 * handled while the thread cannot run: a signal sent meanwhile waits until the
 * call has its result. */

/* What becomes of a traced call. */
enum sv_verdict {
	SV_RETURN,  /* skipped, returning ret */
	SV_NATIVE,  /* runs in the kernel as the program made it */
	SV_WAIT,    /* a receive with nothing queued: the thread waits natively,
	             * in a zero-length peek, holding copy */
	SV_AGAIN    /* made again: once a waiting signal has been handled, or to
	             * wait for the next datagram */
};

struct sv_traced {
	pid_t tid;
	int nr;
	__u64 args[6];
	/* what svcall_traced and svcall_waited decide */
	enum sv_verdict verdict;
	long long ret;   /* SV_RETURN: the result, or -errno */
	int copy;        /* SV_WAIT: the supervisor's descriptor for the socket */
	uint64_t cookie; /* SV_WAIT: the socket's */
};

/* Decides a traced call at its entry. */
void svcall_traced(struct sv *sv, struct sv_traced *t);

/* Decides a waiting receive once its peek has returned peeked: a datagram is
 * queued (peeked >= 0), or the peek's own error.  t is as svcall_traced left
 * it; its copy stays the caller's to close. */
void svcall_waited(struct sv *sv, struct sv_traced *t, long long peeked);

/* Attaches to the program, the child the supervisor forked, before it runs:
 * its threads and descendants are attached as they are made.  0, or an
 * errno. */
int svtrace_attach(pid_t child);

/* Handles every stop and exit the kernel has to report.  Sets *none_left once
 * no child or traced thread is left, and records the program's status. */
void svtrace_reap(struct sv *sv, bool *none_left);

/* A UDP, raw or packet socket: what the supervisor carries only when it made
 * it (D-50), or never (D-36). */
bool sv_uncarriable(int fd);

/* Asks the loop for a sweep soon: a descriptor in the range was closed or
 * replaced. */
void sv_sweep_soon(struct sv *sv);

long long sv_now_ms(void);

#endif /* UDPCHAINS_SVINT_H */

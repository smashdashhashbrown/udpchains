/* svint.h -- the supervisor's internals, shared by supervise.c (the filter,
 * start-up and the notification loop), svcall.c (answering each call) and
 * svsock.c (the sockets it carries).  Wrapper-only, like the rest of the
 * supervisor.
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

/* A blocking receive with nothing queued yet (D-51): its call waits in the
 * program while the supervisor watches the socket, and is answered when a
 * datagram arrives, its SO_RCVTIMEO expires, or the call goes away. */
struct sv_parked {
	struct seccomp_notif req; /* the call, as notified */
	uint64_t cookie;          /* the socket's */
	int copy;                 /* the supervisor's descriptor for it */
	long long deadline_ms;    /* CLOCK_MONOTONIC; 0 for none */
	struct sv_parked *next;
};

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

	struct sv_parked *parked;
	long long sweep_at_ms; /* when the next sweep is due; 0 for none */
};

/* How a call was answered. */
enum sv_outcome {
	SV_ANSWER,   /* resp is filled in; the loop sends it */
	SV_ANSWERED, /* already answered, or gone: nothing to send */
	SV_PARKED    /* a receive waiting for a datagram */
};

/* Fills in sv->resp for sv->req, or answers it. */
enum sv_outcome svcall_decide(struct sv *sv);

/* Retries a parked receive: when its socket is readable, at its deadline, or to
 * notice that it has gone.  True once it is answered or gone, and may be
 * freed. */
bool svcall_retry_parked(struct sv *sv, struct sv_parked *p, long long now_ms);

/* Forgets parked calls that are no longer pending: with tid, those of that
 * thread, which has made another call since; with 0, any the kernel no longer
 * has. */
void svcall_prune_parked(struct sv *sv, pid_t tid);

/* A UDP, raw or packet socket: what the supervisor carries only when it made
 * it (D-50), or never (D-36). */
bool sv_uncarriable(int fd);

/* Asks the loop for a sweep soon: a descriptor in the range was closed or
 * replaced. */
void sv_sweep_soon(struct sv *sv);

long long sv_now_ms(void);

#endif /* UDPCHAINS_SVINT_H */

/* svsock.c -- the UDP sockets the supervisor carries, and their associations
 * (D-50, FR-P-01, FR-P-08).
 *
 * Wrapper-only.  The supervisor is one thread, so nothing here is locked.
 */
#include "svint.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/kcmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "addr.h"
#include "dgram.h"
#include "log.h"

#define NBUCKETS 256

static struct sv_sock *g_bucket[NBUCKETS];     /* by cookie */
static struct sv_sock *g_ino_bucket[NBUCKETS]; /* by inode, for the sweep */
static unsigned g_count;

static unsigned bucket_of(uint64_t cookie)
{
	return (unsigned)(cookie ^ (cookie >> 8) ^ (cookie >> 16)) % NBUCKETS;
}

static unsigned ino_bucket_of(unsigned long ino)
{
	return (unsigned)(ino % NBUCKETS);
}

struct sv_sock *svsock_find(uint64_t cookie)
{
	struct sv_sock *s;

	for (s = g_bucket[bucket_of(cookie)]; s != NULL; s = s->next)
		if (s->cookie == cookie)
			return s;
	return NULL;
}

struct sv_sock *svsock_add(uint64_t cookie, unsigned long ino, int family)
{
	struct sv_sock *s = calloc(1, sizeof(*s));
	unsigned b = bucket_of(cookie), ib = ino_bucket_of(ino);

	if (s == NULL)
		return NULL;
	s->cookie = cookie;
	s->ino = ino;
	s->family = family;
	s->next = g_bucket[b];
	g_bucket[b] = s;
	s->ino_next = g_ino_bucket[ib];
	g_ino_bucket[ib] = s;
	g_count++;
	return s;
}

void svsock_drop_assoc(struct sv_sock *s)
{
	if (!s->associated)
		return;
	udpc_socks_disconnect_chain(&s->chain);
	s->associated = false;
}

void svsock_remove(struct sv_sock *s)
{
	struct sv_sock **pp = &g_bucket[bucket_of(s->cookie)];

	while (*pp != NULL && *pp != s)
		pp = &(*pp)->next;
	if (*pp == NULL)
		return;
	*pp = s->next;
	pp = &g_ino_bucket[ino_bucket_of(s->ino)];
	while (*pp != NULL && *pp != s)
		pp = &(*pp)->ino_next;
	if (*pp != NULL)
		*pp = s->ino_next;
	g_count--;
	svsock_drop_assoc(s);
	free(s);
}

unsigned svsock_count(void)
{
	return g_count;
}

/* --- the sweep ------------------------------------------------------------
 *
 * It reads the tables of the processes the supervisor traces (svtrace.c), and
 * nothing else on the host (D-50). */

/* Marks every carried socket held at a descriptor in the range of the table
 * listed at path.  False if it cannot be read, which says nothing about what
 * it holds. */
static bool mark_table(const char *path, unsigned range_start)
{
	struct dirent *e;
	DIR *d;

	d = opendir(path);
	if (d == NULL)
		return errno == ENOENT; /* gone: holds nothing */
	while ((e = readdir(d)) != NULL) {
		char link[64];
		unsigned long fd, ino;
		struct sv_sock *s;
		ssize_t n;

		if (!isdigit((unsigned char)e->d_name[0]))
			continue;
		fd = strtoul(e->d_name, NULL, 10);
		if (fd < range_start)
			continue;
		n = readlinkat(dirfd(d), e->d_name, link, sizeof(link) - 1);
		if (n <= 0)
			continue;
		link[n] = '\0';
		if (sscanf(link, "socket:[%lu]", &ino) != 1)
			continue;
		/* Every entry with the inode: a socket forgotten late may share
		 * the number of one made since. */
		for (s = g_ino_bucket[ino_bucket_of(ino)]; s != NULL; s = s->ino_next)
			if (s->ino == ino)
				s->seen = true;
	}
	closedir(d);
	return true;
}

/* Marks every carried socket pid holds in the range: in its table, and in that
 * of any thread of it with a table of its own (unshare(CLONE_FILES)), as
 * kcmp(2) tells.  False if any cannot be read. */
static bool mark_held(pid_t pid, unsigned range_start)
{
	char path[96];
	struct dirent *e;
	DIR *d;

	snprintf(path, sizeof(path), "/proc/%d/fd", (int)pid);
	if (!mark_table(path, range_start))
		return false;
	snprintf(path, sizeof(path), "/proc/%d/task", (int)pid);
	d = opendir(path);
	if (d == NULL)
		return true; /* gone since: what it held went with it */
	while ((e = readdir(d)) != NULL) {
		long tid;

		if (!isdigit((unsigned char)e->d_name[0]))
			continue;
		tid = strtol(e->d_name, NULL, 10);
		if (tid == pid || syscall(SYS_kcmp, pid, (pid_t)tid, KCMP_FILES, 0, 0) == 0)
			continue;
		snprintf(path, sizeof(path), "/proc/%d/task/%ld/fd", (int)pid, tid);
		if (!mark_table(path, range_start) && errno != ENOENT) {
			closedir(d);
			return false;
		}
	}
	closedir(d);
	return true;
}

static int by_tgid(const void *a, const void *b)
{
	pid_t x = ((const struct sv_task *)a)->tgid, y = ((const struct sv_task *)b)->tgid;

	return (x > y) - (x < y);
}

static bool listed(const struct sv_task *t, size_t n, pid_t tgid)
{
	struct sv_task key = { 0, tgid };

	return bsearch(&key, t, n, sizeof(*t), by_tgid) != NULL;
}

/* A child a thread has made that is not listed yet: between its creation and
 * its parent's fork stop the kernel has not reported it, but it already holds
 * what it inherited.  It cannot have run, so has no children of its own.  The
 * kernel lists a thread's children in /proc (CONFIG_PROC_CHILDREN); without
 * that file there is nothing to add.  False if a table cannot be read; *read
 * counts the tables read. */
static bool mark_unlisted_children(const struct sv_task *t, size_t n, const struct sv_task *k,
                                   unsigned range_start, size_t *read)
{
	char path[96];
	FILE *f;
	int pid;
	bool ok = true;

	snprintf(path, sizeof(path), "/proc/%d/task/%d/children", (int)k->tgid, (int)k->tid);
	f = fopen(path, "re");
	if (f == NULL)
		return errno == ENOENT; /* gone, or no such file on this kernel */
	while (ok && fscanf(f, "%d", &pid) == 1) {
		if (listed(t, n, (pid_t)pid))
			continue;
		ok = mark_held((pid_t)pid, range_start);
		(*read)++;
	}
	fclose(f);
	return ok;
}

void svsock_sweep(unsigned range_start)
{
	struct sv_task *t;
	struct sv_sock *s, *next;
	size_t n, i, read = 0;
	unsigned b, dropped = 0;

	if (g_count == 0 || !svtrace_complete())
		return; /* a thread not recorded might hold any of them */
	t = svtrace_tasks(&n);
	if (t == NULL)
		return; /* try again at the next sweep */
	qsort(t, n, sizeof(*t), by_tgid);

	for (b = 0; b < NBUCKETS; b++)
		for (s = g_bucket[b]; s != NULL; s = s->next)
			s->seen = false;
	for (i = 0; i < n; i++) {
		/* A process whose descriptors cannot be read might hold any
		 * of them: forget nothing this time. */
		if (i == 0 || t[i].tgid != t[i - 1].tgid) {
			if (!mark_held(t[i].tgid, range_start)) {
				free(t);
				return;
			}
			read++;
		}
		if (!mark_unlisted_children(t, n, &t[i], range_start, &read)) {
			free(t);
			return;
		}
	}
	free(t);

	for (b = 0; b < NBUCKETS; b++)
		for (s = g_bucket[b]; s != NULL; s = next) {
			next = s->next;
			if (!s->seen) {
				svsock_remove(s);
				dropped++;
			}
		}
	if (dropped > 0)
		udpc_debug("closed %u association%s no supervised process uses any "
		           "longer, after reading %zu process table%s",
		           dropped, dropped == 1 ? "" : "s", read, read == 1 ? "" : "s");
}

/* --- associations ---------------------------------------------------------*/

static long now_s(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC_COARSE, &ts) != 0)
		return 0;
	return (long)ts.tv_sec;
}

/* Points the program's socket at hop 1's relay, through the supervisor's
 * descriptor for the same socket (FR-I-07): replies then arrive on the
 * program's own socket, and poll, select and epoll work on it untouched. */
static int redirect(struct sv_sock *s, int copy)
{
	struct sockaddr_storage relay;
	char rbuf[UDPC_ADDRSTRLEN];

	if (udpc_addr_for_family((const struct sockaddr *)&s->chain.relay[0].sa, s->family,
	                         &relay) != 0) {
		udpc_err("proxy returned relay %s, which an %s socket cannot reach",
		         udpc_addr_str((const struct sockaddr *)&s->chain.relay[0].sa, rbuf,
		                       sizeof(rbuf)),
		         s->family == AF_INET6 ? "AF_INET6" : "AF_INET");
		return EAFNOSUPPORT;
	}
	if (connect(copy, (const struct sockaddr *)&relay,
	            udpc_sa_len((const struct sockaddr *)&relay)) != 0)
		return errno;
	return 0;
}

static int establish(const struct udpc_config *cfg, struct sv_sock *s, int copy,
                     pid_t pid, int fd)
{
	char abuf[UDPC_ADDRSTRLEN], rbuf[UDPC_SOCKS_CHAIN_PATH_MAX];
	const struct sockaddr *dst = s->connected ? (const struct sockaddr *)&s->app_dst : NULL;
	int err = 0;

	/* D-52: a socket connected to the system resolver sends to dns, which
	 * is what the guard is about; with no dns, its sends fail anyway. */
	if (dst != NULL && svdns_system_resolver(dst))
		dst = cfg->dns_set ? (const struct sockaddr *)&cfg->dns : NULL;
	if (udpc_dgram_loopback_guard(cfg, dst, &err) != 0)
		return err;
	/* FR-P-05: declare the bound address only when the program bound a
	 * concrete one. */
	if (udpc_socks_associate_chain(cfg,
	                               s->bound_set ? (const struct sockaddr *)&s->bound
	                                            : NULL,
	                               &s->chain, &err) != 0)
		return err; /* SEC-01: reported on the program's call */
	err = redirect(s, copy);
	if (err != 0) {
		udpc_socks_disconnect_chain(&s->chain);
		return err;
	}
	s->associated = true;
	s->last_used = now_s();

	/* FR-C-06, as in shim mode, naming the process. */
	udpc_socks_chain_path(&s->chain, rbuf, sizeof(rbuf));
	if (s->connected)
		udpc_info("association up: process %d fd %d -> %s via relay %s "
		          "(max_datagram %zu)",
		          (int)pid, fd,
		          udpc_addr_str((const struct sockaddr *)&s->app_dst, abuf,
		                        sizeof(abuf)),
		          rbuf, cfg->max_datagram);
	else
		udpc_info("association up: process %d fd %d via relay %s "
		          "(max_datagram %zu)",
		          (int)pid, fd, rbuf, cfg->max_datagram);
	return 0;
}

void svsock_used(struct sv_sock *s)
{
	s->last_used = now_s();
}

int svsock_hold(const struct udpc_config *cfg, struct sv_sock *s, int copy,
                bool revalidate, pid_t pid, int fd)
{
	long now;

	if (!s->associated)
		return establish(cfg, s, copy, pid, fd);
	if (!revalidate)
		return 0;
	/* FR-P-08: one idle long enough to have been expired is checked before
	 * the send, not discovered after the datagram has gone to a relay port
	 * that no longer exists. */
	now = now_s();
	if (now - s->last_used < UDPC_IDLE_PROBE_SECS)
		return 0;
	if (udpc_socks_chain_alive(&s->chain)) {
		s->last_used = now;
		return 0;
	}
	udpc_debug("process %d fd %d: association idle for %lds and the control "
	           "connection is gone; re-associating (FR-P-08)",
	           (int)pid, fd, now - s->last_used);
	svsock_drop_assoc(s);
	return establish(cfg, s, copy, pid, fd);
}

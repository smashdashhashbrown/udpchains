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

static struct sv_sock *g_bucket[NBUCKETS];
static unsigned g_count;

static unsigned bucket_of(uint64_t cookie)
{
	return (unsigned)(cookie ^ (cookie >> 8) ^ (cookie >> 16)) % NBUCKETS;
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
	unsigned b = bucket_of(cookie);

	if (s == NULL)
		return NULL;
	s->cookie = cookie;
	s->ino = ino;
	s->family = family;
	s->next = g_bucket[b];
	g_bucket[b] = s;
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
	g_count--;
	svsock_drop_assoc(s);
	free(s);
}

unsigned svsock_count(void)
{
	return g_count;
}

/* --- the sweep ------------------------------------------------------------*/

struct proc {
	pid_t pid, ppid;
};

static int by_pid(const void *a, const void *b)
{
	pid_t x = ((const struct proc *)a)->pid, y = ((const struct proc *)b)->pid;

	return (x > y) - (x < y);
}

/* The parent of pid, from /proc/<pid>/stat: the field after the command name,
 * which may itself contain spaces and parentheses, so it is found from the
 * last ')'.  -1 if the process has gone. */
static pid_t ppid_of(const char *pid)
{
	char path[64], line[512], *close;
	int ppid;
	FILE *f;
	size_t n;

	snprintf(path, sizeof(path), "/proc/%s/stat", pid);
	f = fopen(path, "re");
	if (f == NULL)
		return -1;
	n = fread(line, 1, sizeof(line) - 1, f);
	fclose(f);
	line[n] = '\0';
	close = strrchr(line, ')');
	if (close == NULL || sscanf(close + 1, " %*c %d", &ppid) != 1)
		return -1;
	return (pid_t)ppid;
}

static bool descends_from(const struct proc *procs, size_t n, pid_t pid, pid_t self)
{
	int depth;

	for (depth = 0; depth < 256 && pid > 1; depth++) {
		struct proc key = { pid, 0 }, *p;

		p = bsearch(&key, procs, n, sizeof(*procs), by_pid);
		if (p == NULL)
			return false;
		if (p->ppid == self)
			return true;
		pid = p->ppid;
	}
	return false;
}

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
		unsigned b;

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
		for (b = 0; b < NBUCKETS; b++)
			for (s = g_bucket[b]; s != NULL; s = s->next)
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

void svsock_sweep(unsigned range_start)
{
	struct proc *procs = NULL;
	size_t n = 0, cap = 0, i;
	pid_t self = getpid();
	struct sv_sock *s, *next;
	struct dirent *e;
	unsigned b, dropped = 0;
	DIR *d;

	if (g_count == 0)
		return;
	d = opendir("/proc");
	if (d == NULL)
		return;
	while ((e = readdir(d)) != NULL) {
		pid_t ppid;

		if (!isdigit((unsigned char)e->d_name[0]))
			continue;
		ppid = ppid_of(e->d_name);
		if (ppid < 0)
			continue;
		if (n == cap) {
			struct proc *more;

			cap = cap ? cap * 2 : 256;
			more = realloc(procs, cap * sizeof(*procs));
			if (more == NULL) {
				free(procs);
				closedir(d);
				return; /* try again at the next sweep */
			}
			procs = more;
		}
		procs[n].pid = (pid_t)strtol(e->d_name, NULL, 10);
		procs[n].ppid = ppid;
		n++;
	}
	closedir(d);
	qsort(procs, n, sizeof(*procs), by_pid);

	for (b = 0; b < NBUCKETS; b++)
		for (s = g_bucket[b]; s != NULL; s = s->next)
			s->seen = false;
	for (i = 0; i < n; i++) {
		if (!descends_from(procs, n, procs[i].pid, self))
			continue;
		/* A descendant whose descriptors cannot be read might hold any
		 * of them: forget nothing this time. */
		if (!mark_held(procs[i].pid, range_start)) {
			free(procs);
			return;
		}
	}
	free(procs);

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
		           "longer",
		           dropped, dropped == 1 ? "" : "s");
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
	int err = 0;

	if (udpc_dgram_loopback_guard(
		    cfg, s->connected ? (const struct sockaddr *)&s->app_dst : NULL,
		    &err) != 0)
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

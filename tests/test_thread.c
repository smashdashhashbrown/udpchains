/* test_thread.c -- TST-07, threaded stress (FR-L-01, NFR-02, NFR-03).
 *
 * TST-07 is only a SHOULD, but it is the sole verification of FR-L-01, which is
 * a MUST, and of the lock-free fd table that D-07 chose.  D-08 records it as
 * effectively mandatory for that reason.  Run it under TSan and ASan too
 * (TST-08) -- the failure modes this guards against are exactly the ones a
 * single-threaded run cannot see.
 *
 * Run under the shim:  udpchains ./test_thread <echo>
 */
#include "tap.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define NTHREADS 8
#define NITER 25

static struct sockaddr_in g_echo;

static _Atomic int g_ok;
static _Atomic int g_fail;
static _Atomic int g_cross;

static int udp4(void)
{
	struct timeval tv = { 5, 0 };
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (fd >= 0)
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return fd;
}

static int count_tcp_sockets(void)
{
	DIR *d = opendir("/proc/self/fd");
	struct dirent *ent;
	int n = 0;

	if (d == NULL)
		return -1;
	while ((ent = readdir(d)) != NULL) {
		int fd, domain = 0, type = 0;
		socklen_t l;

		if (ent->d_name[0] == '.')
			continue;
		fd = atoi(ent->d_name);
		if (fd == dirfd(d))
			continue;
		l = sizeof(domain);
		if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &l) != 0)
			continue;
		l = sizeof(type);
		if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &l) != 0)
			continue;
		if (type == SOCK_STREAM && (domain == AF_INET || domain == AF_INET6))
			n++;
	}
	closedir(d);
	return n;
}

/* Phase 1: every thread owns its own fd.  Cross-delivery here would be a real
 * defect -- a datagram for one association surfacing on another. */
static void *own_fd_worker(void *arg)
{
	long id = (long)arg;
	int fd = udp4();
	int i;

	if (fd < 0) {
		atomic_fetch_add(&g_fail, 1);
		return NULL;
	}
	if (connect(fd, (struct sockaddr *)&g_echo, sizeof(g_echo)) != 0) {
		atomic_fetch_add(&g_fail, 1);
		close(fd);
		return NULL;
	}

	for (i = 0; i < NITER; i++) {
		char want[64], got[128];
		ssize_t n;
		size_t len;

		snprintf(want, sizeof(want), "own-%ld-%d", id, i);
		len = strlen(want);

		if (send(fd, want, len, 0) != (ssize_t)len) {
			atomic_fetch_add(&g_fail, 1);
			continue;
		}
		memset(got, 0, sizeof(got));
		n = recv(fd, got, sizeof(got), 0);
		if (n < 0) {
			atomic_fetch_add(&g_fail, 1);
			continue;
		}
		if ((size_t)n != len || memcmp(got, want, len) != 0) {
			atomic_fetch_add(&g_cross, 1);
			continue;
		}
		atomic_fetch_add(&g_ok, 1);
	}

	close(fd);
	return NULL;
}

/* Phase 2: every thread shares ONE fd.  Which thread receives which reply is
 * genuinely undefined, so the assertion is that every payload received is one
 * that was actually sent, and that nothing crashes or is lost. */
static int g_shared_fd;

static void *shared_fd_worker(void *arg)
{
	long id = (long)arg;
	int i;

	for (i = 0; i < NITER; i++) {
		char want[64], got[128];
		ssize_t n;
		size_t len;
		long rid, rit;

		snprintf(want, sizeof(want), "shared-%ld-%d", id, i);
		len = strlen(want);

		if (send(g_shared_fd, want, len, 0) != (ssize_t)len) {
			atomic_fetch_add(&g_fail, 1);
			continue;
		}
		memset(got, 0, sizeof(got));
		n = recv(g_shared_fd, got, sizeof(got), 0);
		if (n < 0) {
			atomic_fetch_add(&g_fail, 1);
			continue;
		}
		/* It need not be OUR datagram, but it must be a well-formed one
		 * that some thread sent -- not a fragment, not a header, not
		 * two datagrams run together. */
		if (sscanf(got, "shared-%ld-%ld", &rid, &rit) == 2 && rid >= 0 &&
		    rid < NTHREADS && rit >= 0 && rit < NITER)
			atomic_fetch_add(&g_ok, 1);
		else
			atomic_fetch_add(&g_cross, 1);
	}
	return NULL;
}

/* Phase 3: N threads race to be the first user of one fresh fd.  Establishment
 * is serialised per entry, so exactly one association must result -- two would
 * mean two control connections and a proxy that has pinned the association to
 * the wrong sender (FR-P-06). */
static int g_race_fd;
static pthread_barrier_t g_barrier;

static void *race_worker(void *arg)
{
	char buf[64];
	char msg[32];

	snprintf(msg, sizeof(msg), "race-%ld", (long)arg);
	pthread_barrier_wait(&g_barrier);

	/* sendto rather than send, because the socket is deliberately left
	 * unconnected: connect() establishes the association eagerly, which
	 * would settle the race before it started. */
	if (sendto(g_race_fd, msg, strlen(msg), 0, (struct sockaddr *)&g_echo,
	           sizeof(g_echo)) < 0) {
		atomic_fetch_add(&g_fail, 1);
		return NULL;
	}
	if (recv(g_race_fd, buf, sizeof(buf), 0) < 0)
		atomic_fetch_add(&g_fail, 1);
	else
		atomic_fetch_add(&g_ok, 1);
	return NULL;
}

int main(int argc, char **argv)
{
	pthread_t th[NTHREADS];
	long i;
	int baseline;

	if (argc < 2) {
		fprintf(stderr, "usage: test_thread <echoport>\n");
		return 2;
	}

	memset(&g_echo, 0, sizeof(g_echo));
	g_echo.sin_family = AF_INET;
	g_echo.sin_port = htons((uint16_t)atoi(argv[1]));
	inet_pton(AF_INET, "127.0.0.1", &g_echo.sin_addr);

	baseline = count_tcp_sockets();

	/* --- phase 1 ---------------------------------------------------- */
	TAP_GROUP("TST-07: threads on separate descriptors");
	atomic_store(&g_ok, 0);
	atomic_store(&g_fail, 0);
	atomic_store(&g_cross, 0);

	for (i = 0; i < NTHREADS; i++)
		pthread_create(&th[i], NULL, own_fd_worker, (void *)i);
	for (i = 0; i < NTHREADS; i++)
		pthread_join(th[i], NULL);

	TAP_EQ_INT(atomic_load(&g_ok), NTHREADS * NITER,
	           "%d threads x %d round-trips all succeed", NTHREADS, NITER);
	TAP_EQ_INT(atomic_load(&g_fail), 0, "no send or receive failures");
	TAP_EQ_INT(atomic_load(&g_cross), 0,
	           "no cross-delivery between separate associations");

	/* --- phase 2 ---------------------------------------------------- */
	TAP_GROUP("TST-07: threads sharing one descriptor");
	atomic_store(&g_ok, 0);
	atomic_store(&g_fail, 0);
	atomic_store(&g_cross, 0);

	g_shared_fd = udp4();
	if (connect(g_shared_fd, (struct sockaddr *)&g_echo, sizeof(g_echo)) != 0) {
		TAP_OK(0, "connect on the shared descriptor failed");
	} else {
		for (i = 0; i < NTHREADS; i++)
			pthread_create(&th[i], NULL, shared_fd_worker, (void *)i);
		for (i = 0; i < NTHREADS; i++)
			pthread_join(th[i], NULL);

		TAP_EQ_INT(atomic_load(&g_ok), NTHREADS * NITER,
		           "%d threads x %d round-trips on one fd all succeed",
		           NTHREADS, NITER);
		TAP_EQ_INT(atomic_load(&g_fail), 0, "no failures on the shared fd");
		TAP_EQ_INT(atomic_load(&g_cross), 0,
		           "every payload received was a well-formed sent one");
	}
	close(g_shared_fd);

	/* --- phase 3 ---------------------------------------------------- */
	TAP_GROUP("TST-07: concurrent first use of one fresh descriptor");
	atomic_store(&g_ok, 0);
	atomic_store(&g_fail, 0);

	g_race_fd = udp4();
	{
		/* Measured before any association exists for this fd. */
		int before = count_tcp_sockets();

		pthread_barrier_init(&g_barrier, NULL, NTHREADS);
		for (i = 0; i < NTHREADS; i++)
			pthread_create(&th[i], NULL, race_worker, (void *)i);
		for (i = 0; i < NTHREADS; i++)
			pthread_join(th[i], NULL);
		pthread_barrier_destroy(&g_barrier);

		TAP_EQ_INT(atomic_load(&g_fail), 0,
		           "no failures when %d threads race to establish",
		           NTHREADS);
		TAP_EQ_INT(count_tcp_sockets(), before + 1,
		           "exactly ONE association results from the race, not %d",
		           NTHREADS);
	}
	close(g_race_fd);

	/* --- leak check --------------------------------------------------- */
	TAP_GROUP("TST-07: no leaked associations");
	TAP_EQ_INT(count_tcp_sockets(), baseline,
	           "every association was released once its descriptor closed");

	TAP_DONE();
}

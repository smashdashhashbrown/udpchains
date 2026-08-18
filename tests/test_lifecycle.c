/* test_lifecycle.c -- TST-06, state and lifecycle (FR-L-01…FR-L-05, FR-I-04).
 *
 * Run under the shim:  udpchains ./test_lifecycle <echo1> <echo2>
 */
#include "tap.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

static struct sockaddr_in g_echo1, g_echo2;

static int udp4(void)
{
	struct timeval tv = { 3, 0 };
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (fd >= 0)
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return fd;
}

static int roundtrip(int fd, const char *what)
{
	char buf[64];
	ssize_t n;
	size_t len = strlen(what);

	if (send(fd, what, len, 0) != (ssize_t)len)
		return 0;
	memset(buf, 0, sizeof(buf));
	n = recv(fd, buf, sizeof(buf), 0);
	return n == (ssize_t)len && memcmp(buf, what, len) == 0;
}

/* Counts the TCP sockets this process holds.  In a test running under the shim
 * these are exactly the shim's control connections, so the count tracks live
 * associations -- which is how a leak becomes visible. */
static int count_tcp_sockets(int *missing_cloexec)
{
	DIR *d = opendir("/proc/self/fd");
	struct dirent *ent;
	int n = 0;

	if (missing_cloexec)
		*missing_cloexec = 0;
	if (d == NULL)
		return -1;

	while ((ent = readdir(d)) != NULL) {
		int fd, domain = 0, type = 0, flags;
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
		if (type != SOCK_STREAM)
			continue;
		if (domain != AF_INET && domain != AF_INET6)
			continue;

		n++;
		flags = fcntl(fd, F_GETFD);
		if (missing_cloexec && (flags < 0 || !(flags & FD_CLOEXEC)))
			(*missing_cloexec)++;
	}
	closedir(d);
	return n;
}

static void t_cloexec(void)
{
	int fd = udp4();
	int missing = -1, n;

	TAP_GROUP("FR-L-05: control-connection fds are FD_CLOEXEC");

	connect(fd, (struct sockaddr *)&g_echo1, sizeof(g_echo1));
	TAP_OK(roundtrip(fd, "cloexec"), "an association is established");

	n = count_tcp_sockets(&missing);
	TAP_OK(n >= 1, "at least one control connection exists (%d)", n);
	TAP_EQ_INT(missing, 0,
	           "every control connection has FD_CLOEXEC, so none leaks "
	           "into an exec-ed program");
	close(fd);
}

static void t_dup_shares(void)
{
	int fd, dupfd;

	TAP_GROUP("FR-L-03: dup shares one association across descriptors");

	fd = udp4();
	connect(fd, (struct sockaddr *)&g_echo1, sizeof(g_echo1));
	TAP_OK(roundtrip(fd, "before-dup"), "the original descriptor works");

	{
		int before = count_tcp_sockets(NULL);
		dupfd = dup(fd);
		TAP_OK(dupfd >= 0, "dup succeeds");
		TAP_EQ_INT(count_tcp_sockets(NULL), before,
		           "dup creates no second control connection: the "
		           "association is shared, not duplicated");
	}

	TAP_OK(roundtrip(dupfd, "via-dup"),
	       "the duplicated descriptor uses the shared association");

	/* The association must survive until the LAST descriptor closes. */
	close(fd);
	TAP_OK(roundtrip(dupfd, "after-orig-close"),
	       "closing the original leaves the duplicate working");

	close(dupfd);
}

static void t_dup2_replaces(void)
{
	int a, b;

	TAP_GROUP("FR-I-04: dup2 onto a live intercepted descriptor");

	a = udp4();
	b = udp4();
	connect(a, (struct sockaddr *)&g_echo1, sizeof(g_echo1));
	connect(b, (struct sockaddr *)&g_echo2, sizeof(g_echo2));
	TAP_OK(roundtrip(a, "a-before"), "descriptor a works");
	TAP_OK(roundtrip(b, "b-before"), "descriptor b works");

	/* dup2 implicitly closes b, so b's own state must be released and
	 * replaced by a's -- not merged with it. */
	TAP_EQ_INT(dup2(a, b), b, "dup2(a, b) returns b");
	TAP_OK(roundtrip(b, "b-after"),
	       "b now shares a's association and still round-trips");

	{
		struct sockaddr_in peer;
		socklen_t plen = sizeof(peer);
		getpeername(b, (struct sockaddr *)&peer, &plen);
		TAP_EQ_INT(ntohs(peer.sin_port), ntohs(g_echo1.sin_port),
		           "b's peer is now a's destination, not its own former one");
	}

	close(a);
	close(b);
}

static void t_fd_reuse(void)
{
	int fd, again;
	struct sockaddr_in peer;
	socklen_t plen = sizeof(peer);

	TAP_GROUP("FR-L-02: a reused fd number inherits no stale state");

	fd = udp4();
	connect(fd, (struct sockaddr *)&g_echo1, sizeof(g_echo1));
	TAP_OK(roundtrip(fd, "first-life"), "the first socket works");
	close(fd);

	/* The kernel hands out the lowest free descriptor, so this very often
	 * lands on the same number. */
	again = udp4();
	TAP_EQ_INT(again, fd, "a new socket lands on the same fd number");

	errno = 0;
	TAP_EQ_INT(getpeername(again, (struct sockaddr *)&peer, &plen), -1,
	           "getpeername on the fresh socket fails");
	TAP_EQ_INT(errno, ENOTCONN,
	           "with ENOTCONN: no stale destination was inherited");

	connect(again, (struct sockaddr *)&g_echo2, sizeof(g_echo2));
	TAP_OK(roundtrip(again, "second-life"),
	       "and it works against its own destination");
	close(again);
}

static void t_fork_isolation(void)
{
	int fd;
	pid_t pid;
	int status = 0;
	int before;

	TAP_GROUP("FR-L-04: a forked child does not share the parent's association");

	fd = udp4();
	connect(fd, (struct sockaddr *)&g_echo1, sizeof(g_echo1));
	TAP_OK(roundtrip(fd, "parent-pre-fork"), "the parent's socket works");
	before = count_tcp_sockets(NULL);

	pid = fork();
	if (pid == 0) {
		/* The child inherited the descriptor and the control
		 * connection.  Using it must establish a fresh association
		 * rather than sharing the parent's. */
		int ok = roundtrip(fd, "child-after-fork");
		_exit(ok ? 0 : 1);
	}

	TAP_OK(pid > 0, "fork succeeds");
	waitpid(pid, &status, 0);
	TAP_OK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	       "the child round-trips using its own association");

	/* Tearing down the inherited copy in the child must not disturb the
	 * parent: the parent holds its own descriptor reference. */
	TAP_OK(roundtrip(fd, "parent-post-fork"),
	       "the parent's association still works after the child exits");
	TAP_EQ_INT(count_tcp_sockets(NULL), before,
	           "the parent gained no control connections");
	close(fd);
}

static void t_close_releases(void)
{
	int i, before, after;

	TAP_GROUP("FR-P-02: closing the socket closes the control connection");

	before = count_tcp_sockets(NULL);

	for (i = 0; i < 8; i++) {
		int fd = udp4();
		connect(fd, (struct sockaddr *)&g_echo1, sizeof(g_echo1));
		roundtrip(fd, "churn");
		close(fd);
	}

	after = count_tcp_sockets(NULL);
	TAP_EQ_INT(after, before,
	           "eight open/associate/close cycles leak no control "
	           "connections");
}

#ifdef __linux__
static void t_close_range(void)
{
	int fds[4];
	int i, before;

	TAP_GROUP("FR-I-04: close_range releases the state it closes");

	before = count_tcp_sockets(NULL);
	for (i = 0; i < 4; i++) {
		fds[i] = udp4();
		connect(fds[i], (struct sockaddr *)&g_echo1, sizeof(g_echo1));
		roundtrip(fds[i], "cr");
	}
	TAP_OK(count_tcp_sockets(NULL) > before,
	       "four associations are live");

	/* The four descriptors are not necessarily contiguous, so close each
	 * as its own single-element range. */
	for (i = 0; i < 4; i++) {
		if (close_range((unsigned)fds[i], (unsigned)fds[i], 0) != 0) {
			TAP_OK(0, "close_range failed: %s", strerror(errno));
			return;
		}
	}
	TAP_EQ_INT(count_tcp_sockets(NULL), before,
	           "close_range released every association it closed");
}
#endif

int main(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr, "usage: test_lifecycle <echo1> <echo2>\n");
		return 2;
	}

	memset(&g_echo1, 0, sizeof(g_echo1));
	g_echo1.sin_family = AF_INET;
	g_echo1.sin_port = htons((uint16_t)atoi(argv[1]));
	inet_pton(AF_INET, "127.0.0.1", &g_echo1.sin_addr);

	memset(&g_echo2, 0, sizeof(g_echo2));
	g_echo2.sin_family = AF_INET;
	g_echo2.sin_port = htons((uint16_t)atoi(argv[2]));
	inet_pton(AF_INET, "127.0.0.1", &g_echo2.sin_addr);

	t_cloexec();
	t_dup_shares();
	t_dup2_replaces();
	t_fd_reuse();
	t_fork_isolation();
	t_close_releases();
#ifdef __linux__
	t_close_range();
#endif

	TAP_DONE();
}

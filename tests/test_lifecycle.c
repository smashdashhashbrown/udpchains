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

static void t_fcntl_dup_shares(void)
{
	int fd, copy, before;

	TAP_GROUP("FR-L-03: fcntl(F_DUPFD_CLOEXEC) shares the association like dup");

	fd = udp4();
	connect(fd, (struct sockaddr *)&g_echo1, sizeof(g_echo1));
	TAP_OK(roundtrip(fd, "before-fcntl"), "the original descriptor works");

	before = count_tcp_sockets(NULL);
	copy = fcntl(fd, F_DUPFD_CLOEXEC, 100);
	TAP_OK(copy >= 100, "the minimum-descriptor argument is forwarded (%d)",
	       copy);
	TAP_EQ_INT(count_tcp_sockets(NULL), before,
	           "the copy creates no second control connection");

	/* An untracked copy would send the bare payload to the relay, which
	 * drops it, so this round trip only succeeds if the copy is proxied. */
	close(fd);
	TAP_OK(roundtrip(copy, "via-fcntl-copy"),
	       "the copy is proxied through the shared association");
	close(copy);
}

static void t_dup2_failure_keeps_tracking(void)
{
	int fd;
	struct sockaddr_in peer;
	socklen_t plen = sizeof(peer);

	TAP_GROUP("SEC-01: a failed dup2 leaves its target tracked");

	fd = udp4();
	connect(fd, (struct sockaddr *)&g_echo1, sizeof(g_echo1));
	TAP_OK(roundtrip(fd, "before-bad-dup2"), "the descriptor works");

	errno = 0;
	TAP_OK(dup2(-1, fd) < 0 && errno == EBADF,
	       "dup2 from a bad descriptor fails with EBADF");
	TAP_OK(roundtrip(fd, "after-bad-dup2"),
	       "the target is still proxied, not released by the failed call");
	memset(&peer, 0, sizeof(peer));
	getpeername(fd, (struct sockaddr *)&peer, &plen);
	TAP_EQ_INT(ntohs(peer.sin_port), ntohs(g_echo1.sin_port),
	           "getpeername still reports the application's destination");
	close(fd);
}

static void t_dup2_pipe_onto_udp(void)
{
	int fd, p[2];
	char buf[8] = { 0 };

	TAP_GROUP("FR-I-04: dup2 of a non-socket onto an intercepted descriptor");

	fd = udp4();
	connect(fd, (struct sockaddr *)&g_echo1, sizeof(g_echo1));
	TAP_OK(roundtrip(fd, "before-pipe"), "the descriptor works");
	TAP_OK(pipe(p) == 0, "pipe created");

	TAP_EQ_INT(dup2(p[1], fd), fd, "dup2(pipe, fd) returns fd");
	TAP_EQ_INT(write(fd, "pipe", 4), 4,
	           "a write to fd now reaches the pipe, not the proxy path");
	TAP_EQ_INT(read(p[0], buf, sizeof(buf)), 4, "the pipe received it");
	TAP_EQ_MEM(buf, "pipe", 4, "unaltered: no SOCKS header was added");

	close(fd);
	close(p[0]);
	close(p[1]);
}

/* Sends fd across a unix socket pair to ourselves; returns what arrives. */
static int pass_fd(int fd)
{
	int sv[2], got = -1;
	char byte = 0;
	union {
		struct cmsghdr align;
		char buf[CMSG_SPACE(sizeof(int))];
	} ctl;
	struct iovec v = { &byte, 1 };
	struct msghdr m;
	struct cmsghdr *c;

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0)
		return -1;

	/* Zeroed so the CMSG_SPACE padding the kernel copies is initialised. */
	memset(&ctl, 0, sizeof(ctl));
	memset(&m, 0, sizeof(m));
	m.msg_iov = &v;
	m.msg_iovlen = 1;
	m.msg_control = ctl.buf;
	m.msg_controllen = sizeof(ctl.buf);
	c = CMSG_FIRSTHDR(&m);
	c->cmsg_level = SOL_SOCKET;
	c->cmsg_type = SCM_RIGHTS;
	c->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(c), &fd, sizeof(int));

	if (sendmsg(sv[0], &m, 0) == 1) {
		m.msg_controllen = sizeof(ctl.buf);
		if (recvmsg(sv[1], &m, 0) == 1 &&
		    (c = CMSG_FIRSTHDR(&m)) != NULL && c->cmsg_type == SCM_RIGHTS)
			memcpy(&got, CMSG_DATA(c), sizeof(int));
	}
	close(sv[0]);
	close(sv[1]);
	return got;
}

static void t_scm_rights_adopted(void)
{
	int fd, got, before;

	TAP_GROUP("SEC-01: a UDP socket received over SCM_RIGHTS is adopted");

	fd = udp4();
	got = pass_fd(fd);
	TAP_OK(got >= 0 && got != fd, "a new descriptor arrives (%d)", got);

	/* The hand-off pattern: the sender keeps no copy. */
	close(fd);

	/* An unadopted socket would round-trip too -- directly.  A new control
	 * connection is what shows the traffic took the proxy. */
	before = count_tcp_sockets(NULL);
	connect(got, (struct sockaddr *)&g_echo1, sizeof(g_echo1));
	TAP_OK(roundtrip(got, "via-scm-rights"),
	       "the received socket round-trips");
	TAP_EQ_INT(count_tcp_sockets(NULL), before + 1,
	           "and it did so through its own association");
	close(got);
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
	t_fcntl_dup_shares();
	t_dup2_failure_keeps_tracking();
	t_dup2_pipe_onto_udp();
	t_scm_rights_adopted();
	t_fd_reuse();
	t_fork_isolation();
	t_close_releases();
#ifdef __linux__
	t_close_range();
#endif

	TAP_DONE();
}

/* test_supervise.c -- supervisor mode (D-48 to D-53).
 *
 * Built -static, so it is the kind of program supervisor mode exists for: the
 * shim could not see a single call it makes.  Each mode is run by
 * tests/test_supervise.sh.
 *
 *   test_supervise refusals <tcp port>   under the supervisor: what is refused,
 *                                        and that what is not still works
 *   test_supervise range <echo port>     under the supervisor: UDP sockets in
 *                                        the reserved range, the dup family,
 *                                        names, and receives that wait
 *   test_supervise nodump <tcp port>     under the supervisor: a process that
 *                                        makes itself non-dumpable fails
 *                                        closed, and files still work
 *   test_supervise churn <echo port> <n> <secs>
 *                                        under the supervisor: n sockets, each
 *                                        used and closed, then a pause in
 *                                        which the supervisor should let go
 *                                        of their associations
 *   test_supervise pass <path> <port>    NOT supervised: listens on a Unix
 *                                        socket at <path>, and hands the first
 *                                        client a UDP socket connected to
 *                                        127.0.0.1:<port>, as an unsupervised
 *                                        process passing a socket would
 *   test_supervise received <path>       under the supervisor: takes that
 *                                        socket, and tries to send on it
 */
#include "tap.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef AF_PACKET
#define AF_PACKET 17
#endif

/* D-50: the reserved range starts here, with the usual soft limit of 1024. */
#define RANGE 768

/* -1 and the errno, or the result: what a TAP check compares. */
static int fails_with(long rc, int err)
{
	return rc == -1 && errno == err;
}

static struct sockaddr_in loopback(int port)
{
	struct sockaddr_in a;

	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_port = htons((uint16_t)port);
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	return a;
}

/* An i386 system call from this 64-bit program: getpid, number 20 there. */
static long int80_getpid(void)
{
#if defined(__x86_64__)
	long ret;

	__asm__ volatile("int $0x80" : "=a"(ret) : "a"(20L) : "memory");
	return ret;
#else
	return -ENOSYS;
#endif
}

static int refusals(int tcp_port)
{
	struct sockaddr_in a = loopback(tcp_port);
	unsigned char params[120];
	int fd, pidfd;
	long rc;

	TAP_GROUP("a UDP socket is made in the reserved range (D-50)");
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	TAP_OK(fd >= RANGE, "socket(AF_INET, SOCK_DGRAM) is made, at fd %d", fd);
	close(fd);
	fd = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	TAP_OK(fd >= RANGE && (fcntl(fd, F_GETFL) & O_NONBLOCK) &&
	               (fcntl(fd, F_GETFD) & FD_CLOEXEC),
	       "AF_INET6, keeping SOCK_NONBLOCK and SOCK_CLOEXEC");
	close(fd);
	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	TAP_OK(fd >= RANGE, "and with IPPROTO_UDP named");
	close(fd);

	TAP_GROUP("sockets SOCKS5 cannot carry are refused (D-29, D-36)");
	errno = 0;
	TAP_OK(fails_with(socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP), EPROTONOSUPPORT),
	       "an ICMP datagram socket: EPROTONOSUPPORT (%s)", strerror(errno));
	TAP_OK(fails_with(socket(AF_INET, SOCK_RAW, IPPROTO_UDP), EPERM),
	       "a raw socket: EPERM");
	TAP_OK(fails_with(socket(AF_PACKET, SOCK_DGRAM, 0), EPERM), "a packet socket: EPERM");

	TAP_GROUP("routes around the supervisor are refused (D-53)");
	memset(params, 0, sizeof(params));
	TAP_OK(fails_with(syscall(SYS_io_uring_setup, 1, params), ENOSYS),
	       "io_uring_setup: ENOSYS");
	pidfd = (int)syscall(SYS_pidfd_open, getpid(), 0);
	TAP_OK(pidfd >= 0, "pidfd_open itself is not refused");
	TAP_OK(fails_with(syscall(SYS_pidfd_getfd, pidfd, 1, 0), EPERM),
	       "pidfd_getfd: EPERM");
	close(pidfd);

	TAP_GROUP("one ABI (D-48)");
#if defined(__x86_64__)
	TAP_OK(fails_with(syscall(SYS_getpid | 0x40000000), ENOSYS),
	       "an x32 call fails with ENOSYS");
	rc = int80_getpid();
	TAP_EQ_INT((int)rc, -ENOSYS, "a 32-bit int $0x80 call fails with ENOSYS");
#else
	TAP_OK(1, "# SKIP not x86-64");
	TAP_OK(1, "# SKIP not x86-64");
#endif

	TAP_GROUP("everything else runs: TCP, Unix sockets, files");
	fd = socket(AF_INET, SOCK_STREAM, 0);
	TAP_OK(fd >= 0, "a TCP socket is made");
	TAP_EQ_INT(connect(fd, (struct sockaddr *)&a, sizeof(a)), 0,
	           "and connects, checked and let through");
	TAP_EQ_INT((int)send(fd, "x", 1, MSG_NOSIGNAL), 1, "send() on it");
	{
		struct iovec iov = { (void *)(uintptr_t)"y", 1 };
		struct msghdr mh = { 0 };

		mh.msg_iov = &iov;
		mh.msg_iovlen = 1;
		TAP_EQ_INT((int)sendmsg(fd, &mh, MSG_NOSIGNAL), 1, "sendmsg() on it");
	}
	close(fd);
	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	TAP_OK(fd >= 0, "a Unix datagram socket is made");
	close(fd);
	fd = open("/dev/null", O_WRONLY);
	TAP_EQ_INT((int)write(fd, "z", 1), 1, "a file is written");
	close(fd);
	TAP_EQ_INT((int)getpid(), (int)syscall(SYS_getpid), "getpid() agrees with itself");
	TAP_DONE();
}

/* --- range -----------------------------------------------------------------*/

static struct sockaddr_in g_echo;

/* Sends what on fd to the echo server, and reads the reply on rfd. */
static int round_trip(int fd, int rfd, const char *what)
{
	char back[64];
	ssize_t n;

	if (sendto(fd, what, strlen(what), 0, (struct sockaddr *)&g_echo, sizeof(g_echo)) !=
	    (ssize_t)strlen(what))
		return 0;
	memset(back, 0, sizeof(back));
	n = recv(rfd, back, sizeof(back), 0);
	return n == (ssize_t)strlen(what) && memcmp(back, what, (size_t)n) == 0;
}

static int udp_timed(int ms)
{
	struct timeval tv = { ms / 1000, (ms % 1000) * 1000 };
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (fd >= 0)
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return fd;
}

static long elapsed_ms(const struct timespec *t0)
{
	struct timespec t1;

	clock_gettime(CLOCK_MONOTONIC, &t1);
	return (t1.tv_sec - t0->tv_sec) * 1000 + (t1.tv_nsec - t0->tv_nsec) / 1000000;
}

static void on_alarm(int sig)
{
	(void)sig;
}

static int range(int echo_port)
{
	struct sockaddr_in local, peer;
	socklen_t len;
	struct timespec t0;
	char buf[9000];
	int fd, fd2, d, st;
	pid_t pid;

	g_echo = loopback(echo_port);

	TAP_GROUP("sockets in the range, numbered as the kernel would there (D-50)");
	fd = udp_timed(5000);
	fd2 = udp_timed(5000);
	TAP_EQ_INT(fd, RANGE, "the first UDP socket is the range's first number");
	TAP_EQ_INT(fd2, RANGE + 1, "the second, the next");
	TAP_OK(round_trip(fd, fd, "one"), "each round-trips through the proxy");
	TAP_OK(round_trip(fd2, fd2, "two"), "the second as well, independently");
	close(fd);
	d = udp_timed(5000);
	TAP_EQ_INT(d, RANGE, "a closed number is given out again");
	fd = d;

	TAP_GROUP("the dup family keeps the socket in the range (FR-SV-04)");
	d = dup(fd);
	TAP_OK(d >= RANGE && d != fd, "dup() is placed in the range, at fd %d", d);
	TAP_OK(round_trip(d, fd, "dup"), "and is the same socket: sent on one, received "
	                                 "on the other");
	close(d);
	d = fcntl(fd, F_DUPFD, 3);
	TAP_OK(d >= RANGE, "fcntl(F_DUPFD, 3) is placed in the range too, at fd %d", d);
	close(d);
	d = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	TAP_OK(d >= RANGE && (fcntl(d, F_GETFD) & FD_CLOEXEC),
	       "F_DUPFD_CLOEXEC: in the range, close-on-exec");
	close(d);
	TAP_OK(fails_with(dup2(fd, 50), EPERM), "dup2() below the range: EPERM");
	TAP_OK(fails_with(dup3(fd, 51, 0), EPERM), "dup3() below the range: EPERM");
	TAP_OK(fcntl(50, F_GETFD) == -1, "and nothing was put there");
	d = dup2(fd, 900);
	TAP_EQ_INT(d, 900, "dup2() to a number in the range works");
	TAP_OK(round_trip(900, fd, "dup2"), "and carries");
	close(900);

	TAP_GROUP("names are what the program believes (FR-I-05)");
	close(fd2);
	fd2 = udp_timed(5000);
	local = loopback(0);
	TAP_EQ_INT(bind(fd2, (struct sockaddr *)&local, sizeof(local)), 0,
	           "bind() to 127.0.0.1, port 0");
	len = sizeof(local);
	memset(&local, 0, sizeof(local));
	TAP_OK(getsockname(fd2, (struct sockaddr *)&local, &len) == 0 &&
	               local.sin_addr.s_addr == htonl(INADDR_LOOPBACK) && local.sin_port != 0,
	       "getsockname() reports it, with the port the kernel chose");
	TAP_OK(fails_with(getpeername(fd2, (struct sockaddr *)&peer, &len), ENOTCONN),
	       "getpeername() unconnected: ENOTCONN");
	TAP_EQ_INT(connect(fd2, (struct sockaddr *)&g_echo, sizeof(g_echo)), 0, "connect()");
	len = sizeof(peer);
	TAP_OK(getpeername(fd2, (struct sockaddr *)&peer, &len) == 0 &&
	               peer.sin_port == g_echo.sin_port,
	       "getpeername() reports the destination, not the relay");
	TAP_EQ_INT((int)send(fd2, "conn", 4, 0), 4, "send() on the connected socket");
	memset(buf, 0, sizeof(buf));
	TAP_OK(read(fd2, buf, sizeof(buf)) == 4 && memcmp(buf, "conn", 4) == 0,
	       "read() gets the reply");
	close(fd2);

	TAP_GROUP("what cannot be sent is refused, as in shim mode");
	TAP_OK(fails_with(send(fd, "x", 1, MSG_MORE), EOPNOTSUPP), "MSG_MORE: EOPNOTSUPP");
	peer = g_echo;
	peer.sin_addr.s_addr = htonl(0xe0000001); /* 224.0.0.1 */
	TAP_OK(fails_with(sendto(fd, "x", 1, 0, (struct sockaddr *)&peer, sizeof(peer)),
	                  ENETUNREACH),
	       "multicast: ENETUNREACH");
	memset(buf, 'x', sizeof(buf));
	TAP_OK(fails_with(sendto(fd, buf, 8193, 0, (struct sockaddr *)&g_echo, sizeof(g_echo)),
	                  EMSGSIZE),
	       "more than max_datagram: EMSGSIZE");
	TAP_OK(fails_with(send(fd, "x", 1, 0), EDESTADDRREQ),
	       "send() unconnected: EDESTADDRREQ");
	TAP_OK(fails_with(pread(fd, buf, 1, 0), ESPIPE), "pread(): ESPIPE, as on any socket");
	TAP_OK(fails_with(sendto(fd, "x", 1, 0, (struct sockaddr *)&g_echo, 3), EINVAL),
	       "a short address: EINVAL");

	TAP_GROUP("receives that wait (D-51)");
	clock_gettime(CLOCK_MONOTONIC, &t0);
	TAP_OK(fails_with(recv(fd, buf, sizeof(buf), MSG_DONTWAIT), EAGAIN) &&
	               elapsed_ms(&t0) < 200,
	       "MSG_DONTWAIT with nothing queued: EAGAIN at once");
	fcntl(fd, F_SETFL, O_NONBLOCK);
	TAP_OK(fails_with(recv(fd, buf, sizeof(buf), 0), EAGAIN), "O_NONBLOCK: EAGAIN");
	fcntl(fd, F_SETFL, 0);
	d = udp_timed(300);
	clock_gettime(CLOCK_MONOTONIC, &t0);
	TAP_OK(fails_with(recv(d, buf, sizeof(buf), 0), EAGAIN) && elapsed_ms(&t0) >= 250 &&
	               elapsed_ms(&t0) < 2000,
	       "SO_RCVTIMEO of 300 ms: EAGAIN after %ld ms", elapsed_ms(&t0));
	close(d);
	{
		struct sigaction sa;

		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = on_alarm; /* no SA_RESTART */
		sigaction(SIGALRM, &sa, NULL);
		d = udp_timed(0);
		alarm(1);
		TAP_OK(fails_with(recv(d, buf, sizeof(buf), 0), EINTR),
		       "a signal interrupts a blocking receive: EINTR");
		alarm(0);
		TAP_OK(round_trip(d, d, "after"), "and the socket still works after");
		close(d);
	}
	{
		struct pollfd p = { fd, POLLIN, 0 };

		sendto(fd, "poll", 4, 0, (struct sockaddr *)&g_echo, sizeof(g_echo));
		TAP_OK(poll(&p, 1, 5000) == 1 && (p.revents & POLLIN),
		       "poll() sees the reply arrive on the program's own socket");
		memset(buf, 0, sizeof(buf));
		TAP_OK(recv(fd, buf, sizeof(buf), 0) == 4 && memcmp(buf, "poll", 4) == 0,
		       "and the receive returns it, unwrapped");
	}

	TAP_GROUP("a socket inherited across fork is the same socket");
	pid = fork();
	if (pid == 0)
		_exit(sendto(fd, "fork", 4, 0, (struct sockaddr *)&g_echo, sizeof(g_echo)) == 4
		              ? 0
		              : 1);
	TAP_OK(waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0,
	       "the child sends on it");
	memset(buf, 0, sizeof(buf));
	TAP_OK(recv(fd, buf, sizeof(buf), 0) == 4 && memcmp(buf, "fork", 4) == 0,
	       "and the parent receives the reply");
	/* The parent lets go first, as a daemon does: the supervisor must not
	 * forget a socket a child still holds when it looks for closed ones. */
	pid = fork();
	if (pid == 0) {
		usleep(800 * 1000);
		_exit(round_trip(fd, fd, "orphan") ? 0 : 1);
	}
	close(fd);
	TAP_OK(waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0,
	       "a child still using the socket after the parent closed it is carried");
	TAP_DONE();
}

/* D-48: the supervisor cannot inspect a non-dumpable process, so what needs
 * inspecting is refused rather than let through unchecked. */
static int nodump(int tcp_port)
{
	struct sockaddr_in a = loopback(tcp_port);
	int fd, p[2];

	TAP_GROUP("a process that makes itself non-dumpable fails closed (D-48)");
	TAP_EQ_INT(prctl(PR_SET_DUMPABLE, 0, 0, 0, 0), 0, "prctl(PR_SET_DUMPABLE, 0)");
	fd = socket(AF_INET, SOCK_STREAM, 0);
	TAP_OK(fd >= 0, "a TCP socket is still made: socket() needs no inspecting");
	TAP_OK(fails_with(connect(fd, (struct sockaddr *)&a, sizeof(a)), EPERM),
	       "but its connect() is refused: EPERM");
	close(fd);
	TAP_OK(fails_with(socket(AF_INET, SOCK_DGRAM, 0), EPERM),
	       "a UDP socket cannot be placed in the range: EPERM");
	fd = open("/dev/null", O_WRONLY);
	TAP_EQ_INT((int)write(fd, "z", 1), 1, "a file is still written");
	close(fd);
	TAP_OK(pipe(p) == 0 && write(p[1], "q", 1) == 1, "and a pipe");
	TAP_DONE();
}

static int churn(int echo_port, int n, int secs)
{
	int i, ok = 0;

	g_echo = loopback(echo_port);
	for (i = 0; i < n; i++) {
		int fd = udp_timed(5000);

		ok += fd >= 0 && round_trip(fd, fd, "churn");
		close(fd);
	}
	printf("CHURNED %d of %d\n", ok, n);
	fflush(stdout);
	sleep((unsigned)secs);
	return ok == n ? 0 : 1;
}

static int listen_unix(const char *path)
{
	struct sockaddr_un sun;
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", path);
	unlink(path);
	if (fd < 0 || bind(fd, (struct sockaddr *)&sun, sizeof(sun)) != 0 ||
	    listen(fd, 1) != 0)
		return -1;
	return fd;
}

static int pass(const char *path, int port)
{
	struct sockaddr_in a = loopback(port);
	int lfd = listen_unix(path), cfd, udp;
	char cbuf[CMSG_SPACE(sizeof(int))];
	struct iovec iov = { (void *)(uintptr_t)"S", 1 };
	struct msghdr mh = { 0 };
	struct cmsghdr *c;

	if (lfd < 0) {
		perror("pass: listen");
		return 2;
	}
	printf("READY\n");
	fflush(stdout);
	cfd = accept(lfd, NULL, NULL);
	udp = socket(AF_INET, SOCK_DGRAM, 0);
	/* Connected before it is passed: the case D-50 cannot fully close. */
	if (cfd < 0 || udp < 0 || connect(udp, (struct sockaddr *)&a, sizeof(a)) != 0) {
		perror("pass");
		return 2;
	}
	memset(cbuf, 0, sizeof(cbuf));
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	mh.msg_control = cbuf;
	mh.msg_controllen = sizeof(cbuf);
	c = CMSG_FIRSTHDR(&mh);
	c->cmsg_level = SOL_SOCKET;
	c->cmsg_type = SCM_RIGHTS;
	c->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(c), &udp, sizeof(int));
	if (sendmsg(cfd, &mh, 0) != 1) {
		perror("pass: sendmsg");
		return 2;
	}
	close(cfd);
	close(lfd);
	unlink(path);
	return 0;
}

static int received(const char *path)
{
	struct sockaddr_un sun;
	char cbuf[CMSG_SPACE(sizeof(int))], b;
	struct iovec iov = { &b, 1 };
	struct msghdr mh = { 0 };
	struct cmsghdr *c;
	struct sockaddr_in a = loopback(9);
	int ufd = socket(AF_UNIX, SOCK_STREAM, 0), fd = -1, type = 0, p[2];
	socklen_t len = sizeof(type);

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", path);
	TAP_GROUP("a UDP socket received from an unsupervised process (D-50)");
	TAP_EQ_INT(connect(ufd, (struct sockaddr *)&sun, sizeof(sun)), 0,
	           "the Unix socket connects");
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	mh.msg_control = cbuf;
	mh.msg_controllen = sizeof(cbuf);
	TAP_EQ_INT((int)recvmsg(ufd, &mh, 0), 1, "and a descriptor arrives");
	c = CMSG_FIRSTHDR(&mh);
	if (c != NULL && c->cmsg_type == SCM_RIGHTS)
		memcpy(&fd, CMSG_DATA(c), sizeof(int));
	TAP_OK(fd >= 0 && getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len) == 0 &&
	           type == SOCK_DGRAM,
	       "a UDP socket");

	TAP_OK(fails_with(sendto(fd, "a", 1, 0, (struct sockaddr *)&a, sizeof(a)), EPERM),
	       "sendto() on it: EPERM");
	TAP_OK(fails_with(send(fd, "a", 1, 0), EPERM), "send() on it, which is sendto(): EPERM");
	{
		struct iovec v = { (void *)(uintptr_t)"a", 1 };
		struct msghdr m = { 0 };
		struct mmsghdr mm;

		m.msg_iov = &v;
		m.msg_iovlen = 1;
		TAP_OK(fails_with(sendmsg(fd, &m, 0), EPERM), "sendmsg(): EPERM");
		memset(&mm, 0, sizeof(mm));
		mm.msg_hdr = m;
		TAP_OK(fails_with(sendmmsg(fd, &mm, 1, 0), EPERM), "sendmmsg(): EPERM");
	}
	TAP_OK(fails_with(connect(fd, (struct sockaddr *)&a, sizeof(a)), EPERM),
	       "connect() on it: EPERM");
	{
		int src = open("/proc/self/stat", O_RDONLY);

		TAP_OK(fails_with(sendfile(fd, src, NULL, 1), EINVAL), "sendfile() onto it: EINVAL");
		close(src);
	}
	if (pipe(p) == 0) {
		ssize_t w = write(p[1], "s", 1);

		TAP_OK(w == 1 && fails_with(splice(p[0], NULL, fd, NULL, 1, 0), EINVAL),
		       "splice() onto it: EINVAL");
		close(p[0]);
		close(p[1]);
	}
	/* D-50's documented gap: write() is not trapped outside the range, so
	 * a socket passed already connected still sends with it.  Reported,
	 * not asserted. */
	printf("# known gap (D-50): write() on the received, connected socket returned %d\n",
	       (int)write(fd, "w", 1));
	close(fd);
	close(ufd);
	TAP_DONE();
}

int main(int argc, char **argv)
{
	if (argc == 3 && strcmp(argv[1], "refusals") == 0)
		return refusals(atoi(argv[2]));
	if (argc == 3 && strcmp(argv[1], "range") == 0)
		return range(atoi(argv[2]));
	if (argc == 3 && strcmp(argv[1], "nodump") == 0)
		return nodump(atoi(argv[2]));
	if (argc == 5 && strcmp(argv[1], "churn") == 0)
		return churn(atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));
	if (argc == 4 && strcmp(argv[1], "pass") == 0)
		return pass(argv[2], atoi(argv[3]));
	if (argc == 3 && strcmp(argv[1], "received") == 0)
		return received(argv[2]);
	fprintf(stderr, "usage: test_supervise refusals <tcp port> | range <echo port> | "
	                "nodump <tcp port> | churn <echo port> <n> <secs> | "
	                "pass <path> <port> | "
	                "received <path>\n");
	return 2;
}

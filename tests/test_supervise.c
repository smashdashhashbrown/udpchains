/* test_supervise.c -- supervisor mode (D-48 to D-54).
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
 *   test_supervise signals <delayed echo port> <echo port>
 *                                        under the supervisor: receives
 *                                        interrupted by a storm of signals,
 *                                        with and without SA_RESTART, lose no
 *                                        datagram, sends are never repeated,
 *                                        and closes never left undone
 *                                        (FR-SV-T4, D-54)
 *   test_supervise silent                NOT supervised: a TCP listener that
 *                                        never answers, as a proxy that hangs
 *                                        in the handshake
 *   test_supervise abandon <echo port>   under the supervisor, with the silent
 *                                        proxy: a signal arriving while the
 *                                        association is set up is handled at
 *                                        once, and the send made again (D-54)
 *   test_supervise lifecycle <echo port> under the supervisor: threads, a thread
 *                                        with its own descriptor table,
 *                                        clone(CLONE_FILES), close_range,
 *                                        posix_spawn and exec, from the first
 *                                        thread and another (FR-SV-11, T3);
 *                                        runs itself again as "execed"
 *   test_supervise dns <dnsd port>       under the supervisor, with dns set to
 *                                        dnsd: queries to the system resolver
 *                                        reach it, and port 53 elsewhere and TCP
 *                                        to the resolver do not (D-52)
 *   test_supervise nodns                 under the supervisor, no dns: queries
 *                                        to the system resolver fail
 *   test_supervise threadexit            under the supervisor: two threads make
 *                                        and close sockets, and exit before
 *                                        the program does
 *   test_supervise spray <ip> <port> <secs>
 *                                        a datagram every 5 ms, for the wire
 *                                        capture: a line per one sent
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
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <spawn.h>
#include <linux/close_range.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
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

/* --- signals ---------------------------------------------------------------*/

static volatile sig_atomic_t g_signals;

static void count_signal(int sig)
{
	(void)sig;
	g_signals++;
}

/* SIGALRM every us microseconds, handled with or without SA_RESTART; 0 stops
 * it. */
static void storm(int us, int restart)
{
	struct itimerval it = { { 0, us }, { 0, us } };
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = count_signal;
	sa.sa_flags = restart ? SA_RESTART : 0;
	sigaction(SIGALRM, &sa, NULL);
	setitimer(ITIMER_REAL, &it, NULL);
}

struct tally {
	int lost, dups, recv_eintr, send_eintr;
};

/* The far end of a TCP connection, read until it closes. */
static int g_tcp_peer;

static void *drain_tcp(void *arg)
{
	char buf[4096];

	(void)arg;
	while (read(g_tcp_peer, buf, sizeof(buf)) > 0)
		;
	return NULL;
}

/* Waits, up to two seconds, until pid sleeps in a call: a child's receive
 * waiting for its datagram, rather than one still being set up, which its
 * thread spends stopped for the supervisor. */
static void wait_sleeping(pid_t pid)
{
	char path[64], buf[256], *close_paren;
	int i;

	snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
	for (i = 0; i < 2000; i++) {
		FILE *f = fopen(path, "re");
		size_t n = f != NULL ? fread(buf, 1, sizeof(buf) - 1, f) : 0;

		if (f != NULL)
			fclose(f);
		buf[n] = '\0';
		close_paren = strrchr(buf, ')');
		if (close_paren != NULL && close_paren[1] == ' ' && close_paren[2] == 'S')
			return;
		usleep(1000);
	}
}

/* n numbered datagrams through the delayed echo, one at a time, each waited
 * for in a blocking receive while the signals arrive.  A datagram that never
 * comes back is lost: the receive times out (SO_RCVTIMEO) or, with no
 * timeout, the test hangs and its caller's timeout fails it. */
static struct tally ping_pong(int fd, int n)
{
	struct tally t = { 0, 0, 0, 0 };
	uint32_t i, got;

	for (i = 0; i < (uint32_t)n; i++) {
		ssize_t r;

		/* An interrupted send may have gone already; sent again, it
		 * comes back twice, counted as a duplicate (D-48). */
		while ((r = sendto(fd, &i, sizeof(i), 0, (struct sockaddr *)&g_echo,
		                   sizeof(g_echo))) < 0 &&
		       errno == EINTR)
			t.send_eintr++;
		if (r != (ssize_t)sizeof(i)) {
			t.lost++;
			continue;
		}
		for (;;) {
			r = recv(fd, &got, sizeof(got), 0);
			if (r < 0 && errno == EINTR) {
				t.recv_eintr++;
				continue;
			}
			if (r != (ssize_t)sizeof(got) || got > i) {
				t.lost++;
				break;
			}
			if (got == i)
				break;
			t.dups++; /* an earlier one, again */
		}
	}
	return t;
}

static int signals(int delayed_port, int echo_port)
{
	struct timespec t0;
	struct tally t;
	char buf[16];
	int fd, st;
	pid_t pid;

	g_echo = loopback(delayed_port);

	TAP_GROUP("FR-SV-T4: receives interrupted without SA_RESTART lose nothing");
	fd = udp_timed(3000);
	g_signals = 0;
	storm(2000, 0);
	t = ping_pong(fd, 100);
	storm(0, 0);
	TAP_EQ_INT(t.lost, 0, "100 datagrams, each waited for 10 ms under a signal every 2 ms: "
	                      "none lost");
	TAP_OK(t.recv_eintr > 0, "the waiting receives were interrupted: %d EINTR, %d signals",
	       t.recv_eintr, (int)g_signals);
	/* D-54: a send is performed while its thread is stopped, so it
	 * cannot report EINTR after its datagram has gone, and be sent
	 * again. */
	TAP_EQ_INT(t.send_eintr, 0, "no send failed with EINTR, which a UDP send never does");
	TAP_EQ_INT(t.dups, 0, "and none came back twice");
	close(fd);

	TAP_GROUP("FR-SV-T4: receives restarted by SA_RESTART lose nothing");
	fd = udp_timed(0);
	g_signals = 0;
	storm(2000, 1);
	t = ping_pong(fd, 100);
	storm(0, 0);
	TAP_EQ_INT(t.lost, 0, "100 datagrams, none lost, after %d signals", (int)g_signals);
	TAP_EQ_INT(t.recv_eintr, 0, "and no receive saw EINTR: each was restarted");
	TAP_EQ_INT(t.dups + t.send_eintr, 0, "and no send was interrupted or repeated");
	close(fd);

	TAP_GROUP("FR-SV-T4: a datagram delivered just as a signal interrupts its receive");
	/* D-54: under user notification, a reply the kernel accepted could
	 * still be discarded by a call a signal had just interrupted, and its
	 * datagram was lost (about 1 in 10,000 interrupted receives).  Replies
	 * at once and a signal every 100 us put many deliveries in that
	 * instant; traced, none can be lost. */
	g_echo = loopback(echo_port);
	fd = udp_timed(500);
	g_signals = 0;
	storm(100, 0);
	t = ping_pong(fd, 1000);
	storm(0, 0);
	TAP_EQ_INT(t.lost, 0, "1000 datagrams under a signal every 100 us: none lost (%d EINTR, "
	                      "%d signals)",
	           t.recv_eintr, (int)g_signals);
	TAP_EQ_INT(t.dups + t.send_eintr, 0, "no send interrupted or repeated");
	close(fd);
	g_echo = loopback(delayed_port);

	TAP_GROUP("SO_RCVTIMEO, as on a native socket (D-54)");
	/* The receive waits in the program's own kernel, so its timeout is
	 * the kernel's. */
	fd = udp_timed(300);
	clock_gettime(CLOCK_MONOTONIC, &t0);
	TAP_OK(fails_with(recv(fd, buf, sizeof(buf), 0), EAGAIN),
	       "a receive with nothing coming times out: EAGAIN");
	TAP_OK(elapsed_ms(&t0) >= 250 && elapsed_ms(&t0) < 1500, "after its 300 ms (%ld ms)",
	       elapsed_ms(&t0));
	/* signal(7): a receive on a socket with SO_RCVTIMEO is never
	 * restarted after a handler, whatever SA_RESTART says. */
	storm(2000, 1);
	TAP_OK(fails_with(recv(fd, buf, sizeof(buf), 0), EINTR),
	       "interrupted under SA_RESTART, it fails with EINTR, as signal(7) says");
	storm(0, 0);
	close(fd);

	TAP_GROUP("a receive waiting through SIGSTOP and SIGCONT");
	/* With no SO_RCVTIMEO, as signal(7) has it, the stopped receive is
	 * restarted when the process continues; with one, it fails with EINTR
	 * instead.  An alarm ends a child whose datagram never comes. */
	fd = udp_timed(0);
	pid = fork();
	if (pid == 0) {
		uint32_t v = 7, got = 0;

		alarm(5);
		sendto(fd, &v, sizeof(v), 0, (struct sockaddr *)&g_echo, sizeof(g_echo));
		_exit(recv(fd, &got, sizeof(got), 0) == sizeof(got) && got == 7 ? 0 : 1);
	}
	wait_sleeping(pid);
	kill(pid, SIGSTOP);
	usleep(30000);
	kill(pid, SIGCONT);
	TAP_OK(waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0,
	       "is restarted, and gets its datagram (status %#x)", st);
	close(fd);
	fd = udp_timed(3000);
	pid = fork();
	if (pid == 0) {
		uint32_t v = 8, got = 0;
		ssize_t r;

		alarm(5);
		sendto(fd, &v, sizeof(v), 0, (struct sockaddr *)&g_echo, sizeof(g_echo));
		r = recv(fd, &got, sizeof(got), 0);
		if (r < 0 && errno == EINTR)
			_exit(2);
		_exit(r == sizeof(got) && got == 8 ? 0 : 1);
	}
	wait_sleeping(pid);
	kill(pid, SIGSTOP);
	usleep(30000);
	kill(pid, SIGCONT);
	TAP_OK(waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 2,
	       "with SO_RCVTIMEO, it fails with EINTR, as signal(7) says (status %#x)", st);
	close(fd);

	TAP_GROUP("an interrupted close never leaves the descriptor open (D-54)");
	{
		int i, close_eintr = 0, left_open = 0, fcntl_eintr = 0;

		/* Linux closes a descriptor even when close() reports EINTR,
		 * so a program never closes it again.  Under user
		 * notification, a close interrupted while the supervisor held
		 * it reported EINTR without having run. */
		g_signals = 0;
		storm(100, 0);
		for (i = 0; i < 2000; i++) {
			int s, f;

			while ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0 && errno == EINTR)
				;
			if (close(s) != 0 && errno == EINTR)
				close_eintr++;
			while ((f = fcntl(s, F_GETFD)) == -1 && errno == EINTR)
				fcntl_eintr++;
			if (f != -1) {
				left_open++;
				close(s);
			}
		}
		storm(0, 0);
		TAP_EQ_INT(left_open, 0, "2000 UDP sockets closed under a signal every 100 us "
		                         "(%d signals): none left open",
		           (int)g_signals);
		TAP_EQ_INT(close_eintr, 0, "no close failed with EINTR");
		TAP_EQ_INT(fcntl_eintr, 0, "and fcntl(F_GETFD), no longer trapped, never did");
	}

	TAP_GROUP("installing descriptors, close_range and TCP under a storm (D-54)");
	{
		int i, sock_eintr = 0, dup_eintr = 0, cr_eintr = 0, left = 0, tcp_eintr = 0;
		int l = socket(AF_INET, SOCK_STREAM, 0), c = socket(AF_INET, SOCK_STREAM, 0);
		struct sockaddr_in a = loopback(0);
		socklen_t alen = sizeof(a);
		char chunk[64];
		pthread_t reader;

		/* A TCP connection below the range, read by a thread. */
		bind(l, (struct sockaddr *)&a, sizeof(a));
		listen(l, 1);
		getsockname(l, (struct sockaddr *)&a, &alen);
		connect(c, (struct sockaddr *)&a, sizeof(a));
		g_tcp_peer = accept(l, NULL, NULL);
		pthread_create(&reader, NULL, drain_tcp, NULL);
		memset(chunk, 0, sizeof(chunk));

		/* Each of these is traced, and a UDP socket() or a dup of one is
		 * then installed by notification with the thread's signals
		 * blocked: none fails with EINTR, which natively none does. */
		g_signals = 0;
		storm(100, 0);
		for (i = 0; i < 2000; i++) {
			int u, d;

			if ((u = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
				sock_eintr += errno == EINTR;
				continue;
			}
			if ((d = fcntl(u, F_DUPFD, 0)) < 0)
				dup_eintr += errno == EINTR;
			else
				close(d);
			if (syscall(SYS_close_range, u, u, 0) != 0 && errno == EINTR) {
				cr_eintr++;
				if (fcntl(u, F_GETFD) != -1) {
					left++;
					close(u);
				}
			}
			if (send(c, chunk, sizeof(chunk), 0) < 0 && errno == EINTR)
				tcp_eintr++;
		}
		storm(0, 0);
		shutdown(c, SHUT_WR);
		pthread_join(reader, NULL);
		close(c);
		close(g_tcp_peer);
		close(l);
		TAP_EQ_INT(sock_eintr, 0, "2000 UDP socket() calls under a signal every 100 us "
		                          "(%d signals): none failed with EINTR",
		           (int)g_signals);
		TAP_EQ_INT(dup_eintr, 0, "nor fcntl(F_DUPFD) of one");
		TAP_EQ_INT(cr_eintr, 0, "nor close_range() of one");
		TAP_EQ_INT(left, 0, "and none was left open");
		TAP_EQ_INT(tcp_eintr, 0, "2000 sends on a TCP connection below the range: none failed "
		                         "with EINTR");
		for (left = 0, i = RANGE; i < RANGE + 4096; i++)
			left += fcntl(i, F_GETFD) != -1;
		TAP_EQ_INT(left, 0, "and no descriptor was left in the range");
	}

	TAP_GROUP("the program is traced by the supervisor (D-54)");
	{
		char line[128];
		int tracer = -1;
		FILE *f = fopen("/proc/self/status", "re");

		while (f != NULL && fgets(line, sizeof(line), f) != NULL)
			if (sscanf(line, "TracerPid: %d", &tracer) == 1)
				break;
		if (f != NULL)
			fclose(f);
		TAP_EQ_INT(tracer, (int)getppid(), "its tracer is udpchains, its parent");
		TAP_OK(fails_with(ptrace(PTRACE_TRACEME, 0, NULL, NULL), EPERM),
		       "so it cannot be traced by another: PTRACE_TRACEME fails with EPERM");
	}
	TAP_DONE();
}

/* A proxy that accepts the connection and never answers. */
static int silent(void)
{
	struct sockaddr_in a = loopback(0);
	socklen_t len = sizeof(a);
	int fd = socket(AF_INET, SOCK_STREAM, 0);

	if (fd < 0 || bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(fd, 64) != 0 ||
	    getsockname(fd, (struct sockaddr *)&a, &len) != 0)
		return 1;
	printf("PORT %d\n", ntohs(a.sin_port));
	fflush(stdout);
	for (;;)
		pause();
}

static struct timespec g_handled;

static void note_signal(int sig)
{
	(void)sig;
	clock_gettime(CLOCK_MONOTONIC, &g_handled);
	g_signals++;
}

/* D-54: a signal arriving while the association is set up -- the proxy never
 * answers -- abandons the setup, so it is handled at once, and the send is
 * made again: it never fails with EINTR, having sent nothing. */
static int abandon(int echo_port)
{
	struct sockaddr_in e = loopback(echo_port);
	struct itimerval it = { { 0, 0 }, { 0, 300000 } };
	struct timespec t0;
	struct sigaction sa;
	long handled_ms;
	int fd, err;
	ssize_t r;

	TAP_GROUP("a signal during association setup is handled at once (D-54)");
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = note_signal;
	sigaction(SIGALRM, &sa, NULL); /* no SA_RESTART */
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	clock_gettime(CLOCK_MONOTONIC, &t0);
	setitimer(ITIMER_REAL, &it, NULL);
	r = sendto(fd, "x", 1, 0, (struct sockaddr *)&e, sizeof(e));
	err = errno;
	handled_ms = (g_handled.tv_sec - t0.tv_sec) * 1000 +
	             (g_handled.tv_nsec - t0.tv_nsec) / 1000000;
	TAP_EQ_INT((int)g_signals, 1, "the signal was handled");
	TAP_OK(handled_ms >= 250 && handled_ms < 1000,
	       "when it arrived, not when the setup gave up (%ld ms)", handled_ms);
	TAP_OK(r < 0 && err != EINTR, "the send was made again, and failed with the proxy's "
	                              "error, not EINTR (%s)",
	       r < 0 ? strerror(err) : "sent");
	TAP_OK(elapsed_ms(&t0) >= 1200, "after a second setup had waited its own timeout "
	                                "(%ld ms)",
	       elapsed_ms(&t0));
	close(fd);
	TAP_DONE();
}

/* --- lifecycle -------------------------------------------------------------*/

/* A thread's own socket, used for n round trips. */
struct own {
	int n, ok;
	char tag[16];
};

static void *own_socket(void *arg)
{
	struct own *o = arg;
	int fd = udp_timed(5000), i;

	for (i = 0; i < o->n; i++)
		o->ok += fd >= 0 && round_trip(fd, fd, o->tag);
	close(fd);
	return NULL;
}

/* One of several threads waiting on the same socket: what it got. */
struct waiter {
	int fd;
	char got[16];
};

static void *wait_one(void *arg)
{
	struct waiter *w = arg;

	if (recv(w->fd, w->got, sizeof(w->got) - 1, 0) < 0)
		strcpy(w->got, "none");
	return NULL;
}

/* Round trips under a storm of signals, on a socket made under it, receives
 * retried on EINTR as a program must.  socket() natively never fails with
 * EINTR, so it is not retried (D-54). */
static void *stormy(void *arg)
{
	struct own *o = arg;
	int fd = udp_timed(5000), i;

	for (i = 0; i < o->n && fd >= 0; i++) {
		char back[16];
		ssize_t r;

		if (sendto(fd, o->tag, strlen(o->tag), 0, (struct sockaddr *)&g_echo,
		           sizeof(g_echo)) != (ssize_t)strlen(o->tag))
			continue;
		while ((r = recv(fd, back, sizeof(back), 0)) < 0 && errno == EINTR)
			;
		o->ok += r == (ssize_t)strlen(o->tag) && memcmp(back, o->tag, (size_t)r) == 0;
	}
	close(fd);
	return NULL;
}

/* A thread with a descriptor table of its own (unshare(CLONE_FILES)).  Both
 * tables start with s and t.  The thread closes t in its own and makes a
 * socket, which belongs at t's number there; the first thread then closes s in
 * its own, leaving the thread's table the only holder of s. */
struct unshared {
	int s, t, fd, ok_new, ok_kept;
	volatile int stage;
};

static void *unshare_files(void *arg)
{
	struct unshared *u = arg;

	if (unshare(CLONE_FILES) != 0) {
		u->stage = 1;
		return NULL;
	}
	close(u->t);
	u->fd = udp_timed(5000);
	u->ok_new = u->fd >= 0 && round_trip(u->fd, u->fd, "unshared");
	u->stage = 1;
	while (u->stage != 2)
		usleep(1000);
	u->ok_kept = round_trip(u->s, u->s, "kept");
	close(u->fd);
	close(u->s);
	return NULL;
}

/* exec from a thread other than the first. */
static char **g_exec_argv;

static void *exec_from_thread(void *arg)
{
	(void)arg;
	execv("/proc/self/exe", g_exec_argv);
	_exit(126);
}

/* clone(CLONE_FILES) without CLONE_VM: a process sharing the parent's
 * descriptor table, which makes a socket there. */

static int cloned(void *arg)
{
	int fd = udp_timed(5000);

	(void)arg;
	if (fd < 0 || !round_trip(fd, fd, "cloned"))
		return 1;
	/* Left open: the parent finds it at the same number. */
	return write(*(int *)arg, &fd, sizeof(fd)) == sizeof(fd) ? 0 : 1;
}

static int lifecycle(int echo_port, const char *self)
{
	char countbuf[16], failbuf[16], keepbuf[16], gonebuf[16], portbuf[16];
	struct own own[8];
	struct waiter w[4];
	pthread_t th[8];
	int i, ok, fd, keep, gone, st, p[2];
	pid_t pid;

	g_echo = loopback(echo_port);

	TAP_GROUP("threads, each with its own socket (FR-SV-11)");
	for (i = 0; i < 8; i++) {
		memset(&own[i], 0, sizeof(own[i]));
		own[i].n = 50;
		snprintf(own[i].tag, sizeof(own[i].tag), "thread-%d", i);
		pthread_create(&th[i], NULL, own_socket, &own[i]);
	}
	for (ok = 0, i = 0; i < 8; i++) {
		pthread_join(th[i], NULL);
		ok += own[i].ok;
	}
	TAP_EQ_INT(ok, 400, "8 threads, 50 round trips each, all carried");

	TAP_GROUP("threads waiting on one socket");
	fd = udp_timed(5000);
	for (i = 0; i < 4; i++) {
		w[i].fd = fd;
		memset(w[i].got, 0, sizeof(w[i].got));
		pthread_create(&th[i], NULL, wait_one, &w[i]);
	}
	usleep(200000); /* all four waiting */
	for (i = 0; i < 4; i++) {
		char what[8];

		snprintf(what, sizeof(what), "w%d", i);
		sendto(fd, what, strlen(what), 0, (struct sockaddr *)&g_echo, sizeof(g_echo));
	}
	for (ok = 0, i = 0; i < 4; i++) {
		int k;

		pthread_join(th[i], NULL);
		for (k = 0; k < 4; k++) {
			char what[8];

			snprintf(what, sizeof(what), "w%d", k);
			ok += strcmp(w[i].got, what) == 0;
		}
	}
	TAP_EQ_INT(ok, 4, "4 datagrams to 4 waiting threads: each got one");
	TAP_OK(strcmp(w[0].got, w[1].got) != 0 && strcmp(w[2].got, w[3].got) != 0 &&
	               strcmp(w[0].got, w[2].got) != 0 && strcmp(w[1].got, w[3].got) != 0 &&
	               strcmp(w[0].got, w[3].got) != 0 && strcmp(w[1].got, w[2].got) != 0,
	       "and no two the same");
	close(fd);

	TAP_GROUP("threads under a storm of signals");
	g_signals = 0;
	storm(200, 0);
	for (i = 0; i < 4; i++) {
		memset(&own[i], 0, sizeof(own[i]));
		own[i].n = 200;
		snprintf(own[i].tag, sizeof(own[i].tag), "storm-%d", i);
		pthread_create(&th[i], NULL, stormy, &own[i]);
	}
	for (ok = 0, i = 0; i < 4; i++) {
		pthread_join(th[i], NULL);
		ok += own[i].ok;
	}
	storm(0, 0);
	TAP_EQ_INT(ok, 800, "4 threads, 200 round trips each, under %d signals: all carried",
	           (int)g_signals);

	TAP_GROUP("a thread with a descriptor table of its own");
	{
		struct unshared u;
		pthread_t t;

		memset(&u, 0, sizeof(u));
		u.s = udp_timed(5000);
		u.t = udp_timed(5000);
		u.fd = -1;
		pthread_create(&t, NULL, unshare_files, &u);
		while (u.stage != 1)
			usleep(1000);
		TAP_EQ_INT(u.fd, u.t, "after unshare(CLONE_FILES), a thread's new socket takes "
		                      "a number free in its own table, though not in the first's");
		TAP_OK(u.ok_new, "and is carried");
		TAP_OK(round_trip(u.t, u.t, "first"), "while the first thread's socket at that "
		                                      "number still is");
		/* Long enough for the sweep after this close to have run. */
		close(u.s);
		usleep(700000);
		u.stage = 2;
		pthread_join(t, NULL);
		TAP_OK(u.ok_kept, "a socket held only in the thread's table is not forgotten "
		                  "by the sweep");
		close(u.t);
	}

	TAP_GROUP("clone(CLONE_FILES): a process sharing the descriptor table");
	{
		static char stack[64 * 1024];
		int got = -1;

		if (pipe(p) == 0) {
			pid = clone(cloned, stack + sizeof(stack), CLONE_FILES | SIGCHLD, &p[1]);
			TAP_OK(pid > 0 && waitpid(pid, &st, 0) == pid && WIFEXITED(st) &&
			               WEXITSTATUS(st) == 0,
			       "the cloned process makes a socket and is carried");
			TAP_OK(read(p[0], &got, sizeof(got)) == sizeof(got) && got >= RANGE,
			       "at fd %d, in the table it shares", got);
			TAP_OK(got >= RANGE && round_trip(got, got, "shared-table"),
			       "where the parent uses it too, after the child has gone");
			if (got >= 0)
				close(got);
			close(p[0]);
			close(p[1]);
		}
	}

	TAP_GROUP("close_range (FR-SV-T3)");
	{
		int a = udp_timed(5000), b = udp_timed(5000), c;

		TAP_OK(round_trip(a, a, "a") && round_trip(b, b, "b"), "two sockets, carried");
		TAP_EQ_INT((int)syscall(SYS_close_range, b, b, CLOSE_RANGE_CLOEXEC), 0,
		           "close_range(CLOSE_RANGE_CLOEXEC) on one");
		TAP_OK(fcntl(b, F_GETFD) & FD_CLOEXEC, "marks it close-on-exec, and leaves it open");
		TAP_EQ_INT((int)syscall(SYS_close_range, RANGE, ~0U, 0), 0,
		           "close_range() over the whole range");
		TAP_OK(fcntl(a, F_GETFD) == -1 && fcntl(b, F_GETFD) == -1, "closes both");
		c = udp_timed(5000);
		TAP_EQ_INT(c, RANGE, "the range's first number is given out again");
		TAP_OK(round_trip(c, c, "c"), "and carries");
		close(c);
	}

	TAP_GROUP("posix_spawn (vfork and exec) keeps an inherited socket");
	keep = udp_timed(5000);
	gone = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	snprintf(keepbuf, sizeof(keepbuf), "%d", keep);
	snprintf(gonebuf, sizeof(gonebuf), "%d", gone);
	snprintf(portbuf, sizeof(portbuf), "%d", echo_port);
	{
		char *argv[] = { (char *)(uintptr_t)self, (char *)(uintptr_t)"execed", portbuf,
			         keepbuf, gonebuf, NULL };
		extern char **environ;

		TAP_EQ_INT(posix_spawn(&pid, "/proc/self/exe", NULL, NULL, argv, environ), 0,
		           "posix_spawn() of this program");
		TAP_OK(waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0,
		       "which carries the inherited socket, and finds the close-on-exec one "
		       "gone (status %#x)",
		       st);
	}

	TAP_GROUP("exec from a thread other than the first");
	{
		char *argv[] = { (char *)(uintptr_t)self, (char *)(uintptr_t)"execed", portbuf,
			         keepbuf, gonebuf, NULL };
		pthread_t t;

		fflush(stdout);
		pid = fork();
		if (pid == 0) {
			g_exec_argv = argv;
			pthread_create(&t, NULL, exec_from_thread, NULL);
			pause();
		}
		TAP_OK(waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0,
		       "the new program carries the socket (status %#x)", st);
	}

	/* Last: this process becomes the exec'd program, which prints the
	 * plan.  The close-on-exec socket's association is let go after the
	 * exec, which test_supervise.sh looks for. */
	TAP_GROUP("exec keeps an inherited socket, and drops a close-on-exec one");
	{
		char *argv[] = { (char *)(uintptr_t)self, (char *)(uintptr_t)"execed", portbuf,
			         keepbuf, gonebuf, countbuf, failbuf, NULL };

		TAP_OK(round_trip(gone, gone, "before"), "the close-on-exec socket is carried "
		                                         "before the exec");
		snprintf(countbuf, sizeof(countbuf), "%d", tap_count);
		snprintf(failbuf, sizeof(failbuf), "%d", tap_failed);
		/* The sweeps due to what came before are over by then, so only
		 * the exec can prompt the next. */
		usleep(600000);
		fflush(stdout);
		execv("/proc/self/exe", argv);
		TAP_OK(0, "execv: %s", strerror(errno));
	}
	TAP_DONE();
}

/* After an exec: keep must still be carried and gone must be closed.  With a
 * count, this is the end of lifecycle's run, numbered after its checks and
 * counting its failures. */
static int execed(int echo_port, int keep, int gone, int count, int failed)
{
	g_echo = loopback(echo_port);
	if (count < 0)
		return round_trip(keep, keep, "spawned") && fcntl(gone, F_GETFD) == -1 ? 0 : 1;
	tap_count = count;
	tap_failed = failed;
	TAP_OK(round_trip(keep, keep, "exec'd"), "after the exec, the inherited socket is "
	                                         "carried");
	TAP_OK(fcntl(gone, F_GETFD) == -1, "and the close-on-exec one is gone");
	/* Long enough for the supervisor to notice the dropped socket, which
	 * test_supervise.sh looks for now: it should hold one association. */
	usleep(300000);
	printf("# waiting\n");
	fflush(stdout);
	usleep(1000000);
	TAP_DONE();
}

/* Two threads making and closing UDP sockets, then gone before the first
 * returns: the supervisor must reap traced threads to see the program exit. */
static void *churn_sockets(void *arg)
{
	int i;

	(void)arg;
	for (i = 0; i < 200; i++)
		close(socket(AF_INET, SOCK_DGRAM, 0));
	return NULL;
}

static int threadexit(void)
{
	pthread_t a, b;

	pthread_create(&a, NULL, churn_sockets, NULL);
	pthread_create(&b, NULL, churn_sockets, NULL);
	pthread_join(a, NULL);
	pthread_join(b, NULL);
	return 0;
}

/* --- DNS (D-52) ------------------------------------------------------------*/

/* A query for name, type A, with id. */
static size_t dns_query(uint8_t *q, uint16_t id, const char *name)
{
	size_t n = 12;
	const char *p = name;

	memset(q, 0, 12);
	q[0] = (uint8_t)(id >> 8);
	q[1] = (uint8_t)id;
	q[2] = 0x01; /* RD */
	q[5] = 1;    /* QDCOUNT */
	while (*p != '\0') {
		const char *dot = strchr(p, '.');
		size_t len = dot != NULL ? (size_t)(dot - p) : strlen(p);

		q[n++] = (uint8_t)len;
		memcpy(q + n, p, len);
		n += len;
		p += len + (dot != NULL);
	}
	q[n++] = 0;
	q[n++] = 0;
	q[n++] = 1; /* A */
	q[n++] = 0;
	q[n++] = 1; /* IN */
	return n;
}

/* Whether r is the answer to id carrying want, an IPv4 address. */
static int dns_answers(const uint8_t *r, ssize_t n, uint16_t id, const char *want)
{
	struct in_addr a;
	ssize_t i;

	if (n < 12 || r[0] != (uint8_t)(id >> 8) || r[1] != (uint8_t)id || (r[3] & 0x0f) != 0 ||
	    inet_pton(AF_INET, want, &a) != 1)
		return 0;
	for (i = 12; i + 4 <= n; i++)
		if (memcmp(r + i, &a, 4) == 0)
			return 1;
	return 0;
}

static struct sockaddr_storage addr_of(const char *ip, int port)
{
	struct sockaddr_storage ss;

	memset(&ss, 0, sizeof(ss));
	if (strchr(ip, ':') != NULL) {
		struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;

		a->sin6_family = AF_INET6;
		a->sin6_port = htons((uint16_t)port);
		inet_pton(AF_INET6, ip, &a->sin6_addr);
	} else {
		struct sockaddr_in *a = (struct sockaddr_in *)&ss;

		a->sin_family = AF_INET;
		a->sin_port = htons((uint16_t)port);
		inet_pton(AF_INET, ip, &a->sin_addr);
	}
	return ss;
}

static socklen_t len_of(const struct sockaddr_storage *ss)
{
	return ss->ss_family == AF_INET6 ? sizeof(struct sockaddr_in6)
	                                 : sizeof(struct sockaddr_in);
}

/* Asks the system resolver at ip for name on a fresh socket, sendto() and
 * recvfrom(), and reports whether the answer came, from ip:53. */
static int ask(const char *ip, uint16_t id, const char *name, const char *want)
{
	struct sockaddr_storage to = addr_of(ip, 53), from;
	socklen_t flen = sizeof(from);
	struct timeval tv = { 3, 0 };
	uint8_t q[512], r[512];
	size_t qn = dns_query(q, id, name);
	int fd = socket(to.ss_family, SOCK_DGRAM, 0), ok;
	ssize_t n;

	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	if (sendto(fd, q, qn, 0, (struct sockaddr *)&to, len_of(&to)) != (ssize_t)qn) {
		close(fd);
		return 0;
	}
	memset(&from, 0, sizeof(from));
	n = recvfrom(fd, r, sizeof(r), 0, (struct sockaddr *)&from, &flen);
	ok = dns_answers(r, n, id, want) && flen == len_of(&to) &&
	     memcmp(&from, &to, len_of(&to)) == 0;
	close(fd);
	return ok;
}

/* Under the supervisor with dns set to dnsd's port: queries to the system
 * resolver reach dnsd, through the proxy, and port 53 elsewhere does not. */
static int dns(int dnsd_port)
{
	struct sockaddr_storage to = addr_of("127.0.0.53", 53), peer;
	struct sockaddr_in direct = loopback(dnsd_port);
	struct timeval tv = { 0, 500000 };
	struct addrinfo hints, *res = NULL;
	socklen_t plen = sizeof(peer);
	uint8_t q[512], r[512];
	size_t qn;
	ssize_t n;
	int fd;

	TAP_GROUP("FR-SV-12: queries to the system resolver go to dns (D-52)");
	TAP_OK(ask("127.0.0.53", 0x1201, "a.test", "192.0.2.1"),
	       "sendto() 127.0.0.53:53 is answered by dns, reported from 127.0.0.53:53");
	TAP_OK(ask("::1", 0x1202, "a.test", "192.0.2.1"), "and [::1]:53 likewise, on an AF_INET6 "
	                                                   "socket");
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	TAP_EQ_INT(connect(fd, (struct sockaddr *)&to, len_of(&to)), 0,
	           "connect() to 127.0.0.53:53, as glibc's resolver does");
	qn = dns_query(q, 0x1203, "multi.test");
	TAP_EQ_INT((int)send(fd, q, qn, 0), (int)qn, "send() the query");
	n = recv(fd, r, sizeof(r), 0);
	TAP_OK(dns_answers(r, n, 0x1203, "192.0.2.10"), "and recv() gets dns's answer: the "
	                                                "connected socket accepts it");
	TAP_OK(getpeername(fd, (struct sockaddr *)&peer, &plen) == 0 &&
	               memcmp(&peer, &to, len_of(&to)) == 0,
	       "getpeername() still says 127.0.0.53:53");
	close(fd);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	TAP_OK(getaddrinfo("v4only.test", NULL, &hints, &res) == 0 && res != NULL &&
	               ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr ==
	                       htonl(0xc0000204),
	       "getaddrinfo() in this static program resolves through it: 192.0.2.4");
	if (res != NULL)
		freeaddrinfo(res);

	TAP_GROUP("port 53 elsewhere is proxied as addressed (D-52)");
	{
		struct sockaddr_storage other = addr_of("192.0.2.53", 53);

		fd = socket(AF_INET, SOCK_DGRAM, 0);
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		qn = dns_query(q, 0x1204, "elsewhere.test");
		TAP_EQ_INT((int)sendto(fd, q, qn, 0, (struct sockaddr *)&other, len_of(&other)),
		           (int)qn, "sendto() 192.0.2.53:53 is sent");
		/* Some networks answer port 53 whatever its address, so a reply
		 * may come; it is 192.0.2.53's, never dns's.  test_supervise.sh
		 * checks that dns never saw the query. */
		{
			struct sockaddr_storage from;
			socklen_t flen = sizeof(from);

			n = recvfrom(fd, r, sizeof(r), 0, (struct sockaddr *)&from, &flen);
			TAP_OK(n < 0 || (flen == len_of(&other) &&
			                 memcmp(&from, &other, len_of(&other)) == 0),
			       "to 192.0.2.53, through the proxy: any reply is reported as "
			       "192.0.2.53's (%s)",
			       n < 0 ? "none came" : "one came");
		}
		close(fd);
	}

	TAP_GROUP("TCP to the system resolver's port 53 is refused (D-52)");
	fd = socket(AF_INET, SOCK_STREAM, 0);
	TAP_OK(fails_with(connect(fd, (struct sockaddr *)&to, len_of(&to)), ECONNREFUSED),
	       "connect() to 127.0.0.53:53: ECONNREFUSED, so the resolver's query cannot go "
	       "upstream around the proxy");
	close(fd);
	fd = socket(AF_INET, SOCK_STREAM, 0);
	qn = dns_query(q, 0x1205, "a.test");
	TAP_OK(fails_with(sendto(fd, q, qn, MSG_FASTOPEN, (struct sockaddr *)&to, len_of(&to)),
	                  ECONNREFUSED),
	       "and by TCP Fast Open: ECONNREFUSED");
	close(fd);
	fd = socket(AF_INET, SOCK_STREAM, 0);
	TAP_EQ_INT(connect(fd, (struct sockaddr *)&direct, sizeof(direct)), 0,
	           "TCP to another port of loopback is not refused");
	close(fd);
	TAP_DONE();
}

/* Under the supervisor with no dns: a query to the system resolver fails,
 * and port 53 elsewhere is still sent. */
static int nodns(void)
{
	struct sockaddr_storage to = addr_of("127.0.0.53", 53), other = addr_of("192.0.2.53", 53);
	struct addrinfo hints, *res = NULL;
	uint8_t q[512];
	size_t qn = dns_query(q, 0x1301, "a.test");
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	TAP_GROUP("FR-SV-12: with no dns, queries to the system resolver fail (D-52)");
	TAP_OK(fails_with(sendto(fd, q, qn, 0, (struct sockaddr *)&to, len_of(&to)), ENETUNREACH),
	       "sendto() 127.0.0.53:53: ENETUNREACH");
	TAP_EQ_INT((int)sendto(fd, q, qn, 0, (struct sockaddr *)&other, len_of(&other)), (int)qn,
	           "sendto() 192.0.2.53:53 is still sent, through the proxy");
	close(fd);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	TAP_OK(getaddrinfo("a.test", NULL, &hints, &res) != 0, "getaddrinfo() fails");
	if (res != NULL)
		freeaddrinfo(res);
	TAP_DONE();
}

/* For the wire capture (FR-SV-T2): a datagram to ip:port every 5 ms for secs
 * seconds, a line for each one sent, so a run killed part way still says how
 * far it got. */
static int spray(const char *ip, int port, int secs)
{
	struct sockaddr_in d = loopback(port);
	int fd = socket(AF_INET, SOCK_DGRAM, 0), i;

	if (inet_pton(AF_INET, ip, &d.sin_addr) != 1 || fd < 0)
		return 2;
	for (i = 0; i < secs * 200; i++) {
		if (sendto(fd, "spray", 5, 0, (struct sockaddr *)&d, sizeof(d)) == 5) {
			printf("SENT %d\n", i);
			fflush(stdout);
		}
		usleep(5000);
	}
	return 0;
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
	if (argc == 4 && strcmp(argv[1], "signals") == 0)
		return signals(atoi(argv[2]), atoi(argv[3]));
	if (argc == 2 && strcmp(argv[1], "silent") == 0)
		return silent();
	if (argc == 3 && strcmp(argv[1], "dns") == 0)
		return dns(atoi(argv[2]));
	if (argc == 2 && strcmp(argv[1], "nodns") == 0)
		return nodns();
	if (argc == 2 && strcmp(argv[1], "threadexit") == 0)
		return threadexit();
	if (argc == 5 && strcmp(argv[1], "spray") == 0)
		return spray(argv[2], atoi(argv[3]), atoi(argv[4]));
	if (argc == 3 && strcmp(argv[1], "lifecycle") == 0)
		return lifecycle(atoi(argv[2]), argv[0]);
	if (argc == 5 && strcmp(argv[1], "execed") == 0)
		return execed(atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), -1, 0);
	if (argc == 7 && strcmp(argv[1], "execed") == 0)
		return execed(atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5]),
		              atoi(argv[6]));
	if (argc == 3 && strcmp(argv[1], "abandon") == 0)
		return abandon(atoi(argv[2]));
	if (argc == 3 && strcmp(argv[1], "nodump") == 0)
		return nodump(atoi(argv[2]));
	if (argc == 5 && strcmp(argv[1], "churn") == 0)
		return churn(atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));
	if (argc == 4 && strcmp(argv[1], "pass") == 0)
		return pass(argv[2], atoi(argv[3]));
	if (argc == 3 && strcmp(argv[1], "received") == 0)
		return received(argv[2]);
	fprintf(stderr, "usage: test_supervise refusals <tcp port> | range <echo port> | "
	                "signals <delayed echo port> <echo port> | silent | "
	                "abandon <echo port> | lifecycle <echo port> | "
	                "spray <ip> <port> <secs> | threadexit | dns <dnsd port> | nodns | "
	                "nodump <tcp port> | "
	                "churn <echo port> <n> <secs> | "
	                "pass <path> <port> | "
	                "received <path>\n");
	return 2;
}

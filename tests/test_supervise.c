/* test_supervise.c -- supervisor mode, step 2 (D-48, D-50, D-53).
 *
 * Built -static, so it is the kind of program supervisor mode exists for: the
 * shim could not see a single call it makes.  Each mode is run by
 * tests/test_supervise.sh.
 *
 *   test_supervise refusals <tcp port>   under the supervisor: what is refused,
 *                                        and that what is not still works
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
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef AF_PACKET
#define AF_PACKET 17
#endif

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

	TAP_GROUP("a UDP socket is refused, not made, until the supervisor can carry it");
	errno = 0;
	TAP_OK(fails_with(socket(AF_INET, SOCK_DGRAM, 0), EPROTONOSUPPORT),
	       "socket(AF_INET, SOCK_DGRAM) fails with EPROTONOSUPPORT (%s)", strerror(errno));
	TAP_OK(fails_with(socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0),
	                  EPROTONOSUPPORT),
	       "and AF_INET6, with SOCK_NONBLOCK and SOCK_CLOEXEC");
	TAP_OK(fails_with(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP), EPROTONOSUPPORT),
	       "and IPPROTO_UDP named");

	TAP_GROUP("sockets SOCKS5 cannot carry are refused (D-29, D-36)");
	TAP_OK(fails_with(socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP), EPROTONOSUPPORT),
	       "an ICMP datagram socket: EPROTONOSUPPORT");
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
	if (argc == 4 && strcmp(argv[1], "pass") == 0)
		return pass(argv[2], atoi(argv[3]));
	if (argc == 3 && strcmp(argv[1], "received") == 0)
		return received(argv[2]);
	fprintf(stderr, "usage: test_supervise refusals <tcp port> | pass <path> <port> | "
	                "received <path>\n");
	return 2;
}

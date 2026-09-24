/* leakclient.c -- the client half of TST-03 / SEC-02.
 *
 * Tries hard, by every send path the shim hooks, to get a datagram to the
 * destination.  Prints a machine-readable summary; test_leak.sh then asserts
 * that the destination received NOTHING.
 *
 * This is the shape of the defect the project exists to fix: under
 * proxychains-ng with a dead proxy, TCP correctly fails while UDP reaches the
 * destination anyway, with no diagnostic (baseline §0.3.1).
 *
 * usage: leakclient <ip> <port> [-6]
 */
#define _GNU_SOURCE 1

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>

static struct sockaddr_storage g_dst;
static socklen_t g_dstlen;
static int g_family;

static char g_payload[] = "leak";

static int g_sent_ok;
static int g_send_failed;

static int mksock(int do_connect)
{
	struct timeval tv = { 1, 0 };
	int fd = socket(g_family, SOCK_DGRAM, 0);

	if (fd < 0)
		return -1;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	if (do_connect &&
	    connect(fd, (struct sockaddr *)&g_dst, g_dstlen) != 0) {
		/* connect() failing is fine; the point is whether a datagram
		 * escapes, and we still try to send afterwards. */
	}
	return fd;
}

static void record(const char *what, ssize_t n)
{
	if (n >= 0) {
		g_sent_ok++;
		printf("LEAK-RISK %s reported success (%zd)\n", what, n);
	} else {
		g_send_failed++;
		printf("ok %s failed: %s\n", what, strerror(errno));
	}
}

/* Sends fd across a unix socket pair to ourselves and returns the descriptor
 * that arrives -- a new number, created without socket() or dup. */
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

int main(int argc, char **argv)
{
	const char *ip;
	int port;
	int i;

	if (argc < 3) {
		fprintf(stderr, "usage: leakclient <ip> <port> [-6]\n");
		return 2;
	}
	ip = argv[1];
	port = atoi(argv[2]);
	g_family = (argc > 3 && strcmp(argv[3], "-6") == 0) ? AF_INET6 : AF_INET;

	memset(&g_dst, 0, sizeof(g_dst));
	if (g_family == AF_INET) {
		struct sockaddr_in *a = (struct sockaddr_in *)&g_dst;
		a->sin_family = AF_INET;
		a->sin_port = htons((uint16_t)port);
		inet_pton(AF_INET, ip, &a->sin_addr);
		g_dstlen = sizeof(*a);
	} else {
		struct sockaddr_in6 *a = (struct sockaddr_in6 *)&g_dst;
		a->sin6_family = AF_INET6;
		a->sin6_port = htons((uint16_t)port);
		inet_pton(AF_INET6, ip, &a->sin6_addr);
		g_dstlen = sizeof(*a);
	}

	/* Every send path, unconnected. */
	for (i = 0; i < 2; i++) {
		int fd = mksock(0);
		if (fd < 0)
			continue;
		record("sendto", sendto(fd, g_payload, 4, 0,
		                        (struct sockaddr *)&g_dst, g_dstlen));
		{
			struct msghdr m;
			struct iovec v;
			v.iov_base = g_payload;
			v.iov_len = 4;
			memset(&m, 0, sizeof(m));
			m.msg_name = &g_dst;
			m.msg_namelen = g_dstlen;
			m.msg_iov = &v;
			m.msg_iovlen = 1;
			record("sendmsg", sendmsg(fd, &m, 0));
		}
		{
			struct mmsghdr mm[2];
			struct iovec v[2];
			int rc;
			memset(mm, 0, sizeof(mm));
			for (int k = 0; k < 2; k++) {
				v[k].iov_base = g_payload;
				v[k].iov_len = 4;
				mm[k].msg_hdr.msg_name = &g_dst;
				mm[k].msg_hdr.msg_namelen = g_dstlen;
				mm[k].msg_hdr.msg_iov = &v[k];
				mm[k].msg_hdr.msg_iovlen = 1;
			}
			rc = sendmmsg(fd, mm, 2, 0);
			record("sendmmsg", rc < 0 ? -1 : rc);
		}
		close(fd);
	}

	/* Every send path, connected. */
	{
		int fd = mksock(1);
		if (fd >= 0) {
			struct iovec v;

			record("send", send(fd, g_payload, 4, 0));
			record("write", write(fd, g_payload, 4));
			v.iov_base = g_payload;
			v.iov_len = 4;
			record("writev", writev(fd, &v, 1));
			close(fd);
		}
	}

	/* A socket that is bound first, in case binding changes the path. */
	{
		int fd = mksock(0);
		if (fd >= 0) {
			struct sockaddr_in b;
			memset(&b, 0, sizeof(b));
			b.sin_family = AF_INET;
			b.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			b.sin_port = 0;
			if (g_family == AF_INET)
				bind(fd, (struct sockaddr *)&b, sizeof(b));
			record("sendto-after-bind",
			       sendto(fd, g_payload, 4, 0, (struct sockaddr *)&g_dst,
			              g_dstlen));
			close(fd);
		}
	}

	/* Descriptors that reach the application by a route other than socket()
	 * or dup: an fcntl duplicate, a socket received over SCM_RIGHTS, and a
	 * socket left open by a FAILED dup2 onto it.  Each was once untracked,
	 * and each then sent directly with the proxy down. */
	{
		int fd = mksock(0);
		if (fd >= 0) {
			int copy = fcntl(fd, F_DUPFD_CLOEXEC, 0);
			int got = pass_fd(fd);

			if (copy >= 0) {
				record("sendto-via-fcntl-dup",
				       sendto(copy, g_payload, 4, 0,
				              (struct sockaddr *)&g_dst, g_dstlen));
				close(copy);
			}
			if (got >= 0) {
				record("sendto-via-SCM_RIGHTS",
				       sendto(got, g_payload, 4, 0,
				              (struct sockaddr *)&g_dst, g_dstlen));
				close(got);
			}
			/* dup2 from a bad descriptor fails with EBADF and leaves
			 * fd open and unchanged. */
			if (dup2(-1, fd) < 0)
				record("sendto-after-failed-dup2",
				       sendto(fd, g_payload, 4, 0,
				              (struct sockaddr *)&g_dst, g_dstlen));
			close(fd);
		}
	}

	/* The same, through syscall() -- how libuv reaches the kernel.  A socket
	 * created or duplicated there never met a hook (D-23). */
	{
		int fd = (int)syscall(SYS_socket, g_family, SOCK_DGRAM, 0);
		if (fd >= 0) {
			int copy = (int)syscall(SYS_dup, fd);

			record("sendto-via-syscall-socket",
			       sendto(fd, g_payload, 4, 0, (struct sockaddr *)&g_dst,
			              g_dstlen));
			if (copy >= 0) {
				record("sendto-via-syscall-dup",
				       sendto(copy, g_payload, 4, 0,
				              (struct sockaddr *)&g_dst, g_dstlen));
				close(copy);
			}
			close(fd);
		}
	}

	printf("SUMMARY sent_ok=%d send_failed=%d\n", g_sent_ok, g_send_failed);
	return 0;
}

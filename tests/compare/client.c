/* client.c -- the test client for tests/compare/run.sh.
 *
 * Runs under each tool being compared (udpchains, Dante socksify, and so on),
 * against an echo server on another host.  Every payload starts
 * "T|<tag>|<cell>|", so the server's log shows whether that datagram came
 * through the proxy or straight from this host -- the tool's own report is
 * never trusted for that.
 *
 *   client cell  <tag> <ip> <port>   one sender x receiver combination, chosen
 *                                    by CMP_SENDER and CMP_RECVER; CMP_WARM=1
 *                                    first exchanges a datagram on the socket
 *   client extra <tag> <ip> <port>   dup, fork, getpeername, zero-length
 *   client leak  <tag> <ip> <port>   one send per sender, no receive
 *
 * One cell per process, so a crash inside a tool costs only that cell.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

static struct sockaddr_storage g_dst;
static socklen_t g_dlen;
static const char *g_tag;

/* "_u" sends name the destination on an unconnected socket; "_c" connect()
 * first.  send, write and writev need a connected socket. */
static const char *const SENDERS[] = {
	"sendto_u", "sendmsg_u", "sendmmsg_u", "sendto_c", "send_c",
	"write_c", "writev_c", "sendmsg_c", "sendmmsg_c",
};

static int mksock(void)
{
	struct timeval tv = { 2, 0 };
	int fd = socket(g_dst.ss_family, SOCK_DGRAM, 0);

	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return fd;
}

static ssize_t do_send(int fd, const char *how, const void *buf, size_t n)
{
	struct iovec iov = { (void *)buf, n };
	struct msghdr m = { 0 };
	struct mmsghdr mm = { 0 };
	int conn = how[strlen(how) - 1] == 'c';

	if (conn && connect(fd, (struct sockaddr *)&g_dst, g_dlen) != 0)
		return -1;
	m.msg_iov = &iov;
	m.msg_iovlen = 1;
	if (!conn) {
		m.msg_name = &g_dst;
		m.msg_namelen = g_dlen;
	}

	if (strncmp(how, "sendto", 6) == 0)
		return conn ? sendto(fd, buf, n, 0, NULL, 0)
		            : sendto(fd, buf, n, 0, (struct sockaddr *)&g_dst, g_dlen);
	if (strcmp(how, "send_c") == 0)
		return send(fd, buf, n, 0);
	if (strcmp(how, "write_c") == 0)
		return write(fd, buf, n);
	if (strcmp(how, "writev_c") == 0)
		return writev(fd, &iov, 1);
	if (strncmp(how, "sendmsg", 7) == 0)
		return sendmsg(fd, &m, 0);
	mm.msg_hdr = m;
	return sendmmsg(fd, &mm, 1, 0) == 1 ? (ssize_t)mm.msg_len : -1;
}

/* Receives into buf.  *have_src says whether the call reports a sender. */
static ssize_t do_recv(int fd, const char *how, void *buf, size_t n,
                       struct sockaddr_storage *src, int *have_src)
{
	struct iovec iov = { buf, n };
	struct msghdr m = { 0 };
	struct mmsghdr mm = { 0 };
	socklen_t sl = sizeof(*src);

	*have_src = 0;
	m.msg_iov = &iov;
	m.msg_iovlen = 1;
	m.msg_name = src;
	m.msg_namelen = sizeof(*src);

	if (strcmp(how, "recvfrom") == 0) {
		*have_src = 1;
		return recvfrom(fd, buf, n, 0, (struct sockaddr *)src, &sl);
	}
	if (strcmp(how, "recv") == 0)
		return recv(fd, buf, n, 0);
	if (strcmp(how, "read") == 0)
		return read(fd, buf, n);
	if (strcmp(how, "readv") == 0)
		return readv(fd, &iov, 1);
	*have_src = 1;
	if (strcmp(how, "recvmsg") == 0)
		return recvmsg(fd, &m, 0);
	mm.msg_hdr = m;
	return recvmmsg(fd, &mm, 1, 0, NULL) == 1 ? (ssize_t)mm.msg_len : -1;
}

static int is_server(const struct sockaddr_storage *a)
{
	if (a->ss_family == AF_INET && g_dst.ss_family == AF_INET) {
		const struct sockaddr_in *x = (const void *)a, *y = (const void *)&g_dst;

		return x->sin_addr.s_addr == y->sin_addr.s_addr &&
		       x->sin_port == y->sin_port;
	}
	if (a->ss_family == AF_INET6 && g_dst.ss_family == AF_INET6) {
		const struct sockaddr_in6 *x = (const void *)a, *y = (const void *)&g_dst;

		return memcmp(&x->sin6_addr, &y->sin6_addr, 16) == 0 &&
		       x->sin6_port == y->sin6_port;
	}
	return 0;
}

/* A tagged payload with a binary tail, so a header delivered as data, or a
 * truncation, cannot pass for the original. */
static int payload(char *buf, const char *cell)
{
	int n = snprintf(buf, 128, "T|%s|%s|", g_tag, cell), i;

	for (i = 0; i < 64; i++)
		buf[n + i] = (char)(i * 37 + 11);
	return n + 64;
}

static void cell(const char *snd, const char *rcv)
{
	char name[64], out[256], in[2048];
	struct sockaddr_storage src;
	int fd = mksock(), have, n;
	ssize_t s, r;

	snprintf(name, sizeof(name), "%s/%s", snd, rcv);

	if (getenv("CMP_WARM") != NULL) {
		/* Real programs reuse sockets: a tool that behaves differently
		 * on a socket's first send should not be judged by it. */
		char w[64];
		int wn = snprintf(w, sizeof(w), "T|%s|warmup|", g_tag);

		do_send(fd, snd, w, (size_t)wn);
		usleep(300000);
		while (recv(fd, in, sizeof(in), MSG_DONTWAIT) > 0)
			;
	}

	n = payload(out, name);
	s = do_send(fd, snd, out, (size_t)n);
	if (s != n) {
		printf("CELL %s SENDERR %s\n", name, strerrorname_np(errno));
		close(fd);
		return;
	}
	r = do_recv(fd, rcv, in, sizeof(in), &src, &have);
	if (r < 0)
		printf("CELL %s NOREPLY %s\n", name, strerrorname_np(errno));
	else if (r != n || memcmp(in, out, (size_t)n) != 0)
		printf("CELL %s BADDATA got %zd want %d\n", name, r, n);
	else if (have && !is_server(&src))
		printf("CELL %s BADSRC\n", name);
	else
		printf("CELL %s OK\n", name);
	close(fd);
}

static int round_trip(int sfd, int rfd, const char *cellname)
{
	char out[256], in[2048];
	int n = payload(out, cellname);
	ssize_t r = sendto(sfd, out, (size_t)n, 0, (struct sockaddr *)&g_dst, g_dlen);

	if (r != n)
		return 0;
	r = recv(rfd, in, sizeof(in), 0);
	return r == n && memcmp(in, out, (size_t)n) == 0;
}

static void extra(void)
{
	struct sockaddr_storage peer, src;
	socklen_t pl = sizeof(peer);
	char out[256], in[2048];
	int fd, d, n, st;
	ssize_t r;

	/* dup: send on the duplicate, receive on the original. */
	fd = mksock();
	d = dup(fd);
	printf("CELL dup %s\n", round_trip(d, fd, "dup") ? "OK" : "FAIL");
	close(d);
	close(fd);

	/* fork: the child uses the socket it inherited. */
	fd = mksock();
	round_trip(fd, fd, "fork-parent");
	if (fork() == 0)
		_exit(round_trip(fd, fd, "fork-child") ? 0 : 1);
	wait(&st);
	printf("CELL fork %s\n",
	       WIFEXITED(st) && WEXITSTATUS(st) == 0 ? "OK" : "FAIL");
	close(fd);

	/* getpeername after connect: the program's destination, not a relay. */
	fd = mksock();
	connect(fd, (struct sockaddr *)&g_dst, g_dlen);
	n = payload(out, "peer");
	send(fd, out, (size_t)n, 0);
	recv(fd, in, sizeof(in), 0);
	printf("CELL getpeername %s\n",
	       getpeername(fd, (struct sockaddr *)&peer, &pl) == 0 &&
	       is_server(&peer) ? "OK" : "FAIL");
	close(fd);

	/* A zero-length datagram.  Whether it survives is mostly the proxy's
	 * decision (INTEROP-CHECKLIST.md 12), so it is recorded, not judged. */
	fd = mksock();
	r = sendto(fd, in, 0, 0, (struct sockaddr *)&g_dst, g_dlen);
	pl = sizeof(src);
	if (r == 0)
		r = recvfrom(fd, in, sizeof(in), 0, (struct sockaddr *)&src, &pl);
	printf("CELL zerolen %s\n", r == 0 ? "OK" : "FAIL");
	close(fd);
}

static void leak(void)
{
	char out[256];
	size_t i;

	for (i = 0; i < sizeof(SENDERS) / sizeof(*SENDERS); i++) {
		int fd = mksock(), n = payload(out, SENDERS[i]);
		ssize_t s = do_send(fd, SENDERS[i], out, (size_t)n);

		printf("LEAK %s %s\n", SENDERS[i],
		       s == n ? "sent" : strerrorname_np(errno));
		close(fd);
	}
}

int main(int argc, char **argv)
{
	struct sockaddr_in *s4 = (struct sockaddr_in *)&g_dst;
	struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&g_dst;

	setvbuf(stdout, NULL, _IOLBF, 0);
	if (argc != 5) {
		fprintf(stderr, "usage: client cell|extra|leak <tag> <ip> <port>\n");
		return 2;
	}
	g_tag = argv[2];
	memset(&g_dst, 0, sizeof(g_dst));
	if (inet_pton(AF_INET, argv[3], &s4->sin_addr) == 1) {
		s4->sin_family = AF_INET;
		s4->sin_port = htons((uint16_t)atoi(argv[4]));
		g_dlen = sizeof(*s4);
	} else if (inet_pton(AF_INET6, argv[3], &s6->sin6_addr) == 1) {
		s6->sin6_family = AF_INET6;
		s6->sin6_port = htons((uint16_t)atoi(argv[4]));
		g_dlen = sizeof(*s6);
	} else {
		return 2;
	}

	if (strcmp(argv[1], "cell") == 0 && getenv("CMP_SENDER") && getenv("CMP_RECVER"))
		cell(getenv("CMP_SENDER"), getenv("CMP_RECVER"));
	else if (strcmp(argv[1], "extra") == 0)
		extra();
	else if (strcmp(argv[1], "leak") == 0)
		leak();
	else
		return 2;
	return 0;
}

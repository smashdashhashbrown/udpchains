/* probe.c -- the client and sink programs for tests/interop/run.sh.
 *
 * The integration tests from `make test` cover the hook matrix, fidelity and
 * lifecycle against any proxy.  What they cannot show is what a REAL proxy does
 * to a datagram on its way through -- truncate it, drop it, or deliver it whole
 * -- or what reaches a destination while the proxy is dead.  Each subcommand
 * below answers one of those, in a line format run.sh parses:
 *
 *   probe sweep  <ip> <port> <size>...  one round-trip per size through an echo
 *                                       server, each on a fresh socket:
 *                                         "<size> whole"
 *                                         "<size> cut <received>"
 *                                         "<size> lost"
 *                                         "<size> refused <ERRNO>"
 *   probe steady <ip> <port> <secs>     one socket, a numbered datagram every
 *                                       100 ms: "sent <n>" or "fail <n> <ERRNO>"
 *   probe idle   <ip> <port> <secs>     a round-trip, <secs> of silence, and a
 *                                       round-trip on the SAME socket (FR-P-08)
 *   probe sink                          binds 127.0.0.1:0, prints "PORT <n>",
 *                                       then "got <ms> <len>" per datagram, with
 *                                       a CLOCK_REALTIME timestamp in ms
 *
 * Run every subcommand but sink under the shim.  sink is the destination, and
 * runs without it, so what it counts is what actually arrived.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define BUF_MAX 70000

static unsigned char g_out[BUF_MAX], g_in[BUF_MAX];

static const char *errname(int e)
{
	const char *n = strerrorname_np(e);

	return n ? n : "unknown";
}

/* Parses <ip> <port> into *ss, IPv4 or IPv6.  Returns the address length, or 0
 * if ip is neither. */
static socklen_t parse_dst(const char *ip, const char *port,
                           struct sockaddr_storage *ss)
{
	struct sockaddr_in *s4 = (struct sockaddr_in *)ss;
	struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ss;

	memset(ss, 0, sizeof(*ss));
	if (inet_pton(AF_INET, ip, &s4->sin_addr) == 1) {
		s4->sin_family = AF_INET;
		s4->sin_port = htons((uint16_t)atoi(port));
		return sizeof(*s4);
	}
	if (inet_pton(AF_INET6, ip, &s6->sin6_addr) == 1) {
		s6->sin6_family = AF_INET6;
		s6->sin6_port = htons((uint16_t)atoi(port));
		return sizeof(*s6);
	}
	return 0;
}

static int udp_socket(int family, int timeout_s)
{
	struct timeval tv = { timeout_s, 0 };
	int fd = socket(family, SOCK_DGRAM, 0);

	if (fd >= 0)
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return fd;
}

static int cmd_sweep(int argc, char **argv)
{
	struct sockaddr_storage dst;
	socklen_t dlen = parse_dst(argv[0], argv[1], &dst);
	int i;

	if (dlen == 0)
		return 2;
	for (i = 2; i < argc; i++) {
		size_t n = strtoul(argv[i], NULL, 10), k;
		ssize_t s, r;
		int fd;

		if (n > BUF_MAX)
			return 2;
		fd = udp_socket(dst.ss_family, 3);
		if (fd < 0)
			return 1;
		/* A pattern that differs per size, so a reply from an earlier
		 * datagram cannot pass for this one. */
		for (k = 0; k < n; k++)
			g_out[k] = (unsigned char)(k * 7 + n);

		s = sendto(fd, g_out, n, 0, (struct sockaddr *)&dst, dlen);
		if (s != (ssize_t)n) {
			printf("%zu refused %s\n", n, errname(errno));
			close(fd);
			continue;
		}
		r = recv(fd, g_in, sizeof(g_in), 0);
		if (r < 0)
			printf("%zu lost\n", n);
		else if ((size_t)r == n && memcmp(g_in, g_out, n) == 0)
			printf("%zu whole\n", n);
		else
			printf("%zu cut %zd\n", n, r);
		close(fd);
	}
	return 0;
}

static int cmd_steady(int argc, char **argv)
{
	struct sockaddr_storage dst;
	socklen_t dlen = parse_dst(argv[0], argv[1], &dst);
	int fd, i, count;
	char b[32];

	if (dlen == 0 || argc < 3)
		return 2;
	fd = udp_socket(dst.ss_family, 1);
	if (fd < 0)
		return 1;
	count = atoi(argv[2]) * 10;
	for (i = 0; i < count; i++) {
		int l = snprintf(b, sizeof(b), "seq %d", i);

		if (sendto(fd, b, (size_t)l, 0, (struct sockaddr *)&dst, dlen) == l)
			printf("sent %d\n", i);
		else
			printf("fail %d %s\n", i, errname(errno));
		usleep(100000);
	}
	return 0;
}

static int round_trip(int fd, const struct sockaddr_storage *dst, socklen_t dlen,
                      const char *msg)
{
	size_t len = strlen(msg);
	ssize_t r;

	if (sendto(fd, msg, len, 0, (const struct sockaddr *)dst, dlen) < 0) {
		printf("fail %s send %s\n", msg, errname(errno));
		return 1;
	}
	r = recv(fd, g_in, sizeof(g_in), 0);
	if (r != (ssize_t)len || memcmp(g_in, msg, len) != 0) {
		printf("fail %s reply %s\n", msg, r < 0 ? errname(errno) : "wrong");
		return 1;
	}
	printf("ok %s\n", msg);
	return 0;
}

static int cmd_idle(int argc, char **argv)
{
	struct sockaddr_storage dst;
	socklen_t dlen = parse_dst(argv[0], argv[1], &dst);
	int fd, failed = 0;

	if (dlen == 0 || argc < 3)
		return 2;
	fd = udp_socket(dst.ss_family, 3);
	if (fd < 0)
		return 1;
	failed |= round_trip(fd, &dst, dlen, "before-idle");
	sleep((unsigned)atoi(argv[2]));
	failed |= round_trip(fd, &dst, dlen, "after-idle");
	close(fd);
	return failed;
}

static int cmd_sink(void)
{
	struct sockaddr_in a = { .sin_family = AF_INET };
	socklen_t alen = sizeof(a);
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
	if (fd < 0 || bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0 ||
	    getsockname(fd, (struct sockaddr *)&a, &alen) != 0)
		return 1;
	printf("PORT %u\n", ntohs(a.sin_port));
	for (;;) {
		struct timespec ts;
		ssize_t r = recv(fd, g_in, sizeof(g_in), 0);

		if (r < 0) {
			if (errno == EINTR)
				continue;
			return 1;
		}
		clock_gettime(CLOCK_REALTIME, &ts);
		printf("got %lld %zd\n",
		       (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000, r);
	}
}

int main(int argc, char **argv)
{
	/* run.sh reads this output while the probe is still running. */
	setvbuf(stdout, NULL, _IOLBF, 0);

	if (argc >= 2 && strcmp(argv[1], "sink") == 0)
		return cmd_sink();
	if (argc >= 5 && strcmp(argv[1], "sweep") == 0)
		return cmd_sweep(argc - 2, argv + 2);
	if (argc == 5 && strcmp(argv[1], "steady") == 0)
		return cmd_steady(argc - 2, argv + 2);
	if (argc == 5 && strcmp(argv[1], "idle") == 0)
		return cmd_idle(argc - 2, argv + 2);
	fprintf(stderr, "usage: probe sweep <ip> <port> <size>... | "
	                "steady <ip> <port> <secs> | idle <ip> <port> <secs> | "
	                "sink\n");
	return 2;
}

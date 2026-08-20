/* bench_latency.c -- NFR-04, added latency per datagram.
 *
 * NFR-04 asks for under 100 us per datagram on loopback, excluding proxy and
 * network time.  D-08 keeps this a REPORTED NUMBER rather than a CI gate: a
 * microsecond threshold enforced in CI is a flaky-test generator, and the
 * number is useful precisely because it is looked at rather than merely
 * asserted.
 *
 * Measured as the delta between the same round-trip run under the shim and run
 * directly.  Both go to the same echo server, so the fixed cost of loopback and
 * the echo server itself cancels out; what remains is the shim plus the proxy
 * hop.  The proxy hop is NOT excluded and is called out in the output, since
 * NFR-04 excludes it and this harness cannot.
 *
 * usage: bench_latency <echoport> [--tag NAME]
 *
 * Run it TWICE -- once under the shim, once directly against the same echo
 * server -- and subtract.  The fixed cost of loopback, the echo server and the
 * syscall path cancels, leaving the shim plus the proxy hop.  The proxy hop is
 * not separable by this harness, so the delta is an UPPER BOUND on the shim's
 * own share, which is the honest form of the NFR-04 claim.  tests/run.sh does
 * both runs and the subtraction; the NFR04 line below is what it parses.
 */
#define _GNU_SOURCE 1

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define WARMUP 200
#define ITERS 2000

static struct sockaddr_in g_echo;

static double now_us(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec * 1e6 + (double)ts.tv_nsec / 1e3;
}

static int cmp_double(const void *a, const void *b)
{
	double x = *(const double *)a, y = *(const double *)b;

	return (x > y) - (x < y);
}

/* Returns 0 on success, filling stats. */
static int measure(int iters, double *out, double *median, double *p99)
{
	struct timeval tv = { 2, 0 };
	char payload[64];
	char buf[256];
	int fd, i, n = 0;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	if (connect(fd, (struct sockaddr *)&g_echo, sizeof(g_echo)) != 0) {
		close(fd);
		return -1;
	}

	memset(payload, 'b', sizeof(payload));

	for (i = 0; i < WARMUP; i++) {
		if (send(fd, payload, sizeof(payload), 0) < 0)
			break;
		if (recv(fd, buf, sizeof(buf), 0) < 0)
			break;
	}

	for (i = 0; i < iters; i++) {
		double t0, t1;

		t0 = now_us();
		if (send(fd, payload, sizeof(payload), 0) < 0)
			continue;
		if (recv(fd, buf, sizeof(buf), 0) < 0)
			continue;
		t1 = now_us();
		out[n++] = t1 - t0;
	}

	close(fd);
	if (n == 0)
		return -1;

	qsort(out, (size_t)n, sizeof(double), cmp_double);
	*median = out[n / 2];
	*p99 = out[(int)((double)n * 0.99)];
	return n;
}

int main(int argc, char **argv)
{
	static double samples[ITERS];
	double median = 0, p99 = 0;
	const char *tag = "run";
	int n, i;

	if (argc < 2) {
		fprintf(stderr, "usage: bench_latency <echoport> [--tag NAME]\n");
		return 2;
	}
	for (i = 2; i < argc; i++) {
		if (strcmp(argv[i], "--tag") == 0 && i + 1 < argc)
			tag = argv[++i];
	}

	memset(&g_echo, 0, sizeof(g_echo));
	g_echo.sin_family = AF_INET;
	g_echo.sin_port = htons((uint16_t)atoi(argv[1]));
	inet_pton(AF_INET, "127.0.0.1", &g_echo.sin_addr);

	n = measure(ITERS, samples, &median, &p99);
	if (n < 0) {
		fprintf(stderr, "bench_latency: no successful round-trips\n");
		return 1;
	}

	printf("#   %-8s median %8.1f us   p99 %8.1f us   (%d samples)\n", tag,
	       median, p99, n);
	/* Machine-readable, parsed by tests/run.sh to do the subtraction. */
	printf("NFR04 %s median=%.1f p99=%.1f n=%d\n", tag, median, p99, n);
	fflush(stdout);
	return 0;
}

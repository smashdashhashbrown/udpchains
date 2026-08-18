/* test_faults.c -- behaviour against an unhelpful proxy.
 *
 * Driven by test_faults.sh, which starts the fixture (D-06) with the matching
 * fault-injection mode.  These are the behaviours no real proxy can be made to
 * exhibit on demand, which is why the fixture exists.
 *
 * usage: test_faults <mode> <echoport> [arg]
 *   reassoc <port> <idle_secs>   FR-P-08 transparent re-association
 *   frag    <port>               FR-P-04 FRAG != 0 is discarded
 *   maxdgram <port>              proxy's limit smaller than ours
 */
#include "tap.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static struct sockaddr_in g_echo;

static int udp4(int timeout_s)
{
	struct timeval tv = { timeout_s, 0 };
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (fd >= 0)
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return fd;
}

static int roundtrip(int fd, const char *what)
{
	char buf[128];
	ssize_t n;
	size_t len = strlen(what);

	if (send(fd, what, len, 0) != (ssize_t)len)
		return 0;
	memset(buf, 0, sizeof(buf));
	n = recv(fd, buf, sizeof(buf), 0);
	return n == (ssize_t)len && memcmp(buf, what, len) == 0;
}

int main(int argc, char **argv)
{
	const char *mode;
	int fd;

	if (argc < 3) {
		fprintf(stderr, "usage: test_faults <mode> <echoport> [arg]\n");
		return 2;
	}
	mode = argv[1];

	memset(&g_echo, 0, sizeof(g_echo));
	g_echo.sin_family = AF_INET;
	g_echo.sin_port = htons((uint16_t)atoi(argv[2]));
	inet_pton(AF_INET, "127.0.0.1", &g_echo.sin_addr);

	if (strcmp(mode, "reassoc") == 0) {
		int idle = (argc > 3) ? atoi(argv[3]) : 2;

		TAP_GROUP("FR-P-08: the proxy expires an idle association");

		fd = udp4(8);
		connect(fd, (struct sockaddr *)&g_echo, sizeof(g_echo));
		TAP_OK(roundtrip(fd, "before-idle"),
		       "traffic flows before the idle period");

		/* Wait past the fixture's expiry so the association is gone and
		 * the relay port stops existing. */
		sleep((unsigned)idle + 2);

		/* Without FR-P-08 this is where a flow dies permanently and
		 * presents as a shim bug.  The application must see a
		 * successful send, not an error it has to handle. */
		TAP_OK(roundtrip(fd, "after-idle"),
		       "traffic flows again: the shim re-associated transparently");
		TAP_OK(roundtrip(fd, "after-reassoc"),
		       "and the new association keeps working");
		close(fd);
	} else if (strcmp(mode, "frag") == 0) {
		char buf[128];
		ssize_t n;

		TAP_GROUP("FR-P-04: a datagram with FRAG != 0 is discarded");

		fd = udp4(2);
		connect(fd, (struct sockaddr *)&g_echo, sizeof(g_echo));

		TAP_EQ_INT(send(fd, "fragged", 7, 0), 7, "the send succeeds");

		/* The proxy sets FRAG=1 on everything it returns.  Those
		 * datagrams must be dropped, never handed to the application --
		 * so the receive finds nothing and times out. */
		errno = 0;
		n = recv(fd, buf, sizeof(buf), 0);
		TAP_EQ_INT(n, -1, "the receive returns nothing");
		TAP_OK(errno == EAGAIN || errno == EWOULDBLOCK,
		       "with EAGAIN: the fragmented datagram was discarded, not "
		       "delivered (errno=%s)",
		       strerror(errno));
		close(fd);
	} else if (strcmp(mode, "maxdgram") == 0) {
		static char big[9000];

		TAP_GROUP("D-12: our configured limit vs the proxy's real one");

		memset(big, 'M', sizeof(big));
		fd = udp4(2);
		connect(fd, (struct sockaddr *)&g_echo, sizeof(g_echo));

		/* Configured max_datagram is 8192, so 9000 is rejected locally
		 * with EMSGSIZE before anything is sent (FR-F-07). */
		errno = 0;
		TAP_EQ_INT(send(fd, big, 9000, 0), -1,
		           "a payload over the configured limit is refused");
		TAP_EQ_INT(errno, EMSGSIZE, "with EMSGSIZE, not a silent drop");

		/* 4096 is under our limit but over the proxy's injected 1000, so
		 * the proxy drops it.  The send succeeds and the reply never
		 * comes -- which is exactly the silent-drop failure D-12 warns
		 * about when the configured limit is wrong.  The association
		 * line reports the configured limit so this is diagnosable. */
		TAP_EQ_INT(send(fd, big, 4096, 0), 4096,
		           "a payload under our limit is sent");
		{
			char buf[8192];
			errno = 0;
			TAP_EQ_INT(recv(fd, buf, sizeof(buf), 0), -1,
			           "but the proxy drops it, so no reply arrives");
		}
		close(fd);
	} else {
		fprintf(stderr, "unknown mode %s\n", mode);
		return 2;
	}

	TAP_DONE();
}

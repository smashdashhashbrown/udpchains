/* test_portswitch.c -- the TFTP pattern: a server that replies from a
 * different port than the one it was addressed on.
 *
 * TFTP addresses port 69 and gets its DATA back from a freshly allocated
 * ephemeral port; the client must notice and re-target.  SIP/RTP and a number
 * of game protocols do the same.  It is the only common shape whose
 * CORRECTNESS depends on FR-F-02: a client like nc ignores the source address
 * entirely and would pass even if the shim reported the relay.
 *
 * Two halves, and they are supposed to disagree:
 *
 *   unconnected socket -- works.  This is what real TFTP clients use, and
 *                         precisely why they use it.
 *   connected socket   -- the reply is refused, because the kernel refuses it
 *                         too (D-15).  A client that connects to port 69 is
 *                         broken with or without the shim, and the shim must
 *                         not paper over that.
 *
 * Run under the shim:  udpchains ./test_portswitch <switching_echo_port>
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

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: test_portswitch <switching_echo_port>\n");
		return 2;
	}

	memset(&g_echo, 0, sizeof(g_echo));
	g_echo.sin_family = AF_INET;
	g_echo.sin_port = htons((uint16_t)atoi(argv[1]));
	inet_pton(AF_INET, "127.0.0.1", &g_echo.sin_addr);

	TAP_GROUP("unconnected socket: the TFTP pattern works");
	{
		int fd = udp4(4);
		struct sockaddr_in from;
		socklen_t flen = sizeof(from);
		char buf[64];
		ssize_t n;
		uint16_t first_port, reply_port;

		first_port = ntohs(g_echo.sin_port);

		n = sendto(fd, "RRQ", 3, 0, (struct sockaddr *)&g_echo,
		           sizeof(g_echo));
		TAP_EQ_INT(n, 3, "the initial request is sent to the well-known port");

		memset(&from, 0, sizeof(from));
		n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&from,
		             &flen);
		TAP_EQ_INT(n, 3, "the reply arrives");
		TAP_OK(memcmp(buf, "RRQ", 3) == 0, "with the expected payload");

		reply_port = ntohs(from.sin_port);
		TAP_OK(reply_port != 0 && reply_port != first_port,
		       "and its source is a DIFFERENT port (%u, not %u) -- FR-F-02 "
		       "is what makes this visible",
		       reply_port, first_port);

		/* The whole point: continue the conversation at the new port. */
		{
			struct sockaddr_in second = g_echo;
			second.sin_port = htons(reply_port);

			n = sendto(fd, "ACK", 3, 0, (struct sockaddr *)&second,
			           sizeof(second));
			TAP_EQ_INT(n, 3, "the follow-up is sent to the new port");

			memset(buf, 0, sizeof(buf));
			memset(&from, 0, sizeof(from));
			flen = sizeof(from);
			n = recvfrom(fd, buf, sizeof(buf), 0,
			             (struct sockaddr *)&from, &flen);
			TAP_EQ_INT(n, 3, "and is answered");
			TAP_OK(memcmp(buf, "ACK", 3) == 0, "with the right payload");
			TAP_EQ_INT(ntohs(from.sin_port), reply_port,
			           "from the same switched port");
		}
		close(fd);
	}

	TAP_GROUP("connected socket: the reply is refused, as the kernel would");
	{
		int fd = udp4(2);
		char buf[64];
		ssize_t n;

		/* A client that connects to the well-known port cannot receive
		 * the reply, because it arrives from a different one.  That is
		 * true without the shim, and D-15 makes it true with it.  If
		 * this ever "passes" by delivering the datagram, the shim has
		 * become more permissive than a real socket. */
		TAP_EQ_INT(connect(fd, (struct sockaddr *)&g_echo, sizeof(g_echo)),
		           0, "connect to the well-known port succeeds");

		n = send(fd, "RRQ2", 4, 0);
		TAP_EQ_INT(n, 4, "the request is sent");

		errno = 0;
		n = recv(fd, buf, sizeof(buf), 0);
		TAP_EQ_INT(n, -1, "the reply from the switched port is NOT delivered");
		TAP_OK(errno == EAGAIN || errno == EWOULDBLOCK,
		       "the receive times out with EAGAIN, exactly as an unhooked "
		       "connected socket would (errno=%s)",
		       strerror(errno));
	}

	TAP_DONE();
}

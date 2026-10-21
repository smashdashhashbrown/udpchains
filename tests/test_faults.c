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
 *   forged  <port> <secs>        FR-CH-T3: under a chain, nothing forged at a
 *                                later hop's relay is delivered (D-41)
 *   forge   <port> <relayport>   the forger: run WITHOUT the shim
 *   fdband  <port> <limit>       FR-CH-10: the shim's descriptors run out
 */
#include "tap.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <sys/wait.h>
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
	} else if (strcmp(mode, "mcast-burst") == 0) {
		/* D-33: a warning that fires per datagram.  The script counts
		 * how many reach stderr. */
		struct sockaddr_in mc;
		int i, refused = 0;

		memset(&mc, 0, sizeof(mc));
		mc.sin_family = AF_INET;
		mc.sin_port = htons(5000);
		inet_pton(AF_INET, "239.1.2.3", &mc.sin_addr);
		fd = udp4(1);
		for (i = 0; i < 50; i++)
			if (sendto(fd, "m", 1, 0, (struct sockaddr *)&mc, sizeof(mc)) == -1 &&
			    errno == ENETUNREACH)
				refused++;
		TAP_EQ_INT(refused, 50, "all 50 multicast sends are refused");
		close(fd);
	} else if (strcmp(mode, "stderr-reused") == 0) {
		/* D-33: a daemon closes stderr, and the next descriptor it opens
		 * -- its log file -- is given number 2.  A warning from the shim
		 * must not end up inside that file. */
		struct sockaddr_in mc;
		char buf[512];
		ssize_t n;
		int f;

		memset(&mc, 0, sizeof(mc));
		mc.sin_family = AF_INET;
		mc.sin_port = htons(5000);
		inet_pton(AF_INET, "239.1.2.3", &mc.sin_addr);
		fd = udp4(1);

		close(2);
		f = open(argv[3], O_RDWR | O_CREAT | O_TRUNC, 0600);
		TAP_EQ_INT(f, 2, "the program's own file is given descriptor 2");
		TAP_OK(sendto(fd, "m", 1, 0, (struct sockaddr *)&mc, sizeof(mc)) == -1,
		       "a multicast send, which the shim warns about, is refused");
		lseek(f, 0, SEEK_SET);
		n = read(f, buf, sizeof(buf) - 1);
		buf[n > 0 ? n : 0] = '\0';
		TAP_OK(strstr(buf, "udpchains") == NULL,
		       "and the warning is not written into the program's file");
		close(fd);
	} else if (strcmp(mode, "forkbind") == 0) {
		/* D-34, against a proxy that pins each association to the
		 * address it declares (--pin-declared).  The parent binds a
		 * concrete address and port, so its association declares them.
		 * A forked child cannot bind that port again -- the parent
		 * still holds it -- so its private socket sends from another.
		 * Declaring the parent's address anyway, as the shim once did,
		 * gets every one of the child's datagrams dropped. */
		struct sockaddr_in b;
		socklen_t bl = sizeof(b);
		int probe, status = 0;
		pid_t pid;

		memset(&b, 0, sizeof(b));
		b.sin_family = AF_INET;
		b.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		probe = socket(AF_INET, SOCK_DGRAM, 0);
		bind(probe, (struct sockaddr *)&b, sizeof(b));
		getsockname(probe, (struct sockaddr *)&b, &bl);
		close(probe);

		fd = udp4(3);
		TAP_EQ_INT(bind(fd, (struct sockaddr *)&b, sizeof(b)), 0,
		           "the parent binds 127.0.0.1:%u", ntohs(b.sin_port));
		connect(fd, (struct sockaddr *)&g_echo, sizeof(g_echo));
		TAP_OK(roundtrip(fd, "parent-bound"),
		       "its association declares that address, and works against "
		       "a proxy that enforces it");

		pid = fork();
		if (pid == 0)
			_exit(roundtrip(fd, "child-bound") ? 0 : 1);
		waitpid(pid, &status, 0);
		TAP_OK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		       "a forked child, unable to bind that port again, still "
		       "round-trips: it stops declaring an address it cannot "
		       "send from");
		TAP_OK(roundtrip(fd, "parent-after"),
		       "and the parent's association is untouched");
		close(fd);
	} else if (strcmp(mode, "forged") == 0) {
		/* Run under a 3-hop chain.  test_faults.sh, seeing READY, runs
		 * the forge mode below against hop 2's relay: a datagram that
		 * hop 2 wraps as from the forger, and hop 1 as from hop 2's
		 * relay -- a genuine outer layer.  Inside is a header claiming
		 * the echo server, which, were the layers under the outermost
		 * not checked (D-41), the shim would take as the innermost and
		 * deliver.  It is from the echo server's address, so even a
		 * connected socket would accept it. */
		int secs = (argc > 3) ? atoi(argv[3]) : 4;
		int delivered = 0;
		time_t end;

		TAP_GROUP("FR-CH-T3: a forged inner source behind a genuine outer one");

		fd = udp4(1);
		connect(fd, (struct sockaddr *)&g_echo, sizeof(g_echo));
		TAP_OK(roundtrip(fd, "genuine"), "traffic flows through the chain");

		printf("# READY\n");
		fflush(stdout);
		end = time(NULL) + secs;
		while (time(NULL) < end) {
			char buf[128];

			if (recv(fd, buf, sizeof(buf), 0) >= 0)
				delivered++;
		}
		TAP_EQ_INT(delivered, 0,
		           "nothing sent to hop 2's relay is delivered, though it "
		           "names the echo server inside");
		TAP_OK(roundtrip(fd, "genuine-after"),
		       "and genuine traffic still flows");
		close(fd);
	} else if (strcmp(mode, "forge") == 0) {
		/* Not under the shim.  RFC 1928 §7 header naming 127.0.0.1 and
		 * the echo port, then a payload. */
		struct sockaddr_in relay;
		uint8_t dgram[64] = { 0, 0, 0, 0x01, 127, 0, 0, 1 };
		size_t len = 10;
		int i, sent = 0;

		TAP_GROUP("the forger");
		memcpy(dgram + 8, &g_echo.sin_port, 2);
		memcpy(dgram + len, "forged", 6);
		len += 6;
		memset(&relay, 0, sizeof(relay));
		relay.sin_family = AF_INET;
		relay.sin_port = htons((uint16_t)atoi(argv[3]));
		inet_pton(AF_INET, "127.0.0.1", &relay.sin_addr);
		fd = socket(AF_INET, SOCK_DGRAM, 0);
		for (i = 0; i < 5; i++)
			if (sendto(fd, dgram, len, 0, (struct sockaddr *)&relay,
			           sizeof(relay)) == (ssize_t)len)
				sent++;
		TAP_EQ_INT(sent, 5, "5 forged datagrams sent to port %u",
		           ntohs(relay.sin_port));
		close(fd);
	} else if (strcmp(mode, "fdband") == 0) {
		/* FR-CH-10, D-46.  Under a chain each socket's association holds
		 * a control connection per hop, in the shim's range: half the
		 * soft limit and up, here.  Sockets are opened and sent on
		 * until descriptors run out.  test_faults.sh checks that the
		 * range filling was reported, that associations kept working
		 * past it, and that every send reported as sent went through
		 * the chain. */
		struct rlimit rl;
		int limit = (argc > 3) ? atoi(argv[3]) : 64;
		int sent_ok = 0, err = 0, spare, s;

		TAP_GROUP("FR-CH-10: the shim's descriptors run out");

		getrlimit(RLIMIT_NOFILE, &rl);
		rl.rlim_cur = (rlim_t)limit;
		TAP_EQ_INT(setrlimit(RLIMIT_NOFILE, &rl), 0,
		           "the soft limit is lowered to %d", limit);
		/* Held back, so that whichever runs out first -- the program's
		 * socket() or the shim's connections -- the last send below
		 * has a socket and the shim has nothing. */
		spare = dup(0);

		for (;;) {
			s = socket(AF_INET, SOCK_DGRAM, 0);
			if (s < 0)
				break;
			if (sendto(s, "band", 4, 0, (struct sockaddr *)&g_echo,
			           sizeof(g_echo)) != 4) {
				err = errno;
				break;
			}
			sent_ok++;
		}
		if (s < 0) {
			close(spare);
			s = socket(AF_INET, SOCK_DGRAM, 0);
			errno = 0;
			if (sendto(s, "band", 4, 0, (struct sockaddr *)&g_echo,
			           sizeof(g_echo)) == 4)
				sent_ok++;
			else
				err = errno;
		}
		/* Exiting closes every control connection, and a hop that
		 * sees its close first tears the association down with the
		 * last datagram still unforwarded.  The count must match. */
		sleep(1);
		printf("# sent_ok=%d\n", sent_ok);
		TAP_OK(sent_ok > 0, "%d sockets sent before descriptors ran out",
		       sent_ok);
		TAP_EQ_INT(err, EMFILE,
		           "then the shim, with no descriptor for a hop, fails the "
		           "send with EMFILE (%s)",
		           strerror(err));
	} else {
		fprintf(stderr, "unknown mode %s\n", mode);
		return 2;
	}

	TAP_DONE();
}

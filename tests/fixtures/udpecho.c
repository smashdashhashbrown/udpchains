/* udpecho.c -- trivial UDP echo server, test fixture only (D-06).
 *
 * Echoes every datagram back to its sender, preserving length exactly --
 * including zero-length datagrams, which FR-F-06 requires round-trip as
 * zero-length and distinct from "no datagram".
 *
 * usage: udpecho [--port N] [-6] [--quiet] [--switch-port]
 * Prints "PORT <n>" on stdout once bound.
 *
 * --switch-port reproduces TFTP's defining behaviour: the first datagram is
 * answered from a DIFFERENT, freshly bound port, and the conversation continues
 * there.  A client must notice the new source and re-target, which is why real
 * TFTP clients use an unconnected socket -- a connected one would have the
 * kernel drop the reply.  Both halves of that are worth testing.
 */
#define _GNU_SOURCE 1

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	int port = 0;
	bool v6 = false, quiet = false, switch_port = false;
	int fd, reply_fd = -1;
	struct sockaddr_storage addr;
	socklen_t alen;
	static unsigned char buf[70000];

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)
			port = atoi(argv[++i]);
		else if (strcmp(argv[i], "-6") == 0)
			v6 = true;
		else if (strcmp(argv[i], "--quiet") == 0)
			quiet = true;
		else if (strcmp(argv[i], "--switch-port") == 0)
			switch_port = true;
		else {
			fprintf(stderr, "udpecho: unknown option %s\n", argv[i]);
			return 1;
		}
	}

	signal(SIGPIPE, SIG_IGN);

	fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		return 1;
	}

	memset(&addr, 0, sizeof(addr));
	if (v6) {
		struct sockaddr_in6 *a = (struct sockaddr_in6 *)&addr;
		a->sin6_family = AF_INET6;
		a->sin6_addr = in6addr_loopback;
		a->sin6_port = htons((uint16_t)port);
		alen = sizeof(*a);
	} else {
		struct sockaddr_in *a = (struct sockaddr_in *)&addr;
		a->sin_family = AF_INET;
		a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		a->sin_port = htons((uint16_t)port);
		alen = sizeof(*a);
	}

	if (bind(fd, (struct sockaddr *)&addr, alen) != 0) {
		perror("bind");
		return 1;
	}

	alen = sizeof(addr);
	if (getsockname(fd, (struct sockaddr *)&addr, &alen) != 0) {
		perror("getsockname");
		return 1;
	}
	printf("PORT %u\n",
	       ntohs(v6 ? ((struct sockaddr_in6 *)&addr)->sin6_port
	                : ((struct sockaddr_in *)&addr)->sin_port));
	fflush(stdout);

	for (;;) {
		struct sockaddr_storage from;
		socklen_t flen = sizeof(from);
		struct pollfd pfd[2];
		int nfds = 1, r, src;
		ssize_t n;

		pfd[0].fd = fd;
		pfd[0].events = POLLIN;
		pfd[0].revents = 0;
		if (reply_fd >= 0) {
			pfd[1].fd = reply_fd;
			pfd[1].events = POLLIN;
			pfd[1].revents = 0;
			nfds = 2;
		}

		r = poll(pfd, (nfds_t)nfds, -1);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		if (pfd[0].revents & POLLIN)
			src = fd;
		else if (nfds == 2 && (pfd[1].revents & POLLIN))
			src = reply_fd;
		else
			continue;

		n = recvfrom(src, buf, sizeof(buf), 0, (struct sockaddr *)&from,
		             &flen);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		/* TFTP's port switch: answer the first datagram from a new port
		 * and carry on there.  Everything after arrives on reply_fd
		 * already, so it is simply echoed back from the same socket. */
		if (switch_port && reply_fd < 0 && src == fd) {
			struct sockaddr_storage ra;
			socklen_t ral;

			reply_fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
			if (reply_fd >= 0) {
				memset(&ra, 0, sizeof(ra));
				if (v6) {
					struct sockaddr_in6 *a =
						(struct sockaddr_in6 *)&ra;
					a->sin6_family = AF_INET6;
					a->sin6_addr = in6addr_loopback;
					ral = sizeof(*a);
				} else {
					struct sockaddr_in *a =
						(struct sockaddr_in *)&ra;
					a->sin_family = AF_INET;
					a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
					ral = sizeof(*a);
				}
				if (bind(reply_fd, (struct sockaddr *)&ra, ral) != 0) {
					close(reply_fd);
					reply_fd = -1;
				}
			}
			if (!quiet && reply_fd >= 0) {
				ral = sizeof(ra);
				getsockname(reply_fd, (struct sockaddr *)&ra, &ral);
				fprintf(stderr,
				        "udpecho: switching to port %u for the reply\n",
				        ntohs(v6 ? ((struct sockaddr_in6 *)&ra)->sin6_port
				                 : ((struct sockaddr_in *)&ra)->sin_port));
				fflush(stderr);
			}
		}

		if (!quiet) {
			fprintf(stderr, "udpecho: %zd bytes\n", n);
			fflush(stderr);
		}

		/* n may be 0; sendto with length 0 is correct and required. */
		(void)sendto(switch_port && reply_fd >= 0 ? reply_fd : src, buf,
		             (size_t)n, 0, (struct sockaddr *)&from, flen);
	}

	if (reply_fd >= 0)
		close(reply_fd);
	close(fd);
	return 0;
}

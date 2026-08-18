/* udpecho.c -- trivial UDP echo server, test fixture only (D-06).
 *
 * Echoes every datagram back to its sender, preserving length exactly --
 * including zero-length datagrams, which FR-F-06 requires round-trip as
 * zero-length and distinct from "no datagram".
 *
 * usage: udpecho [--port N] [-6] [--quiet]
 * Prints "PORT <n>" on stdout once bound.
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
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	int port = 0;
	bool v6 = false, quiet = false;
	int fd;
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
		ssize_t n = recvfrom(fd, buf, sizeof(buf), 0,
		                     (struct sockaddr *)&from, &flen);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (!quiet) {
			fprintf(stderr, "udpecho: %zd bytes\n", n);
			fflush(stderr);
		}
		/* n may be 0; sendto with length 0 is correct and required. */
		(void)sendto(fd, buf, (size_t)n, 0, (struct sockaddr *)&from, flen);
	}

	close(fd);
	return 0;
}

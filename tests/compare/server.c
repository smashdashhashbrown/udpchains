/* server.c -- the echo server for tests/compare/run.sh.
 *
 * Echoes every datagram on IPv4 and IPv6, and logs where it came from:
 *
 *   ECHO <source address> <length> <printable tag prefix>
 *
 * A datagram from the proxy's address went through the proxy; one from the
 * client's own address did not.  This log, not any tool's report, is the
 * evidence the comparison rests on.
 *
 * usage: server <port>
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

static unsigned char g_buf[70000];

int main(int argc, char **argv)
{
	struct sockaddr_in a4 = { .sin_family = AF_INET };
	struct sockaddr_in6 a6 = { .sin6_family = AF_INET6, .sin6_addr = IN6ADDR_ANY_INIT };
	struct pollfd p[2];
	int on = 1, i;

	if (argc != 2)
		return 2;
	a4.sin_port = a6.sin6_port = htons((uint16_t)atoi(argv[1]));
	setvbuf(stdout, NULL, _IOLBF, 0);

	p[0].fd = socket(AF_INET, SOCK_DGRAM, 0);
	p[1].fd = socket(AF_INET6, SOCK_DGRAM, 0);
	setsockopt(p[1].fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
	if (bind(p[0].fd, (struct sockaddr *)&a4, sizeof(a4)) != 0 ||
	    bind(p[1].fd, (struct sockaddr *)&a6, sizeof(a6)) != 0) {
		perror("bind");
		return 1;
	}
	for (i = 0; i < 2; i++)
		p[i].events = POLLIN;

	for (;;) {
		if (poll(p, 2, -1) < 0)
			continue;
		for (i = 0; i < 2; i++) {
			struct sockaddr_storage s;
			socklen_t sl = sizeof(s);
			char host[INET6_ADDRSTRLEN], tag[80];
			size_t k = 0;
			ssize_t n;

			if (!(p[i].revents & POLLIN))
				continue;
			n = recvfrom(p[i].fd, g_buf, sizeof(g_buf), 0,
			             (struct sockaddr *)&s, &sl);
			if (n < 0)
				continue;
			if (s.ss_family == AF_INET)
				inet_ntop(AF_INET, &((struct sockaddr_in *)&s)->sin_addr,
				          host, sizeof(host));
			else
				inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&s)->sin6_addr,
				          host, sizeof(host));
			while (k < (size_t)n && k < sizeof(tag) - 1 &&
			       g_buf[k] >= 32 && g_buf[k] < 127) {
				tag[k] = (char)g_buf[k];
				k++;
			}
			tag[k] = '\0';
			printf("ECHO %s %zd %s\n", host, n, k ? tag : "-");
			sendto(p[i].fd, g_buf, (size_t)n, 0, (struct sockaddr *)&s, sl);
		}
	}
}

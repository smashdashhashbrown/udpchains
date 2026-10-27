/* dnsd.c -- minimal authoritative DNS server, test fixture only (D-22).
 *
 * Never linked into the shipped shim.  Answers a fixed zone over UDP and TCP on
 * the same port, so the shim's resolver can be tested end to end through the
 * fixture proxy -- including the truncated-answer path, which a public resolver
 * cannot be made to produce on demand.
 *
 * The zone (all class IN):
 *
 *   a.test              A 192.0.2.1, AAAA 2001:db8::1
 *   multi.test          A 192.0.2.10, A 192.0.2.11
 *   alias.test          CNAME a.test
 *   v4only.test         A 192.0.2.4            (AAAA: NOERROR, no data)
 *   host.search.test    A 192.0.2.20           (for dns_search)
 *   nss.local           A 192.0.2.77           (found only if a lookup that
 *                                               mDNS would answer reaches DNS,
 *                                               D-55)
 *   big.test            100 x A 198.51.100.x   (truncated over UDP; whole over TCP)
 *   loop.test           CNAME loop2.test, which CNAMEs back to loop.test
 *   1.2.0.192.in-addr.arpa and the ip6.arpa name of 2001:db8::1   PTR a.test
 *   anything else       NXDOMAIN
 *
 * Every query is logged to stderr as "QUERY <udp|tcp> <type> <name>", unless
 * --quiet, so a test can count exactly what reached the resolver.
 *
 * usage: dnsd [--port N] [--quiet]
 * Prints "PORT <n>" on stdout once listening.
 */
#define _GNU_SOURCE 1

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#define T_A 1
#define T_CNAME 5
#define T_PTR 12
#define T_AAAA 28
#define T_OPT 41

static bool g_quiet;

struct msg {
	uint8_t b[65535];
	size_t n;
};

static void put16(struct msg *m, uint16_t v)
{
	m->b[m->n++] = (uint8_t)(v >> 8);
	m->b[m->n++] = (uint8_t)v;
}

static void put_name(struct msg *m, const char *name)
{
	const char *p = name;

	while (*p != '\0') {
		const char *dot = strchr(p, '.');
		size_t l = dot ? (size_t)(dot - p) : strlen(p);

		m->b[m->n++] = (uint8_t)l;
		memcpy(m->b + m->n, p, l);
		m->n += l;
		p += l;
		if (*p == '.')
			p++;
	}
	m->b[m->n++] = 0;
}

static void put_rr(struct msg *m, const char *owner, uint16_t type,
                   const void *rdata, uint16_t rdlen)
{
	put_name(m, owner);
	put16(m, type);
	put16(m, 1);
	put16(m, 0);
	put16(m, 60); /* TTL */
	put16(m, rdlen);
	memcpy(m->b + m->n, rdata, rdlen);
	m->n += rdlen;
}

static void put_name_rr(struct msg *m, const char *owner, uint16_t type,
                        const char *target)
{
	struct msg tmp;

	tmp.n = 0;
	put_name(&tmp, target);
	put_rr(m, owner, type, tmp.b, (uint16_t)tmp.n);
}

static void put_a(struct msg *m, const char *owner, const char *ip)
{
	uint8_t b[4];

	inet_pton(AF_INET, ip, b);
	put_rr(m, owner, T_A, b, 4);
}

static void put_aaaa(struct msg *m, const char *owner, const char *ip)
{
	uint8_t b[16];

	inet_pton(AF_INET6, ip, b);
	put_rr(m, owner, T_AAAA, b, 16);
}

/* Appends the answer records for (name, type).  Returns the rcode. */
static int answer(struct msg *m, const char *name, uint16_t type, unsigned *an)
{
	char q[256];
	size_t i;

#define ANS(stmt) do { stmt; (*an)++; } while (0)

	snprintf(q, sizeof(q), "%s", name);
	for (i = 0; q[i]; i++)
		if (q[i] >= 'A' && q[i] <= 'Z')
			q[i] = (char)(q[i] - 'A' + 'a');

	if (strcmp(q, "a.test") == 0) {
		if (type == T_A)
			ANS(put_a(m, name, "192.0.2.1"));
		if (type == T_AAAA)
			ANS(put_aaaa(m, name, "2001:db8::1"));
		return 0;
	}
	if (strcmp(q, "multi.test") == 0) {
		if (type == T_A) {
			ANS(put_a(m, name, "192.0.2.10"));
			ANS(put_a(m, name, "192.0.2.11"));
		}
		return 0;
	}
	if (strcmp(q, "alias.test") == 0) {
		ANS(put_name_rr(m, name, T_CNAME, "a.test"));
		if (type == T_A)
			ANS(put_a(m, "a.test", "192.0.2.1"));
		if (type == T_AAAA)
			ANS(put_aaaa(m, "a.test", "2001:db8::1"));
		return 0;
	}
	if (strcmp(q, "v4only.test") == 0) {
		if (type == T_A)
			ANS(put_a(m, name, "192.0.2.4"));
		return 0;
	}
	if (strcmp(q, "host.search.test") == 0) {
		if (type == T_A)
			ANS(put_a(m, name, "192.0.2.20"));
		return 0;
	}
	if (strcmp(q, "nss.local") == 0) {
		if (type == T_A)
			ANS(put_a(m, name, "192.0.2.77"));
		return 0;
	}
	if (strcmp(q, "big.test") == 0) {
		if (type == T_A)
			for (i = 1; i <= 100; i++) {
				char ip[32];
				snprintf(ip, sizeof(ip), "198.51.100.%zu", i);
				ANS(put_a(m, name, ip));
			}
		return 0;
	}
	if (strcmp(q, "loop.test") == 0) {
		ANS(put_name_rr(m, name, T_CNAME, "loop2.test"));
		ANS(put_name_rr(m, "loop2.test", T_CNAME, "loop.test"));
		return 0;
	}
	if (strcmp(q, "1.2.0.192.in-addr.arpa") == 0 ||
	    strcmp(q, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa") == 0) {
		if (type == T_PTR)
			ANS(put_name_rr(m, name, T_PTR, "a.test"));
		return 0;
	}
#undef ANS
	return 3; /* NXDOMAIN */
}

/* Parses the query in q and writes the response to r.  max is the most the
 * transport can carry: past it, the response is cut to the header and question
 * with TC set, as a real server does over UDP.  Returns -1 for garbage. */
static int respond(const uint8_t *q, size_t qn, struct msg *r, size_t max,
                   const char *proto)
{
	char name[256];
	size_t off = 12, nl = 0, qend;
	uint16_t type;
	unsigned an = 0;
	int rcode;

	if (qn < 12 || (q[4] << 8 | q[5]) != 1)
		return -1;
	while (off < qn && q[off] != 0) {
		size_t l = q[off];
		if (l > 63 || off + 1 + l >= qn || nl + l + 1 >= sizeof(name))
			return -1;
		if (nl > 0)
			name[nl++] = '.';
		memcpy(name + nl, q + off + 1, l);
		nl += l;
		off += 1 + l;
	}
	name[nl] = '\0';
	if (off + 5 > qn)
		return -1;
	qend = off + 5;
	type = (uint16_t)(q[off + 1] << 8 | q[off + 2]);

	if (!g_quiet)
		fprintf(stderr, "QUERY %s %u %s\n", proto, type, name);

	r->n = 0;
	memcpy(r->b, q, 2);  /* ID */
	r->b[2] = 0x80 | (q[2] & 0x01); /* QR, echo RD */
	r->b[3] = 0x80;                 /* RA */
	memset(r->b + 4, 0, 8);
	r->b[5] = 1; /* QDCOUNT */
	r->n = 12;
	memcpy(r->b + r->n, q + 12, qend - 12);
	r->n += qend - 12;

	rcode = answer(r, name, type, &an);
	r->b[3] |= (uint8_t)rcode;
	r->b[6] = (uint8_t)(an >> 8);
	r->b[7] = (uint8_t)an;

	if (r->n > max) {
		r->n = qend;
		r->b[2] |= 0x02; /* TC */
		r->b[6] = r->b[7] = 0;
	}
	return 0;
}

/* The UDP payload size the client offered in an EDNS0 OPT record, or 512. */
static size_t edns_size(const uint8_t *q, size_t qn)
{
	size_t off = 12;

	while (off < qn && q[off] != 0)
		off += 1 + q[off];
	off += 5; /* root, QTYPE, QCLASS */
	if ((q[10] << 8 | q[11]) >= 1 && off + 11 <= qn && q[off] == 0 &&
	    (q[off + 1] << 8 | q[off + 2]) == T_OPT) {
		size_t s = (size_t)(q[off + 3] << 8 | q[off + 4]);
		return s < 512 ? 512 : s;
	}
	return 512;
}

static int read_full(int fd, uint8_t *b, size_t n)
{
	size_t off = 0;

	while (off < n) {
		ssize_t k = read(fd, b + off, n - off);
		if (k <= 0) {
			if (k < 0 && errno == EINTR)
				continue;
			return -1;
		}
		off += (size_t)k;
	}
	return 0;
}

static void serve_tcp(int fd)
{
	static uint8_t q[65535];
	static struct msg r;
	uint8_t l2[2];

	for (;;) {
		size_t qn;

		if (read_full(fd, l2, 2) != 0)
			break;
		qn = (size_t)(l2[0] << 8 | l2[1]);
		if (read_full(fd, q, qn) != 0 || respond(q, qn, &r, 65535, "tcp") != 0)
			break;
		l2[0] = (uint8_t)(r.n >> 8);
		l2[1] = (uint8_t)r.n;
		if (write(fd, l2, 2) != 2 || write(fd, r.b, r.n) != (ssize_t)r.n)
			break;
	}
	close(fd);
}

int main(int argc, char **argv)
{
	int port = 0, udp = -1, tcp = -1, tries, one = 1, zero = 0;
	struct sockaddr_in6 a;
	socklen_t al = sizeof(a);
	static uint8_t q[65535];
	static struct msg r;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)
			port = atoi(argv[++i]);
		else if (strcmp(argv[i], "--quiet") == 0)
			g_quiet = true;
		else {
			fprintf(stderr, "dnsd: unknown option %s\n", argv[i]);
			return 1;
		}
	}
	signal(SIGPIPE, SIG_IGN);

	/* UDP and TCP on the same port number, dual-stack.  With an ephemeral
	 * port the TCP bind can collide, so retry with a fresh UDP port. */
	for (tries = 0; tries < 50; tries++) {
		udp = socket(AF_INET6, SOCK_DGRAM, 0);
		tcp = socket(AF_INET6, SOCK_STREAM, 0);
		setsockopt(udp, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));
		setsockopt(tcp, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));
		setsockopt(tcp, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
		memset(&a, 0, sizeof(a));
		a.sin6_family = AF_INET6;
		a.sin6_addr = in6addr_any;
		a.sin6_port = htons((uint16_t)port);
		al = sizeof(a);
		if (bind(udp, (struct sockaddr *)&a, sizeof(a)) == 0 &&
		    getsockname(udp, (struct sockaddr *)&a, &al) == 0 &&
		    bind(tcp, (struct sockaddr *)&a, sizeof(a)) == 0 &&
		    listen(tcp, 16) == 0)
			break;
		close(udp);
		close(tcp);
		udp = tcp = -1;
		if (port != 0)
			break;
	}
	if (udp < 0) {
		perror("dnsd: bind");
		return 1;
	}
	printf("PORT %u\n", ntohs(a.sin6_port));
	fflush(stdout);

	for (;;) {
		struct pollfd pfd[2] = { { udp, POLLIN, 0 }, { tcp, POLLIN, 0 } };

		if (poll(pfd, 2, -1) < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (pfd[0].revents & POLLIN) {
			struct sockaddr_storage from;
			socklen_t fl = sizeof(from);
			ssize_t n = recvfrom(udp, q, sizeof(q), 0,
			                     (struct sockaddr *)&from, &fl);

			if (n > 0 && respond(q, (size_t)n, &r, edns_size(q, (size_t)n),
			                     "udp") == 0)
				(void)sendto(udp, r.b, r.n, 0, (struct sockaddr *)&from, fl);
		}
		if (pfd[1].revents & POLLIN) {
			int c = accept(tcp, NULL, NULL);
			if (c >= 0)
				serve_tcp(c);
		}
	}
	return 0;
}

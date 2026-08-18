/* socks5d.c -- minimal SOCKS5 UDP ASSOCIATE server, test fixture only (D-06).
 *
 * Never linked into the shipped shim.  Implements just enough of RFC 1928 to
 * exercise the shim, plus fault injection that a real proxy cannot be made to
 * perform on demand: expiring an association, injecting FRAG != 0, refusing
 * UDP ASSOCIATE, dropping datagrams, enforcing the peer lock.
 *
 * Interop against a real proxy is a separate, manual step (TST-04).  A green
 * run against this fixture is not evidence of interop.
 *
 * usage: socks5d [options]
 *   --port N            listen port (0 = ephemeral, the default)
 *   --refuse-associate  reply to UDP ASSOCIATE with a general failure
 *   --auth-required     offer only username/password, which v1 cannot do
 *   --expire-after N    tear the association down after N seconds idle
 *   --drop-nth N        drop every Nth relayed datagram
 *   --delay-ms N        delay each relayed datagram
 *   --max-dgram N       drop payloads larger than N (default 8192)
 *   --frag-inject       set FRAG=1 on datagrams sent to the client
 *   --no-peer-lock      accept client datagrams from any source address
 *   --reject-atyp N     reject requests carrying this ATYP
 *   --quiet             suppress the per-datagram log
 *
 * Prints "PORT <n>" on stdout once listening, so tests can use an ephemeral
 * port without racing.
 */
#define _GNU_SOURCE 1

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define SOCKS_VER 0x05
#define METHOD_NONE 0x00
#define METHOD_USERPASS 0x02
#define METHOD_UNACCEPTABLE 0xff
#define CMD_UDP_ASSOCIATE 0x03

#define ATYP_IPV4 0x01
#define ATYP_DOMAIN 0x03
#define ATYP_IPV6 0x04

#define HDR_MAX 262
#define BUF_MAX 70000

static struct {
	int port;
	bool refuse_associate;
	bool auth_required;
	int expire_after;
	int drop_nth;
	int delay_ms;
	size_t max_dgram;
	bool frag_inject;
	bool peer_lock;
	int reject_atyp;
	bool quiet;
} opt = { 0, false, false, 0, 0, 0, 8192, false, true, -1, false };

static void logf_(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));

static void logf_(const char *fmt, ...)
{
	va_list ap;
	if (opt.quiet)
		return;
	fprintf(stderr, "socks5d: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	fflush(stderr);
}

static int read_all(int fd, uint8_t *buf, size_t len)
{
	size_t off = 0;
	while (off < len) {
		ssize_t n = read(fd, buf + off, len - off);
		if (n > 0) {
			off += (size_t)n;
			continue;
		}
		if (n < 0 && errno == EINTR)
			continue;
		return -1;
	}
	return 0;
}

static int write_all(int fd, const uint8_t *buf, size_t len)
{
	size_t off = 0;
	while (off < len) {
		ssize_t n = write(fd, buf + off, len - off);
		if (n > 0) {
			off += (size_t)n;
			continue;
		}
		if (n < 0 && errno == EINTR)
			continue;
		return -1;
	}
	return 0;
}

static socklen_t sa_len(const struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET)
		return sizeof(struct sockaddr_in);
	if (sa->sa_family == AF_INET6)
		return sizeof(struct sockaddr_in6);
	return 0;
}

static bool sa_equal(const struct sockaddr *a, const struct sockaddr *b)
{
	if (a->sa_family != b->sa_family)
		return false;
	if (a->sa_family == AF_INET) {
		const struct sockaddr_in *x = (const struct sockaddr_in *)a;
		const struct sockaddr_in *y = (const struct sockaddr_in *)b;
		return x->sin_addr.s_addr == y->sin_addr.s_addr &&
		       x->sin_port == y->sin_port;
	}
	if (a->sa_family == AF_INET6) {
		const struct sockaddr_in6 *x = (const struct sockaddr_in6 *)a;
		const struct sockaddr_in6 *y = (const struct sockaddr_in6 *)b;
		return memcmp(&x->sin6_addr, &y->sin6_addr, 16) == 0 &&
		       x->sin6_port == y->sin6_port;
	}
	return false;
}

/* The relay socket is dual-stack AF_INET6, so every destination handed to
 * sendto must be in AF_INET6 form.  An AF_INET destination becomes
 * ::ffff:a.b.c.d. */
static void to_mapped(const struct sockaddr_storage *in, struct sockaddr_storage *out)
{
	const struct sockaddr_in *in4;
	struct sockaddr_in6 *out6;

	if (in->ss_family == AF_INET6) {
		memcpy(out, in, sizeof(*out));
		return;
	}

	in4 = (const struct sockaddr_in *)in;
	memset(out, 0, sizeof(*out));
	out6 = (struct sockaddr_in6 *)out;
	out6->sin6_family = AF_INET6;
	out6->sin6_port = in4->sin_port;
	out6->sin6_addr.s6_addr[10] = 0xff;
	out6->sin6_addr.s6_addr[11] = 0xff;
	memcpy(&out6->sin6_addr.s6_addr[12], &in4->sin_addr, 4);
}

/* Conversely, a source address read off the dual-stack socket comes back
 * v4-mapped when the peer is really IPv4.  Reporting ::ffff:127.0.0.1 to an
 * application that addressed 127.0.0.1 would break FR-F-02, so it is unmapped
 * before it goes into a reply header. */
static void unmap(struct sockaddr_storage *ss)
{
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)ss;
	struct sockaddr_in tmp;

	if (ss->ss_family != AF_INET6 || !IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr))
		return;

	memset(&tmp, 0, sizeof(tmp));
	tmp.sin_family = AF_INET;
	tmp.sin_port = in6->sin6_port;
	memcpy(&tmp.sin_addr, &in6->sin6_addr.s6_addr[12], 4);
	memset(ss, 0, sizeof(*ss));
	memcpy(ss, &tmp, sizeof(tmp));
}

static const char *sa_str(const struct sockaddr *sa, char *buf, size_t len)
{
	char host[INET6_ADDRSTRLEN];
	if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *in = (const struct sockaddr_in *)sa;
		inet_ntop(AF_INET, &in->sin_addr, host, sizeof(host));
		snprintf(buf, len, "%s:%u", host, ntohs(in->sin_port));
	} else if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)sa;
		inet_ntop(AF_INET6, &in6->sin6_addr, host, sizeof(host));
		snprintf(buf, len, "[%s]:%u", host, ntohs(in6->sin6_port));
	} else {
		snprintf(buf, len, "<af %d>", sa->sa_family);
	}
	return buf;
}

/* Decodes a UDP request header.  Returns bytes consumed, or -1. */
static ssize_t decode_hdr(const uint8_t *buf, size_t len, uint8_t *frag,
                          uint8_t *atyp, struct sockaddr_storage *dst)
{
	if (len < 4 || buf[0] != 0 || buf[1] != 0)
		return -1;
	*frag = buf[2];
	*atyp = buf[3];
	memset(dst, 0, sizeof(*dst));

	if (*atyp == ATYP_IPV4) {
		struct sockaddr_in *in = (struct sockaddr_in *)dst;
		if (len < 10)
			return -1;
		in->sin_family = AF_INET;
		memcpy(&in->sin_addr, buf + 4, 4);
		memcpy(&in->sin_port, buf + 8, 2);
		return 10;
	}
	if (*atyp == ATYP_IPV6) {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)dst;
		if (len < 22)
			return -1;
		in6->sin6_family = AF_INET6;
		memcpy(&in6->sin6_addr, buf + 4, 16);
		memcpy(&in6->sin6_port, buf + 20, 2);

		/* Deliberately STRICT: an IPv4-mapped address inside ATYP 0x04
		 * is rejected rather than quietly forwarded.
		 *
		 * A dual-stack relay socket would convert ::ffff:a.b.c.d back to
		 * IPv4 and deliver it, which is precisely how this fixture used
		 * to hide a real client bug: the shim emitted ATYP 0x04 for a
		 * v4-mapped destination, the fixture forgave it, the hook matrix
		 * stayed green, and a real proxy silently dropped the traffic.
		 * A correct client always sends ATYP 0x01 for these. */
		if (IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr)) {
			logf_("REJECT: ATYP 0x04 carrying an IPv4-mapped address; "
			      "a correct client sends ATYP 0x01 for these");
			return -1;
		}
		return 22;
	}
	if (*atyp == ATYP_DOMAIN) {
		/* Resolved proxy-side, per FR-P-07. */
		size_t dlen;
		char host[256];
		uint16_t port;
		struct addrinfo hints, *res = NULL;
		char portstr[8];

		if (len < 5)
			return -1;
		dlen = buf[4];
		if (dlen == 0 || len < 5 + dlen + 2)
			return -1;
		memcpy(host, buf + 5, dlen);
		host[dlen] = '\0';
		memcpy(&port, buf + 5 + dlen, 2);
		snprintf(portstr, sizeof(portstr), "%u", ntohs(port));

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_DGRAM;
		if (getaddrinfo(host, portstr, &hints, &res) != 0 || res == NULL)
			return -1;
		memcpy(dst, res->ai_addr, res->ai_addrlen);
		freeaddrinfo(res);
		return (ssize_t)(5 + dlen + 2);
	}
	return -1;
}

/* Encodes a reply header naming src.  Returns bytes written. */
static size_t encode_hdr(uint8_t *buf, const struct sockaddr *src, uint8_t frag)
{
	buf[0] = 0;
	buf[1] = 0;
	buf[2] = frag;
	if (src->sa_family == AF_INET) {
		const struct sockaddr_in *in = (const struct sockaddr_in *)src;
		buf[3] = ATYP_IPV4;
		memcpy(buf + 4, &in->sin_addr, 4);
		memcpy(buf + 8, &in->sin_port, 2);
		return 10;
	}
	{
		const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)src;
		buf[3] = ATYP_IPV6;
		memcpy(buf + 4, &in6->sin6_addr, 16);
		memcpy(buf + 20, &in6->sin6_port, 2);
		return 22;
	}
}

struct client {
	int control_fd;
	int family;
};

static void *client_thread(void *arg)
{
	struct client *c = arg;
	int cfd = c->control_fd;
	int family = c->family;
	uint8_t buf[BUF_MAX];
	uint8_t out[BUF_MAX];
	int relay = -1;
	struct sockaddr_storage relay_addr, client_addr;
	socklen_t rlen;
	bool client_locked = false;
	long counter = 0;
	time_t last_activity;
	char abuf[128], bbuf[128];

	free(c);
	memset(&client_addr, 0, sizeof(client_addr));

	/* Method negotiation. */
	if (read_all(cfd, buf, 2) != 0 || buf[0] != SOCKS_VER)
		goto done;
	{
		uint8_t nmethods = buf[1];
		if (nmethods == 0 || read_all(cfd, buf, nmethods) != 0)
			goto done;

		out[0] = SOCKS_VER;
		if (opt.auth_required) {
			/* Offer only 0x02 so the shim's "method I cannot do"
			 * path is exercised (FR-P-09 is deferred in v1). */
			out[1] = METHOD_USERPASS;
			bool client_offers_userpass = false;
			for (uint8_t i = 0; i < nmethods; i++)
				if (buf[i] == METHOD_USERPASS)
					client_offers_userpass = true;
			if (!client_offers_userpass)
				out[1] = METHOD_UNACCEPTABLE;
		} else {
			out[1] = METHOD_UNACCEPTABLE;
			for (uint8_t i = 0; i < nmethods; i++)
				if (buf[i] == METHOD_NONE)
					out[1] = METHOD_NONE;
		}
		if (write_all(cfd, out, 2) != 0 || out[1] == METHOD_UNACCEPTABLE ||
		    out[1] == METHOD_USERPASS)
			goto done;
	}

	/* Request: VER CMD RSV ATYP ADDR PORT */
	if (read_all(cfd, buf, 4) != 0 || buf[0] != SOCKS_VER)
		goto done;
	{
		uint8_t cmd = buf[1], atyp = buf[3];
		size_t rest;

		if (atyp == ATYP_IPV4)
			rest = 6;
		else if (atyp == ATYP_IPV6)
			rest = 18;
		else if (atyp == ATYP_DOMAIN) {
			if (read_all(cfd, buf + 4, 1) != 0)
				goto done;
			rest = (size_t)buf[4] + 2;
		} else
			goto done;
		if (read_all(cfd, buf + 8, rest) != 0)
			goto done;

		if (cmd != CMD_UDP_ASSOCIATE) {
			out[0] = SOCKS_VER;
			out[1] = 0x07; /* command not supported */
			out[2] = 0;
			out[3] = ATYP_IPV4;
			memset(out + 4, 0, 6);
			(void)write_all(cfd, out, 10);
			goto done;
		}
		if (opt.refuse_associate) {
			logf_("refusing UDP ASSOCIATE (fault injection)");
			out[0] = SOCKS_VER;
			out[1] = 0x01; /* general failure */
			out[2] = 0;
			out[3] = ATYP_IPV4;
			memset(out + 4, 0, 6);
			(void)write_all(cfd, out, 10);
			goto done;
		}
	}

	/* Relay socket: one DUAL-STACK AF_INET6 socket bound to the wildcard
	 * address.
	 *
	 * The same socket both receives from the client and sends to arbitrary
	 * destinations, and the client's family need not match the
	 * destination's -- an application on an AF_INET6 socket reaching the
	 * proxy over IPv4 is entirely normal.  A single-family relay socket
	 * cannot serve both, and a loopback-bound one cannot reach an off-host
	 * destination at all.
	 *
	 * What is ADVERTISED is the loopback address in the client's own
	 * family, matching the reference proxy (§0.5).  The "loopback only"
	 * property there is about which clients are accepted, which the peer
	 * lock below enforces. */
	{
		int off = 0;

		relay = socket(AF_INET6, SOCK_DGRAM, 0);
		if (relay < 0)
			goto done;
		if (setsockopt(relay, IPPROTO_IPV6, IPV6_V6ONLY, &off,
		               sizeof(off)) != 0)
			goto done;

		memset(&relay_addr, 0, sizeof(relay_addr));
		{
			struct sockaddr_in6 *a = (struct sockaddr_in6 *)&relay_addr;
			a->sin6_family = AF_INET6;
			a->sin6_addr = in6addr_any;
			a->sin6_port = 0;
			rlen = sizeof(*a);
		}
		if (bind(relay, (struct sockaddr *)&relay_addr, rlen) != 0)
			goto done;
		rlen = sizeof(relay_addr);
		if (getsockname(relay, (struct sockaddr *)&relay_addr, &rlen) != 0)
			goto done;
	}

	/* Advertise loopback + the bound port, in the client's family. */
	{
		uint16_t port = ((struct sockaddr_in6 *)&relay_addr)->sin6_port;

		memset(&relay_addr, 0, sizeof(relay_addr));
		if (family == AF_INET) {
			struct sockaddr_in *a = (struct sockaddr_in *)&relay_addr;
			a->sin_family = AF_INET;
			a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			a->sin_port = port;
		} else {
			struct sockaddr_in6 *a = (struct sockaddr_in6 *)&relay_addr;
			a->sin6_family = AF_INET6;
			a->sin6_addr = in6addr_loopback;
			a->sin6_port = port;
		}
	}

	/* Reply with BND.ADDR / BND.PORT. */
	{
		size_t n = encode_hdr(out + 1, (struct sockaddr *)&relay_addr, 0);
		out[0] = SOCKS_VER;
		out[1] = 0x00; /* succeeded */
		out[2] = 0;
		/* encode_hdr wrote RSV+FRAG+ATYP+...; the reply wants
		 * VER+REP+RSV+ATYP+..., so shift the ATYP tail into place. */
		memmove(out + 3, out + 4, n - 3);
		if (write_all(cfd, out, 3 + (n - 3)) != 0)
			goto done;
		logf_("association up, relay %s",
		      sa_str((struct sockaddr *)&relay_addr, abuf, sizeof(abuf)));
	}

	last_activity = time(NULL);

	for (;;) {
		struct pollfd pfd[2];
		int timeout = opt.expire_after > 0 ? 250 : 1000;
		int r;

		pfd[0].fd = cfd;
		pfd[0].events = POLLIN;
		pfd[0].revents = 0;
		pfd[1].fd = relay;
		pfd[1].events = POLLIN;
		pfd[1].revents = 0;

		r = poll(pfd, 2, timeout);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		/* Association lifetime is tied to the control connection. */
		if (pfd[0].revents & (POLLIN | POLLERR | POLLHUP | POLLNVAL)) {
			ssize_t n = read(cfd, buf, sizeof(buf));
			if (n <= 0) {
				logf_("control connection closed, tearing down");
				break;
			}
		}

		if (opt.expire_after > 0 &&
		    time(NULL) - last_activity >= opt.expire_after) {
			logf_("association idle for %ds, expiring (fault injection)",
			      opt.expire_after);
			break;
		}

		if (!(pfd[1].revents & POLLIN))
			continue;

		{
			struct sockaddr_storage from;
			socklen_t flen = sizeof(from);
			ssize_t n = recvfrom(relay, buf, sizeof(buf), 0,
			                     (struct sockaddr *)&from, &flen);
			if (n < 0)
				continue;

			last_activity = time(NULL);
			counter++;

			if (opt.drop_nth > 0 && (counter % opt.drop_nth) == 0) {
				logf_("dropping datagram %ld (fault injection)",
				      counter);
				continue;
			}
			if (opt.delay_ms > 0) {
				struct timespec ts = {
					opt.delay_ms / 1000,
					(long)(opt.delay_ms % 1000) * 1000000L
				};
				nanosleep(&ts, NULL);
			}

			if (!client_locked) {
				/* Peer lock: the association pins to the first
				 * sender, like the reference proxy (§0.5). */
				memcpy(&client_addr, &from, sizeof(from));
				client_locked = true;
				logf_("peer locked to %s",
				      sa_str((struct sockaddr *)&client_addr, abuf,
				             sizeof(abuf)));
			}

			if (sa_equal((struct sockaddr *)&from,
			             (struct sockaddr *)&client_addr) ||
			    !opt.peer_lock) {
				/* Client -> destination. */
				uint8_t frag, atyp;
				struct sockaddr_storage dst;
				ssize_t hlen = decode_hdr(buf, (size_t)n, &frag,
				                          &atyp, &dst);
				if (hlen < 0) {
					logf_("malformed request header, dropping");
					continue;
				}
				if (frag != 0) {
					logf_("FRAG=%u, dropping (never fragments)",
					      frag);
					continue;
				}
				if (opt.reject_atyp >= 0 &&
				    atyp == (uint8_t)opt.reject_atyp) {
					logf_("rejecting ATYP 0x%02x (fault injection)",
					      atyp);
					continue;
				}
				if ((size_t)(n - hlen) > opt.max_dgram) {
					logf_("payload %zd > max %zu, dropping",
					      n - hlen, opt.max_dgram);
					continue;
				}
				logf_("-> %s, %zd bytes",
				      sa_str((struct sockaddr *)&dst, abuf,
				             sizeof(abuf)),
				      n - hlen);
				{
					struct sockaddr_storage md;
					to_mapped(&dst, &md);
					if (sendto(relay, buf + hlen,
					           (size_t)(n - hlen), 0,
					           (struct sockaddr *)&md,
					           sa_len((struct sockaddr *)&md)) < 0)
						logf_("forward failed: %s",
						      strerror(errno));
				}
			} else {
				/* Destination -> client.  The source is unmapped
				 * first so an application that addressed an
				 * IPv4 peer is told about an IPv4 peer. */
				struct sockaddr_storage src = from;
				size_t hlen;

				if ((size_t)n > opt.max_dgram) {
					logf_("reply %zd > max %zu, dropping", n,
					      opt.max_dgram);
					continue;
				}

				unmap(&src);
				hlen = encode_hdr(out, (struct sockaddr *)&src,
				                  opt.frag_inject ? 1 : 0);
				memcpy(out + hlen, buf, (size_t)n);
				logf_("<- %s, %zd bytes%s",
				      sa_str((struct sockaddr *)&src, bbuf,
				             sizeof(bbuf)),
				      n, opt.frag_inject ? " (FRAG injected)" : "");
				(void)sendto(relay, out, hlen + (size_t)n, 0,
				             (struct sockaddr *)&client_addr,
				             sa_len((struct sockaddr *)&client_addr));
			}
		}
	}

done:
	if (relay >= 0)
		close(relay);
	close(cfd);
	return NULL;
}

int main(int argc, char **argv)
{
	int listen_fd;
	struct sockaddr_in6 addr;
	socklen_t alen;
	int one = 1, zero = 0;

	for (int i = 1; i < argc; i++) {
		const char *a = argv[i];
		if (strcmp(a, "--port") == 0 && i + 1 < argc)
			opt.port = atoi(argv[++i]);
		else if (strcmp(a, "--refuse-associate") == 0)
			opt.refuse_associate = true;
		else if (strcmp(a, "--auth-required") == 0)
			opt.auth_required = true;
		else if (strcmp(a, "--expire-after") == 0 && i + 1 < argc)
			opt.expire_after = atoi(argv[++i]);
		else if (strcmp(a, "--drop-nth") == 0 && i + 1 < argc)
			opt.drop_nth = atoi(argv[++i]);
		else if (strcmp(a, "--delay-ms") == 0 && i + 1 < argc)
			opt.delay_ms = atoi(argv[++i]);
		else if (strcmp(a, "--max-dgram") == 0 && i + 1 < argc)
			opt.max_dgram = (size_t)atol(argv[++i]);
		else if (strcmp(a, "--frag-inject") == 0)
			opt.frag_inject = true;
		else if (strcmp(a, "--no-peer-lock") == 0)
			opt.peer_lock = false;
		else if (strcmp(a, "--reject-atyp") == 0 && i + 1 < argc)
			opt.reject_atyp = atoi(argv[++i]);
		else if (strcmp(a, "--quiet") == 0)
			opt.quiet = true;
		else {
			fprintf(stderr, "socks5d: unknown option %s\n", a);
			return 1;
		}
	}

	signal(SIGPIPE, SIG_IGN);

	/* A dual-stack listener, so one fixture serves both IPv4 and IPv6
	 * tests. */
	listen_fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (listen_fd < 0) {
		perror("socket");
		return 1;
	}
	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));

	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_addr = in6addr_any;
	addr.sin6_port = htons((uint16_t)opt.port);

	if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		perror("bind");
		return 1;
	}
	if (listen(listen_fd, 16) != 0) {
		perror("listen");
		return 1;
	}

	alen = sizeof(addr);
	if (getsockname(listen_fd, (struct sockaddr *)&addr, &alen) != 0) {
		perror("getsockname");
		return 1;
	}
	printf("PORT %u\n", ntohs(addr.sin6_port));
	fflush(stdout);

	for (;;) {
		struct sockaddr_storage peer;
		socklen_t plen = sizeof(peer);
		int cfd = accept(listen_fd, (struct sockaddr *)&peer, &plen);
		pthread_t tid;
		struct client *c;

		if (cfd < 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		c = malloc(sizeof(*c));
		if (c == NULL) {
			close(cfd);
			continue;
		}
		c->control_fd = cfd;
		/* A v4-mapped peer means the client is really IPv4, so the
		 * relay should be too. */
		c->family = AF_INET6;
		if (peer.ss_family == AF_INET6) {
			const struct sockaddr_in6 *p6 =
				(const struct sockaddr_in6 *)&peer;
			if (IN6_IS_ADDR_V4MAPPED(&p6->sin6_addr))
				c->family = AF_INET;
		} else {
			c->family = AF_INET;
		}

		if (pthread_create(&tid, NULL, client_thread, c) != 0) {
			close(cfd);
			free(c);
			continue;
		}
		pthread_detach(tid);
	}

	close(listen_fd);
	return 0;
}

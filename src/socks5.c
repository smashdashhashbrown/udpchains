#include "socks5.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>

#include "addr.h"
#include "log.h"

/* SOCKS5 constants, RFC 1928. */
#define SOCKS_VER 0x05
#define METHOD_NONE 0x00
#define METHOD_USERPASS 0x02
#define METHOD_UNACCEPTABLE 0xff
#define CMD_CONNECT 0x01
#define CMD_UDP_ASSOCIATE 0x03
/* RFC 1929's sub-negotiation carries its OWN version byte, 0x01, not SOCKS5's
 * 0x05.  Confusing the two is the classic implementation bug here. */
#define UDPC_AUTH_VER 0x01
#define REP_SUCCEEDED 0x00

/* --- header codec ---------------------------------------------------------- */

/* Writes an ATYP + address + port triple at buf, returning its length.
 *
 * An IPv4-MAPPED IPv6 address (::ffff:a.b.c.d) is emitted as ATYP 0x01 with the
 * four embedded bytes, NOT as ATYP 0x04 with all sixteen.
 *
 * This matters more than it looks.  An application that opens an AF_INET6
 * dual-stack socket and connects to an IPv4 destination -- which is what
 * getaddrinfo-based clients, nc, and most modern runtimes do by default on a
 * dual-stack host -- ends up with ::ffff:a.b.c.d as its destination.  Putting
 * that in an ATYP 0x04 field asks the proxy to reach an IPv6 address that does
 * not exist; a proxy that takes it literally silently fails to deliver, with
 * the association looking perfectly healthy from both ends.
 *
 * Note that the in-repo fixture happily tolerates the wrong form -- it decodes
 * the mapped address and sends it from a dual-stack socket, where the kernel
 * converts it back to IPv4 -- so the hook matrix cannot catch this.  It is
 * exactly the class of defect D-06 warns about when it says a green fixture run
 * is not evidence of interop. */
static ssize_t encode_addr(uint8_t *buf, size_t buflen, const struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *in = (const struct sockaddr_in *)sa;

		if (buflen < 1 + 4 + 2) {
			errno = ENOBUFS;
			return -1;
		}
		buf[0] = UDPC_ATYP_IPV4;
		memcpy(buf + 1, &in->sin_addr, 4);
		memcpy(buf + 5, &in->sin_port, 2);
		return 1 + 4 + 2;
	}

	if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)sa;

		if (IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr)) {
			if (buflen < 1 + 4 + 2) {
				errno = ENOBUFS;
				return -1;
			}
			buf[0] = UDPC_ATYP_IPV4;
			memcpy(buf + 1, &in6->sin6_addr.s6_addr[12], 4);
			memcpy(buf + 5, &in6->sin6_port, 2);
			return 1 + 4 + 2;
		}

		if (buflen < 1 + 16 + 2) {
			errno = ENOBUFS;
			return -1;
		}
		buf[0] = UDPC_ATYP_IPV6;
		memcpy(buf + 1, &in6->sin6_addr, 16);
		memcpy(buf + 17, &in6->sin6_port, 2);
		return 1 + 16 + 2;
	}

	errno = EAFNOSUPPORT;
	return -1;
}

ssize_t udpc_socks_encode(uint8_t *buf, size_t buflen, const struct sockaddr *dst)
{
	ssize_t n;

	if (dst == NULL) {
		errno = EDESTADDRREQ;
		return -1;
	}
	if (buflen < 3) {
		errno = ENOBUFS;
		return -1;
	}

	buf[0] = 0;
	buf[1] = 0; /* RSV */
	buf[2] = 0; /* FRAG: always 0 (FR-P-04) */

	n = encode_addr(buf + 3, buflen - 3, dst);
	if (n < 0)
		return -1;

	return n + 3;
}

ssize_t udpc_socks_encode_domain(uint8_t *buf, size_t buflen, const char *host,
                                 uint16_t port)
{
	size_t hlen;
	uint16_t nport;

	if (host == NULL) {
		errno = EDESTADDRREQ;
		return -1;
	}
	hlen = strlen(host);
	if (hlen == 0 || hlen > 255) {
		errno = EINVAL;
		return -1;
	}
	if (buflen < 4 + 1 + hlen + 2) {
		errno = ENOBUFS;
		return -1;
	}

	buf[0] = 0;
	buf[1] = 0;
	buf[2] = 0; /* FRAG */
	buf[3] = UDPC_ATYP_DOMAIN;
	buf[4] = (uint8_t)hlen;
	memcpy(buf + 5, host, hlen);
	nport = htons(port);
	memcpy(buf + 5 + hlen, &nport, 2);

	return (ssize_t)(7 + hlen);
}


/* RFC 1929 username/password sub-negotiation request:
 *
 *   +----+------+----------+------+----------+
 *   |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
 *   +----+------+----------+------+----------+
 *   | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
 *
 * VER here is 0x01 -- the sub-negotiation's own version, NOT the SOCKS5 0x05.
 * Getting that wrong is the classic RFC 1929 bug: the proxy reads 0x05 as an
 * unknown auth version and closes, which looks like a network fault rather than
 * a protocol error.
 *
 * An empty username is refused.  RFC 1929 gives ULEN a range of 1 to 255, and a
 * zero-length name would be encoded as a well-formed message that no proxy can
 * match against an account -- failing later, and less clearly.
 */
ssize_t udpc_socks_encode_userpass(uint8_t *buf, size_t buflen, const char *user,
                                   const char *pass)
{
	size_t ulen, plen;

	if (buf == NULL || user == NULL) {
		errno = EINVAL;
		return -1;
	}
	pass = (pass != NULL) ? pass : "";

	ulen = strlen(user);
	plen = strlen(pass);

	if (ulen == 0) {
		errno = EINVAL;
		return -1;
	}
	if (ulen > 255 || plen > 255) {
		errno = EINVAL;
		return -1;
	}
	if (buflen < 3 + ulen + plen) {
		errno = ENOBUFS;
		return -1;
	}

	buf[0] = UDPC_AUTH_VER;
	buf[1] = (uint8_t)ulen;
	memcpy(buf + 2, user, ulen);
	buf[2 + ulen] = (uint8_t)plen;
	memcpy(buf + 3 + ulen, pass, plen);

	return (ssize_t)(3 + ulen + plen);
}

ssize_t udpc_socks_decode(const uint8_t *buf, size_t len,
                          struct udpc_socks_hdr *out)
{
	size_t need;

	memset(out, 0, sizeof(*out));

	/* Shortest legal header is 10 bytes; anything less cannot declare an
	 * ATYP and a port. */
	if (buf == NULL || len < 4) {
		errno = EPROTO;
		return -1;
	}
	/* RSV must be zero.  Being strict here costs nothing and catches a
	 * misaligned read early. */
	if (buf[0] != 0 || buf[1] != 0) {
		errno = EPROTO;
		return -1;
	}

	out->frag = buf[2];
	out->atyp = buf[3];

	switch (out->atyp) {
	case UDPC_ATYP_IPV4: {
		struct sockaddr_in *in = (struct sockaddr_in *)&out->addr;
		need = 10;
		if (len < need) {
			errno = EPROTO;
			return -1;
		}
		in->sin_family = AF_INET;
		memcpy(&in->sin_addr, buf + 4, 4);
		memcpy(&in->sin_port, buf + 8, 2);
		out->port = ntohs(in->sin_port);
		out->addr_valid = true;
		return (ssize_t)need;
	}
	case UDPC_ATYP_IPV6: {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&out->addr;
		need = 22;
		if (len < need) {
			errno = EPROTO;
			return -1;
		}
		in6->sin6_family = AF_INET6;
		memcpy(&in6->sin6_addr, buf + 4, 16);
		memcpy(&in6->sin6_port, buf + 20, 2);
		out->port = ntohs(in6->sin6_port);
		out->addr_valid = true;
		return (ssize_t)need;
	}
	case UDPC_ATYP_DOMAIN: {
		size_t dlen;
		uint16_t nport;

		if (len < 5) {
			errno = EPROTO;
			return -1;
		}
		dlen = buf[4];
		if (dlen == 0) {
			errno = EPROTO;
			return -1;
		}
		need = 5 + dlen + 2;
		if (len < need) {
			errno = EPROTO;
			return -1;
		}
		memcpy(out->domain, buf + 5, dlen);
		out->domain[dlen] = '\0';
		memcpy(&nport, buf + 5 + dlen, 2);
		out->port = ntohs(nport);
		/* A domain in a reply cannot be turned into a sockaddr without
		 * resolving it, which would both leak a lookup and lie about
		 * the source.  The receive path substitutes the socket's known
		 * peer instead (DESIGN.md 5.2). */
		out->addr_valid = false;
		return (ssize_t)need;
	}
	default:
		errno = EPROTO;
		return -1;
	}
}

/* --- control connection ---------------------------------------------------- */

/* These use libc directly rather than the resolved real symbols.  The control
 * connection is TCP, so the interception predicate (DESIGN.md 2.2) declines it
 * anyway -- the hooks see a descriptor with no table entry and pass it through.
 * Keeping this file free of real.h also keeps it unit-testable outside a
 * preload context. */

static int deadline_poll(int fd, short events, int timeout_ms)
{
	struct pollfd pfd;
	int r;

	pfd.fd = fd;
	pfd.events = events;
	pfd.revents = 0;

	do {
		r = poll(&pfd, 1, timeout_ms);
	} while (r < 0 && errno == EINTR);

	if (r == 0) {
		errno = ETIMEDOUT;
		return -1;
	}
	if (r < 0)
		return -1;
	if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
		errno = ECONNRESET;
		return -1;
	}
	return 0;
}

static int write_all(int fd, const uint8_t *buf, size_t len, int timeout_ms)
{
	size_t off = 0;

	while (off < len) {
		ssize_t n = write(fd, buf + off, len - off);
		if (n > 0) {
			off += (size_t)n;
			continue;
		}
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			if (deadline_poll(fd, POLLOUT, timeout_ms) != 0)
				return -1;
			continue;
		}
		if (n < 0 && errno == EINTR)
			continue;
		if (n == 0)
			errno = ECONNRESET;
		return -1;
	}
	return 0;
}

static int read_all(int fd, uint8_t *buf, size_t len, int timeout_ms)
{
	size_t off = 0;

	while (off < len) {
		ssize_t n = read(fd, buf + off, len - off);
		if (n > 0) {
			off += (size_t)n;
			continue;
		}
		if (n == 0) {
			/* The proxy closed mid-handshake. */
			errno = ECONNRESET;
			return -1;
		}
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			if (deadline_poll(fd, POLLIN, timeout_ms) != 0)
				return -1;
			continue;
		}
		if (errno == EINTR)
			continue;
		return -1;
	}
	return 0;
}

static int connect_with_timeout(int fd, const struct sockaddr *sa, socklen_t len,
                                int timeout_ms)
{
	int err = 0, polled;
	socklen_t elen = sizeof(err);

	if (connect(fd, sa, len) == 0)
		return 0;
	if (errno != EINPROGRESS)
		return -1;

	/* A refused or unreachable connect shows up as POLLERR/POLLHUP, which
	 * deadline_poll reports as ECONNRESET.  SO_ERROR holds the real reason,
	 * and the caller is owed it (DESIGN.md 6.4): ECONNREFUSED for a proxy
	 * that is not listening, not a reset that never happened. */
	polled = deadline_poll(fd, POLLOUT, timeout_ms);
	if (polled != 0 && errno != ECONNRESET)
		return -1;

	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) != 0)
		return -1;
	if (err != 0) {
		errno = err;
		return -1;
	}
	if (polled != 0) {
		errno = ECONNRESET;
		return -1;
	}
	return 0;
}

/* BND.ADDR is the address the client must send datagrams to, but two common
 * forms cannot be taken literally.
 *
 * A wildcard (0.0.0.0 or ::) means "the address you already reached me on".
 * Sent to literally, it would mean sending to the wildcard address.
 *
 * A loopback address means the same thing whenever the proxy is NOT on this
 * host: the proxy is describing its own local view of the socket it bound,
 * which is the only view it has.  Taken literally it points the application's
 * socket at *this* host's loopback, where nothing is listening -- so every
 * datagram is discarded, the resulting ICMP port unreachable surfaces as
 * ECONNREFUSED on the next receive, and the association machinery reads that as
 * expiry and re-associates indefinitely.
 *
 * When the proxy IS on this host, a loopback relay is correct and must be left
 * alone.  That is why proxy_is_local gates the loopback case and the wildcard
 * case is unconditional.
 *
 * Found against a real proxy on 2026-08-19: the fixture had always advertised a
 * reachable relay, so no fixture run could reach this.
 */
void udpc_socks_fixup_relay(struct sockaddr_storage *relay,
                            const struct udpc_config *cfg)
{
	bool wildcard = false, unusable_loopback = false;
	char rbuf[UDPC_ADDRSTRLEN];
	uint16_t port;

	if (relay->ss_family == AF_INET) {
		const struct sockaddr_in *r = (const struct sockaddr_in *)relay;
		wildcard = (r->sin_addr.s_addr == INADDR_ANY);
	} else if (relay->ss_family == AF_INET6) {
		const struct sockaddr_in6 *r = (const struct sockaddr_in6 *)relay;
		wildcard = IN6_IS_ADDR_UNSPECIFIED(&r->sin6_addr);
	} else {
		return;
	}

	if (!wildcard && !cfg->proxy_is_local)
		unusable_loopback =
			udpc_addr_is_loopback((const struct sockaddr *)relay);

	if (!wildcard && !unusable_loopback)
		return;

	if (unusable_loopback)
		udpc_debug("proxy returned loopback relay %s but is not on this "
		           "host; using the proxy address instead",
		           udpc_addr_str((const struct sockaddr *)relay, rbuf,
		                         sizeof(rbuf)));
	else
		udpc_debug("proxy returned a wildcard relay address; using the "
		           "proxy address instead");

	port = udpc_sa_port((const struct sockaddr *)relay);
	*relay = cfg->proxy;
	udpc_sa_set_port((struct sockaddr *)relay, port);
}

/* Opens the TCP connection to the proxy and completes method negotiation,
 * including RFC 1929 authentication when the proxy selects it.  Shared by UDP
 * ASSOCIATE and CONNECT, so both authenticate identically.  Returns the
 * connected descriptor, or -1 with errno set and nothing left open. */
static int open_negotiated(const struct udpc_config *cfg)
{
	uint8_t buf[2 + 2];
	socklen_t plen;
	int fd, saved;

	plen = udpc_sa_len((const struct sockaddr *)&cfg->proxy);
	if (plen == 0) {
		errno = EAFNOSUPPORT;
		return -1;
	}

	/* SOCK_CLOEXEC at creation, not fcntl afterwards: there is no window in
	 * which a concurrent exec could inherit this descriptor (FR-L-05). */
	fd = socket(cfg->proxy.ss_family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	            IPPROTO_TCP);
	if (fd < 0)
		return -1;

	if (connect_with_timeout(fd, (const struct sockaddr *)&cfg->proxy, plen,
	                         cfg->connect_timeout_ms) != 0)
		goto fail;

	{
		/* Nagle would delay the request behind the greeting. */
		int one = 1;
		(void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	}

	/* Method negotiation: VER, NMETHODS, METHODS.
	 *
	 * "No authentication" is always offered.  Username/password (0x02) is
	 * offered only when credentials are configured, so a proxy that accepts
	 * either does not get pushed into an authenticated exchange the user did
	 * not ask for -- and so the "method I cannot do" diagnostic stays
	 * accurate when no credentials exist. */
	{
		uint8_t nmethods = 0;

		buf[0] = SOCKS_VER;
		buf[2 + nmethods++] = METHOD_NONE;
		if (cfg->have_credentials)
			buf[2 + nmethods++] = METHOD_USERPASS;
		buf[1] = nmethods;

		if (write_all(fd, buf, 2 + (size_t)nmethods,
		              cfg->connect_timeout_ms) != 0)
			goto fail;
	}

	if (read_all(fd, buf, 2, cfg->connect_timeout_ms) != 0)
		goto fail;
	if (buf[0] != SOCKS_VER) {
		udpc_debug("proxy replied with version 0x%02x, expected 0x05", buf[0]);
		errno = EPROTO;
		goto fail;
	}
	if (buf[1] == METHOD_UNACCEPTABLE) {
		udpc_err("proxy rejected all offered authentication methods");
		if (!cfg->have_credentials)
			udpc_err("no credentials are configured; set "
			         "UDPCHAINS_USERNAME and UDPCHAINS_PASSWORD_FILE "
			         "if the proxy requires authentication");
		errno = EACCES;
		goto fail;
	}
	if (buf[1] == METHOD_USERPASS) {
		/* FR-P-09 / RFC 1929.  A separate buffer: the request can reach
		 * 513 bytes. */
		uint8_t authbuf[3 + 255 + 255];
		ssize_t alen;

		if (!cfg->have_credentials) {
			/* Unreachable unless the proxy selected a method we did
			 * not offer, which is a protocol violation worth naming
			 * rather than treating as an auth failure. */
			udpc_err("proxy selected username/password authentication, "
			         "which was not offered -- no credentials are "
			         "configured");
			errno = EPROTO;
			goto fail;
		}

		alen = udpc_socks_encode_userpass(authbuf, sizeof(authbuf),
		                                  cfg->username, cfg->password);
		if (alen < 0) {
			udpc_err("cannot encode credentials: username must be 1 "
			         "to 255 bytes and the password at most 255");
			errno = EINVAL;
			goto fail;
		}

		/* NFR-05: the length is logged, never the bytes. */
		udpc_debug("proxy selected username/password auth; sending "
		           "credentials for user of %zu bytes",
		           strlen(cfg->username));

		if (write_all(fd, authbuf, (size_t)alen,
		              cfg->connect_timeout_ms) != 0) {
			explicit_bzero(authbuf, sizeof(authbuf));
			goto fail;
		}
		explicit_bzero(authbuf, sizeof(authbuf));

		if (read_all(fd, buf, 2, cfg->connect_timeout_ms) != 0)
			goto fail;
		if (buf[0] != UDPC_AUTH_VER) {
			udpc_err("proxy replied to authentication with version "
			         "0x%02x, expected 0x01 (RFC 1929)",
			         buf[0]);
			errno = EPROTO;
			goto fail;
		}
		if (buf[1] != 0x00) {
			udpc_err("proxy rejected the supplied credentials "
			         "(status 0x%02x)",
			         buf[1]);
			errno = EACCES;
			goto fail;
		}
		udpc_debug("authenticated");
	} else if (buf[1] != METHOD_NONE) {
		udpc_err("proxy selected authentication method 0x%02x, which is "
		         "not implemented (only 0x00 and 0x02 are supported)",
		         buf[1]);
		errno = EACCES;
		goto fail;
	}
	return fd;

fail:
	saved = errno;
	close(fd);
	errno = saved ? saved : ECONNREFUSED;
	return -1;
}

/* Sends a request -- VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT -- and reads the
 * reply, decoding BND.ADDR/BND.PORT into *bnd.  A NULL addr is sent as the
 * unspecified address with port 0, in the family of the control connection.
 * Returns 0, or -1 with errno set from the reply code (FR-F-07). */
static int request(int fd, const struct udpc_config *cfg, uint8_t cmd,
                   const struct sockaddr *addr, struct udpc_socks_hdr *bnd)
{
	uint8_t buf[UDPC_SOCKS_HDR_MAX];
	ssize_t hlen;
	size_t replylen;

	buf[0] = SOCKS_VER;
	buf[1] = cmd;
	buf[2] = 0;

	if (addr != NULL && udpc_sa_len(addr) != 0) {
		/* Same ATYP+addr+port encoding as a datagram header, including
		 * the v4-mapped normalisation (D-14). */
		hlen = encode_addr(buf + 3, sizeof(buf) - 3, addr);
		if (hlen < 0)
			return -1;
	} else if (cfg->proxy.ss_family == AF_INET6) {
		buf[3] = UDPC_ATYP_IPV6;
		memset(buf + 4, 0, 16 + 2); /* :: port 0 */
		hlen = 1 + 16 + 2;
	} else {
		buf[3] = UDPC_ATYP_IPV4;
		memset(buf + 4, 0, 4 + 2); /* 0.0.0.0 port 0 */
		hlen = 1 + 4 + 2;
	}

	if (write_all(fd, buf, 3 + (size_t)hlen, cfg->connect_timeout_ms) != 0)
		return -1;

	/* Reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT.  Read the fixed part,
	 * then exactly as much as the declared ATYP requires -- never a fixed
	 * slurp, which would either block waiting for bytes the proxy will not
	 * send or steal bytes that are not ours.  After a CONNECT the bytes
	 * that follow are the tunnelled stream. */
	if (read_all(fd, buf, 4, cfg->connect_timeout_ms) != 0)
		return -1;
	if (buf[0] != SOCKS_VER) {
		errno = EPROTO;
		return -1;
	}
	if (buf[1] != REP_SUCCEEDED) {
		udpc_debug("proxy refused %s with reply code 0x%02x",
		           cmd == CMD_CONNECT ? "CONNECT" : "UDP ASSOCIATE", buf[1]);
		/* RFC 1928 §6 reply codes, mapped to the closest errno so the
		 * application sees something it can act on (FR-F-07). */
		switch (buf[1]) {
		case 0x02: errno = EACCES; break;       /* not allowed by ruleset */
		case 0x03: errno = ENETUNREACH; break;  /* network unreachable */
		case 0x04: errno = EHOSTUNREACH; break; /* host unreachable */
		case 0x05: errno = ECONNREFUSED; break; /* connection refused */
		case 0x06: errno = ETIMEDOUT; break;    /* TTL expired */
		case 0x07: errno = EOPNOTSUPP; break;   /* command not supported */
		case 0x08: errno = EAFNOSUPPORT; break; /* address type */
		default: errno = ECONNREFUSED; break;   /* general failure */
		}
		return -1;
	}

	switch (buf[3]) {
	case UDPC_ATYP_IPV4:
		if (read_all(fd, buf + 4, 4 + 2, cfg->connect_timeout_ms) != 0)
			return -1;
		replylen = 4 + 4 + 2;
		break;
	case UDPC_ATYP_IPV6:
		if (read_all(fd, buf + 4, 16 + 2, cfg->connect_timeout_ms) != 0)
			return -1;
		replylen = 4 + 16 + 2;
		break;
	case UDPC_ATYP_DOMAIN: {
		size_t dlen;
		if (read_all(fd, buf + 4, 1, cfg->connect_timeout_ms) != 0)
			return -1;
		dlen = buf[4];
		if (read_all(fd, buf + 5, dlen + 2, cfg->connect_timeout_ms) != 0)
			return -1;
		replylen = 5 + dlen + 2;
		break;
	}
	default:
		errno = EPROTO;
		return -1;
	}

	/* The reply's ATYP..PORT tail has the same shape as a UDP header's,
	 * minus the RSV+FRAG prefix.  Rebuild that prefix so the one decoder
	 * covers both, rather than duplicating the address parsing. */
	{
		uint8_t tmp[UDPC_SOCKS_HDR_MAX];
		size_t taillen = replylen - 3; /* ATYP..PORT, plus a byte */

		memset(tmp, 0, 3);
		memcpy(tmp + 3, buf + 3, taillen);
		if (udpc_socks_decode(tmp, 3 + taillen, bnd) < 0)
			return -1;
	}
	return 0;
}

int udpc_socks_associate(const struct udpc_config *cfg,
                         const struct sockaddr *bind_addr,
                         struct udpc_socks_conn *conn, int *out_errno)
{
	struct udpc_socks_hdr hdr;
	int fd, saved;

	memset(conn, 0, sizeof(*conn));
	conn->control_fd = -1;

	fd = open_negotiated(cfg);
	if (fd < 0) {
		*out_errno = errno;
		return -1;
	}

	/* FR-P-05: declare 0.0.0.0:0 unless the application bound a concrete
	 * address.  Proxies pin the association to a declared address, so
	 * declaring one we will not send from breaks the association. */
	if (request(fd, cfg, CMD_UDP_ASSOCIATE, bind_addr, &hdr) != 0)
		goto fail;

	if (!hdr.addr_valid) {
		/* A named relay would need a lookup we cannot do honestly here. */
		udpc_err("proxy returned a domain-name relay address, which is "
		         "not usable for a UDP association");
		errno = EPROTO;
		goto fail;
	}

	conn->relay = hdr.addr;
	udpc_socks_fixup_relay(&conn->relay, cfg);
	conn->control_fd = fd;
	return 0;

fail:
	saved = errno;
	close(fd);
	*out_errno = saved ? saved : ECONNREFUSED;
	return -1;
}

int udpc_socks_connect(const struct udpc_config *cfg, const struct sockaddr *dst,
                       int *out_errno)
{
	struct udpc_socks_hdr hdr;
	int fd, saved;

	if (dst == NULL || udpc_sa_len(dst) == 0) {
		*out_errno = EAFNOSUPPORT;
		return -1;
	}

	fd = open_negotiated(cfg);
	if (fd < 0) {
		*out_errno = errno;
		return -1;
	}

	/* BND.ADDR is the proxy's outbound address for the tunnel.  The
	 * caller has no use for it, and a domain-form one is legal here. */
	if (request(fd, cfg, CMD_CONNECT, dst, &hdr) != 0) {
		saved = errno;
		close(fd);
		*out_errno = saved ? saved : ECONNREFUSED;
		return -1;
	}
	return fd;
}

void udpc_socks_disconnect(struct udpc_socks_conn *conn)
{
	if (conn == NULL || conn->control_fd < 0)
		return;
	/* Closing the control connection is what tells the proxy to release the
	 * association (baseline §0.5, FR-P-02). */
	close(conn->control_fd);
	conn->control_fd = -1;
}

bool udpc_socks_control_alive(const struct udpc_socks_conn *conn)
{
	struct pollfd pfd;
	int r;

	if (conn == NULL || conn->control_fd < 0)
		return false;

	/* POLLRDHUP is the signal that matters, not POLLHUP and not POLLIN.
	 *
	 * A proxy that releases an association closes its end, sending a FIN.
	 * That raises POLLRDHUP.  POLLHUP alone is only raised once BOTH
	 * directions are shut down, so polling for it by itself would miss an
	 * association the proxy has just dropped.
	 *
	 * Readable data (POLLIN without POLLRDHUP) is deliberately NOT treated
	 * as death.  A conforming SOCKS5 proxy sends nothing on the control
	 * connection after the UDP ASSOCIATE reply, but "sends nothing" is a
	 * property of the proxy rather than of the protocol, and a proxy that
	 * does send something -- a keepalive, tunnel framing, a trailing byte --
	 * would otherwise have every one of its associations torn down and
	 * rebuilt on the next send.  Being wrong in that direction is expensive
	 * and hard to diagnose; being wrong the other way merely delays noticing
	 * a dead association until the send fails, which is already handled. */
	pfd.fd = conn->control_fd;
	pfd.events = POLLRDHUP;
	pfd.revents = 0;

	do {
		r = poll(&pfd, 1, 0);
	} while (r < 0 && errno == EINTR);

	if (r < 0)
		return false;
	if (pfd.revents & (POLLRDHUP | POLLERR | POLLHUP | POLLNVAL))
		return false;
	return true;
}

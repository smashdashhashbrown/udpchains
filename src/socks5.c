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
#define CMD_UDP_ASSOCIATE 0x03
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
	int err = 0;
	socklen_t elen = sizeof(err);

	if (connect(fd, sa, len) == 0)
		return 0;
	if (errno != EINPROGRESS)
		return -1;

	if (deadline_poll(fd, POLLOUT, timeout_ms) != 0)
		return -1;

	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) != 0)
		return -1;
	if (err != 0) {
		errno = err;
		return -1;
	}
	return 0;
}

int udpc_socks_associate(const struct udpc_config *cfg,
                         const struct sockaddr *bind_addr,
                         struct udpc_socks_conn *conn, int *out_errno)
{
	uint8_t buf[UDPC_SOCKS_HDR_MAX];
	struct udpc_socks_hdr hdr;
	socklen_t plen;
	ssize_t hlen;
	int fd = -1;
	int saved;

	memset(conn, 0, sizeof(*conn));
	conn->control_fd = -1;

	plen = udpc_sa_len((const struct sockaddr *)&cfg->proxy);
	if (plen == 0) {
		*out_errno = EAFNOSUPPORT;
		return -1;
	}

	/* SOCK_CLOEXEC at creation, not fcntl afterwards: there is no window in
	 * which a concurrent exec could inherit this descriptor (FR-L-05). */
	fd = socket(cfg->proxy.ss_family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	            IPPROTO_TCP);
	if (fd < 0) {
		*out_errno = errno;
		return -1;
	}

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
	 * v1 offers only "no authentication" (0x00).  FR-P-09 (RFC 1929
	 * username/password) is deferred per D-08; when it lands, this is where
	 * 0x02 joins the list and a sub-negotiation follows the reply. */
	buf[0] = SOCKS_VER;
	buf[1] = 1;
	buf[2] = METHOD_NONE;
	if (write_all(fd, buf, 3, cfg->connect_timeout_ms) != 0)
		goto fail;

	if (read_all(fd, buf, 2, cfg->connect_timeout_ms) != 0)
		goto fail;
	if (buf[0] != SOCKS_VER) {
		udpc_debug("proxy replied with version 0x%02x, expected 0x05", buf[0]);
		errno = EPROTO;
		goto fail;
	}
	if (buf[1] == METHOD_UNACCEPTABLE) {
		udpc_err("proxy rejected all offered authentication methods");
		if (cfg->have_credentials)
			udpc_err("credentials are configured but SOCKS5 "
			         "username/password auth is not implemented in v1 "
			         "(FR-P-09, deferred)");
		errno = EACCES;
		goto fail;
	}
	if (buf[1] != METHOD_NONE) {
		udpc_err("proxy selected authentication method 0x%02x, which v1 "
		         "does not implement (FR-P-09, deferred)",
		         buf[1]);
		errno = EACCES;
		goto fail;
	}

	/* UDP ASSOCIATE request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT.
	 *
	 * FR-P-05: declare 0.0.0.0:0 unless the application bound a concrete
	 * address.  Proxies pin the association to a declared address, so
	 * declaring one we will not send from breaks the association. */
	buf[0] = SOCKS_VER;
	buf[1] = CMD_UDP_ASSOCIATE;
	buf[2] = 0;

	if (bind_addr != NULL && udpc_sa_len(bind_addr) != 0) {
		/* Same ATYP+addr+port encoding as a datagram header, including
		 * the v4-mapped normalisation. */
		hlen = encode_addr(buf + 3, sizeof(buf) - 3, bind_addr);
		if (hlen < 0)
			goto fail;
	} else {
		if (cfg->proxy.ss_family == AF_INET6) {
			buf[3] = UDPC_ATYP_IPV6;
			memset(buf + 4, 0, 16 + 2); /* :: port 0 */
			hlen = 1 + 16 + 2;
		} else {
			buf[3] = UDPC_ATYP_IPV4;
			memset(buf + 4, 0, 4 + 2); /* 0.0.0.0 port 0 */
			hlen = 1 + 4 + 2;
		}
	}

	if (write_all(fd, buf, 3 + (size_t)hlen, cfg->connect_timeout_ms) != 0)
		goto fail;

	/* Reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT.  Read the fixed part,
	 * then exactly as much as the declared ATYP requires -- never a fixed
	 * slurp, which would either block or steal bytes. */
	if (read_all(fd, buf, 4, cfg->connect_timeout_ms) != 0)
		goto fail;
	if (buf[0] != SOCKS_VER) {
		errno = EPROTO;
		goto fail;
	}
	if (buf[1] != REP_SUCCEEDED) {
		udpc_debug("proxy refused UDP ASSOCIATE with reply code 0x%02x",
		           buf[1]);
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
		goto fail;
	}

	/* Read exactly what the declared ATYP requires -- never a fixed-size
	 * slurp, which would either block waiting for bytes the proxy will not
	 * send or steal bytes that are not ours.  replylen tracks how much of
	 * buf is actually valid, so nothing downstream reads past it. */
	{
		size_t replylen;

		switch (buf[3]) {
		case UDPC_ATYP_IPV4:
			if (read_all(fd, buf + 4, 4 + 2, cfg->connect_timeout_ms) != 0)
				goto fail;
			replylen = 4 + 4 + 2;
			break;
		case UDPC_ATYP_IPV6:
			if (read_all(fd, buf + 4, 16 + 2, cfg->connect_timeout_ms) != 0)
				goto fail;
			replylen = 4 + 16 + 2;
			break;
		case UDPC_ATYP_DOMAIN: {
			size_t dlen;
			if (read_all(fd, buf + 4, 1, cfg->connect_timeout_ms) != 0)
				goto fail;
			dlen = buf[4];
			if (read_all(fd, buf + 5, dlen + 2,
			             cfg->connect_timeout_ms) != 0)
				goto fail;
			replylen = 5 + dlen + 2;
			break;
		}
		default:
			errno = EPROTO;
			goto fail;
		}

		/* The reply's ATYP..PORT tail has the same shape as a UDP
		 * header's, minus the RSV+FRAG prefix.  Rebuild that prefix so
		 * the one decoder covers both, rather than duplicating the
		 * address parsing. */
		{
			uint8_t tmp[UDPC_SOCKS_HDR_MAX];
			size_t taillen = replylen - 3; /* ATYP..PORT, plus a byte */

			memset(tmp, 0, 3);
			memcpy(tmp + 3, buf + 3, taillen);
			if (udpc_socks_decode(tmp, 3 + taillen, &hdr) < 0)
				goto fail;
		}
	}

	if (!hdr.addr_valid) {
		/* A named relay would need a lookup we cannot do honestly here. */
		udpc_err("proxy returned a domain-name relay address, which is "
		         "not usable for a UDP association");
		errno = EPROTO;
		goto fail;
	}

	conn->relay = hdr.addr;

	/* A proxy may legitimately return 0.0.0.0 or :: to mean "the address
	 * you already reached me on".  Substituting the proxy's own address is
	 * the standard reading, and without it the shim would send datagrams to
	 * the wildcard address. */
	{
		bool wildcard = false;
		if (conn->relay.ss_family == AF_INET) {
			const struct sockaddr_in *r =
				(const struct sockaddr_in *)&conn->relay;
			wildcard = (r->sin_addr.s_addr == INADDR_ANY);
		} else if (conn->relay.ss_family == AF_INET6) {
			const struct sockaddr_in6 *r =
				(const struct sockaddr_in6 *)&conn->relay;
			wildcard = IN6_IS_ADDR_UNSPECIFIED(&r->sin6_addr);
		}
		if (wildcard) {
			uint16_t port = udpc_sa_port(
				(const struct sockaddr *)&conn->relay);
			conn->relay = cfg->proxy;
			udpc_sa_set_port((struct sockaddr *)&conn->relay, port);
			udpc_debug("proxy returned a wildcard relay address; "
			           "using the proxy address instead");
		}
	}

	conn->control_fd = fd;
	return 0;

fail:
	saved = errno;
	if (fd >= 0)
		close(fd);
	conn->control_fd = -1;
	*out_errno = saved ? saved : ECONNREFUSED;
	return -1;
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

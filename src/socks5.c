#include "socks5.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
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

/* Writes ATYP 0x03 + length + name + port at buf, returning its length. */
static ssize_t encode_name(uint8_t *buf, size_t buflen, const char *host,
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
	if (buflen < 1 + 1 + hlen + 2) {
		errno = ENOBUFS;
		return -1;
	}

	buf[0] = UDPC_ATYP_DOMAIN;
	buf[1] = (uint8_t)hlen;
	memcpy(buf + 2, host, hlen);
	nport = htons(port);
	memcpy(buf + 2 + hlen, &nport, 2);

	return (ssize_t)(4 + hlen);
}

/* encode_addr or encode_name, as the address is held. */
static ssize_t encode_target(uint8_t *buf, size_t buflen,
                             const struct udpc_socks_addr *a)
{
	if (a->named)
		return encode_name(buf, buflen, a->host, a->port);
	return encode_addr(buf, buflen, (const struct sockaddr *)&a->sa);
}

ssize_t udpc_socks_encode_domain(uint8_t *buf, size_t buflen, const char *host,
                                 uint16_t port)
{
	ssize_t n;

	if (host == NULL) {
		errno = EDESTADDRREQ;
		return -1;
	}
	if (buflen < 3) {
		errno = ENOBUFS;
		return -1;
	}

	buf[0] = 0;
	buf[1] = 0;
	buf[2] = 0; /* FRAG */

	n = encode_name(buf + 3, buflen - 3, host, port);
	if (n < 0)
		return -1;

	return n + 3;
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

/* --- hops ------------------------------------------------------------------ */

/* One hop as the handshake sees it.  Hop 1 is the top-level proxy and
 * credentials, exactly as in 0.1.0; hop k >= 2 is cfg->hops[k - 2] (D-38). */
struct hop {
	unsigned no;      /* from 1 */
	unsigned n;       /* hops in the chain */
	const char *spec; /* as written, for diagnostics */
	struct udpc_socks_addr addr;
	bool have_credentials;
	const char *username;
	const char *password;
};

/* Fills h for hop index k, from 0.  Returns 0, or -1 with errno EINVAL for a
 * later hop whose address does not parse, which udpc_config_finalize has
 * already ruled out. */
static int hop_view(const struct udpc_config *cfg, unsigned k, struct hop *h)
{
	const struct udpc_hop *hp;

	memset(h, 0, sizeof(*h));
	h->no = k + 1;
	h->n = 1 + cfg->nextra;

	if (k == 0) {
		h->spec = cfg->proxy_spec;
		h->addr.sa = cfg->proxy;
		h->have_credentials = cfg->have_credentials;
		h->username = cfg->username;
		h->password = cfg->password;
		return 0;
	}

	hp = &cfg->hops[k - 1];
	h->spec = hp->spec;
	h->have_credentials = hp->have_credentials;
	h->username = hp->username;
	h->password = hp->password;
	return udpc_socks_hop_addr(hp->spec, &h->addr);
}

/* The prefix a diagnostic about h carries: nothing for a chain of one, so its
 * diagnostics are 0.1.0's word for word (FR-CH-01), and the hop otherwise
 * (FR-CH-12). */
#define HOP_NAME_MAX (sizeof("hop 8 of 8 (): ") + 256)

static const char *hop_name(const struct hop *h, char *buf, size_t len)
{
	if (h->n <= 1)
		return "";
	snprintf(buf, len, "hop %u of %u (%s): ", h->no, h->n, h->spec);
	return buf;
}

static struct udpc_ratelimit g_rl_hop;

/* In a chain, says which hop failed and how (FR-CH-12).  A chain of one says
 * nothing here, as 0.1.0 did not: the errno is its report.  Rate-limited, since
 * a program retrying its sends retries the chain each time.  Keeps errno. */
static void hop_failed(const struct hop *h, const char *what, int err)
{
	char name[HOP_NAME_MAX], note[64];
	unsigned n;

	if (h->n <= 1)
		return;
	if ((n = udpc_ratelimit(&g_rl_hop)) == 0) {
		errno = err;
		return;
	}
	udpc_err("%s%s: %s%s", hop_name(h, name, sizeof(name)), what,
	         strerror(err), udpc_ratelimit_note(n, note, sizeof(note)));
	errno = err;
}

int udpc_socks_hop_addr(const char *spec, struct udpc_socks_addr *out)
{
	struct sockaddr_in *in = (struct sockaddr_in *)&out->sa;
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&out->sa;
	char host[sizeof(out->host)];
	uint16_t port;

	memset(out, 0, sizeof(*out));
	if (udpc_addr_split(spec, UDPC_DEFAULT_PROXY_PORT, host, sizeof(host), &port,
	                    NULL) != 0) {
		errno = EINVAL;
		return -1;
	}

	if (inet_pton(AF_INET, host, &in->sin_addr) == 1) {
		in->sin_family = AF_INET;
		in->sin_port = htons(port);
		return 0;
	}
	if (inet_pton(AF_INET6, host, &in6->sin6_addr) == 1) {
		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(port);
		return 0;
	}

	/* D-39: a name stays a name, for the hop before this one to resolve. */
	memset(&out->sa, 0, sizeof(out->sa));
	out->named = true;
	memcpy(out->host, host, sizeof(out->host));
	out->port = port;
	return 0;
}

/* True for 0.0.0.0 and ::. */
static bool sa_is_unspecified(const struct sockaddr_storage *ss)
{
	if (ss->ss_family == AF_INET)
		return ((const struct sockaddr_in *)ss)->sin_addr.s_addr ==
		       INADDR_ANY;
	if (ss->ss_family == AF_INET6)
		return IN6_IS_ADDR_UNSPECIFIED(
			&((const struct sockaddr_in6 *)ss)->sin6_addr);
	return false;
}

/* True if a hop was given as a loopback address: numerically, or as the name
 * "localhost", which RFC 6761 reserves for loopback (D-40). */
static bool hop_is_loopback(const struct udpc_socks_addr *hop)
{
	if (hop->named)
		return strcasecmp(hop->host, "localhost") == 0 ||
		       strcasecmp(hop->host, "localhost.") == 0;
	return udpc_addr_is_loopback((const struct sockaddr *)&hop->sa);
}

/* D-40.  Hop 1's relay is fixed up by udpc_socks_fixup_relay, against the
 * address this host reached it on. */
void udpc_socks_fixup_hop_relay(struct udpc_socks_addr *relay,
                                const struct udpc_socks_addr *hop)
{
	const struct sockaddr *r = (const struct sockaddr *)&relay->sa;
	bool wildcard;
	uint16_t port;

	if (relay->named ||
	    (relay->sa.ss_family != AF_INET && relay->sa.ss_family != AF_INET6))
		return;
	wildcard = sa_is_unspecified(&relay->sa);

	/* A loopback relay is the hop's own view of itself.  It is reachable
	 * from the hop before only if the two share a host, which is what a
	 * hop given as a loopback address means: the hop before connected to
	 * it there. */
	if (!wildcard) {
		if (!udpc_addr_is_loopback(r) || hop_is_loopback(hop))
			return;
	}

	port = udpc_sa_port(r);

	/* A wildcard from a hop given as "localhost" is that host's loopback,
	 * kept as an address rather than a name: the receive check can then
	 * compare it exactly, not by port alone (D-41). */
	if (wildcard && hop->named && hop_is_loopback(hop)) {
		udpc_debug("a later hop given as localhost returned a wildcard "
		           "relay; using loopback");
		if (relay->sa.ss_family == AF_INET)
			((struct sockaddr_in *)&relay->sa)->sin_addr.s_addr =
				htonl(INADDR_LOOPBACK);
		else
			((struct sockaddr_in6 *)&relay->sa)->sin6_addr =
				in6addr_loopback;
		return;
	}

	udpc_debug("a later hop returned a %s relay; using its address as given",
	           wildcard ? "wildcard" : "loopback");

	*relay = *hop;
	if (relay->named)
		relay->port = port;
	else
		udpc_sa_set_port((struct sockaddr *)&relay->sa, port);
}

/* --- negotiation ----------------------------------------------------------- */

/* Opens the TCP connection to hop 1.  Returns the connected descriptor, or -1
 * with errno set and nothing left open. */
static int open_tcp(const struct udpc_config *cfg)
{
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
	                         cfg->connect_timeout_ms) != 0) {
		saved = errno;
		close(fd);
		errno = saved ? saved : ECONNREFUSED;
		return -1;
	}

	{
		/* Nagle would delay the request behind the greeting. */
		int one = 1;
		(void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	}
	return fd;
}

/* Completes method negotiation with hop h over fd, which is a connection to
 * it or a tunnel through the hops before it, including RFC 1929
 * authentication when the hop selects it.  Shared by UDP ASSOCIATE and CONNECT,
 * so both authenticate identically.  Returns 0, or -1 with errno set; fd stays
 * open either way.  *reported says whether a failure has already been
 * explained, so the caller does not add a vaguer line after it (D-43). */
static int negotiate(int fd, int timeout_ms, const struct hop *h, bool *reported)
{
	uint8_t buf[2 + 2];
	char name[HOP_NAME_MAX];
	const char *who = hop_name(h, name, sizeof(name));

	*reported = false;

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
		if (h->have_credentials)
			buf[2 + nmethods++] = METHOD_USERPASS;
		buf[1] = nmethods;

		if (write_all(fd, buf, 2 + (size_t)nmethods, timeout_ms) != 0)
			return -1;
	}

	if (read_all(fd, buf, 2, timeout_ms) != 0)
		return -1;
	if (buf[0] != SOCKS_VER) {
		udpc_debug("%sproxy replied with version 0x%02x, expected 0x05", who,
		           buf[0]);
		errno = EPROTO;
		return -1;
	}
	if (buf[1] == METHOD_UNACCEPTABLE) {
		udpc_err("%sproxy rejected all offered authentication methods", who);
		if (!h->have_credentials && h->no == 1)
			udpc_err("%sno credentials are configured; set "
			         "UDPCHAINS_USERNAME and UDPCHAINS_PASSWORD_FILE "
			         "if the proxy requires authentication",
			         who);
		else if (!h->have_credentials)
			udpc_err("%sno credentials are configured for this hop; "
			         "set username and password_file in its [hop] "
			         "section, or UDPCHAINS_USERNAME_%u and "
			         "UDPCHAINS_PASSWORD_FILE_%u",
			         who, h->no, h->no);
		*reported = true;
		errno = EACCES;
		return -1;
	}
	if (buf[1] == METHOD_USERPASS) {
		/* FR-P-09 / RFC 1929.  A separate buffer: the request can reach
		 * 513 bytes. */
		uint8_t authbuf[3 + 255 + 255];
		ssize_t alen;

		if (!h->have_credentials) {
			/* Unreachable unless the proxy selected a method we did
			 * not offer, which is a protocol violation worth naming
			 * rather than treating as an auth failure. */
			udpc_err("%sproxy selected username/password "
			         "authentication, which was not offered -- no "
			         "credentials are configured",
			         who);
			*reported = true;
			errno = EPROTO;
			return -1;
		}

		alen = udpc_socks_encode_userpass(authbuf, sizeof(authbuf),
		                                  h->username, h->password);
		if (alen < 0) {
			udpc_err("%scannot encode credentials: username must be 1 "
			         "to 255 bytes and the password at most 255",
			         who);
			*reported = true;
			errno = EINVAL;
			return -1;
		}

		/* NFR-05: the length is logged, never the bytes. */
		udpc_debug("%sproxy selected username/password auth; sending "
		           "credentials for user of %zu bytes",
		           who, strlen(h->username));

		if (write_all(fd, authbuf, (size_t)alen, timeout_ms) != 0) {
			explicit_bzero(authbuf, sizeof(authbuf));
			return -1;
		}
		explicit_bzero(authbuf, sizeof(authbuf));

		if (read_all(fd, buf, 2, timeout_ms) != 0)
			return -1;
		if (buf[0] != UDPC_AUTH_VER) {
			udpc_err("%sproxy replied to authentication with version "
			         "0x%02x, expected 0x01 (RFC 1929)",
			         who, buf[0]);
			*reported = true;
			errno = EPROTO;
			return -1;
		}
		if (buf[1] != 0x00) {
			udpc_err("%sproxy rejected the supplied credentials "
			         "(status 0x%02x)",
			         who, buf[1]);
			*reported = true;
			errno = EACCES;
			return -1;
		}
		udpc_debug("%sauthenticated", who);
	} else if (buf[1] != METHOD_NONE) {
		udpc_err("%sproxy selected authentication method 0x%02x, which is "
		         "not implemented (only 0x00 and 0x02 are supported)",
		         who, buf[1]);
		*reported = true;
		errno = EACCES;
		return -1;
	}
	return 0;
}

/* Writes the unspecified address with port 0 at buf, as ATYP + address + port,
 * in the given family: what a request declares when it has nothing to
 * declare. */
static ssize_t encode_unspecified(uint8_t *buf, int family)
{
	if (family == AF_INET6) {
		buf[0] = UDPC_ATYP_IPV6;
		memset(buf + 1, 0, 16 + 2); /* :: port 0 */
		return 1 + 16 + 2;
	}
	buf[0] = UDPC_ATYP_IPV4;
	memset(buf + 1, 0, 4 + 2); /* 0.0.0.0 port 0 */
	return 1 + 4 + 2;
}

/* Sends a request -- VER, CMD, RSV, then dst, which is ATYP, DST.ADDR and
 * DST.PORT already encoded -- and reads the reply, decoding BND.ADDR/BND.PORT
 * into *bnd.  Returns 0, or -1 with errno set from the reply code (FR-F-07). */
static int request(int fd, int timeout_ms, uint8_t cmd, const uint8_t *dst,
                   size_t dstlen, struct udpc_socks_hdr *bnd)
{
	uint8_t buf[3 + UDPC_SOCKS_HDR_MAX];
	size_t replylen;

	if (dstlen > sizeof(buf) - 3) {
		errno = EINVAL;
		return -1;
	}
	buf[0] = SOCKS_VER;
	buf[1] = cmd;
	buf[2] = 0;
	memcpy(buf + 3, dst, dstlen);

	if (write_all(fd, buf, 3 + dstlen, timeout_ms) != 0)
		return -1;

	/* Reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT.  Read the fixed part,
	 * then exactly as much as the declared ATYP requires -- never a fixed
	 * slurp, which would either block waiting for bytes the proxy will not
	 * send or steal bytes that are not ours.  After a CONNECT the bytes
	 * that follow are the tunnelled stream: in a chain, the next hop's
	 * greeting. */
	if (read_all(fd, buf, 4, timeout_ms) != 0)
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
		if (read_all(fd, buf + 4, 4 + 2, timeout_ms) != 0)
			return -1;
		replylen = 4 + 4 + 2;
		break;
	case UDPC_ATYP_IPV6:
		if (read_all(fd, buf + 4, 16 + 2, timeout_ms) != 0)
			return -1;
		replylen = 4 + 16 + 2;
		break;
	case UDPC_ATYP_DOMAIN: {
		size_t dlen;
		if (read_all(fd, buf + 4, 1, timeout_ms) != 0)
			return -1;
		dlen = buf[4];
		if (read_all(fd, buf + 5, dlen + 2, timeout_ms) != 0)
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

/* A reply of all zeros is not taken as a signal: proxies that send it send it
 * whatever the family. */
int udpc_socks_declared_family(const struct udpc_socks_addr *hop,
                               const struct udpc_socks_hdr *bnd)
{
	if (!hop->named)
		return hop->sa.ss_family;
	if (bnd != NULL && bnd->addr_valid && !sa_is_unspecified(&bnd->addr)) {
		const struct sockaddr_in6 *b6 =
			(const struct sockaddr_in6 *)&bnd->addr;

		if (bnd->addr.ss_family == AF_INET6 &&
		    IN6_IS_ADDR_V4MAPPED(&b6->sin6_addr))
			return AF_INET;
		return bnd->addr.ss_family;
	}
	return AF_INET;
}

/* Negotiates with h over fd, and reports a failure naming the hop unless
 * negotiate has already said what went wrong (D-43). */
static int negotiate_hop(int fd, const struct udpc_config *cfg,
                         const struct hop *h)
{
	bool reported;

	if (negotiate(fd, cfg->connect_timeout_ms, h, &reported) == 0)
		return 0;
	if (!reported)
		hop_failed(h, "negotiation failed", errno);
	return -1;
}

/* Returns a descriptor whose stream is negotiated with hop index k, from 0: a
 * connection to hop 1, extended by CONNECT through each hop before k, each hop
 * negotiated with its own credentials inside the tunnel (FR-CH-03).  *h is left
 * describing hop k, and *family is the family to declare to it (D-44).
 * Returns -1 with errno set and nothing left open. */
static int open_tunnel(const struct udpc_config *cfg, unsigned k, struct hop *h,
                       int *family)
{
	uint8_t dst[UDPC_SOCKS_HDR_MAX];
	struct udpc_socks_hdr bnd;
	char what[48];
	unsigned j;
	ssize_t dlen;
	int fd, saved;

	(void)hop_view(cfg, 0, h);
	*family = udpc_socks_declared_family(&h->addr, NULL);
	fd = open_tcp(cfg);
	if (fd < 0) {
		hop_failed(h, "cannot connect", errno);
		return -1;
	}
	if (negotiate_hop(fd, cfg, h) != 0)
		goto fail;

	for (j = 1; j <= k; j++) {
		if (hop_view(cfg, j, h) != 0) {
			hop_failed(h, "the address does not parse", errno);
			goto fail;
		}

		/* D-39: the address as given.  A name goes as ATYP 0x03, for
		 * hop j to resolve; it is never looked up here.  BND.ADDR is hop
		 * j's outbound address for the tunnel, used only for its
		 * family. */
		dlen = encode_target(dst, sizeof(dst), &h->addr);
		if (dlen < 0 || request(fd, cfg->connect_timeout_ms, CMD_CONNECT,
		                        dst, (size_t)dlen, &bnd) != 0) {
			snprintf(what, sizeof(what), "hop %u could not reach it", j);
			hop_failed(h, what, errno);
			goto fail;
		}
		*family = udpc_socks_declared_family(&h->addr, &bnd);
		if (negotiate_hop(fd, cfg, h) != 0)
			goto fail;
	}
	return fd;

fail:
	saved = errno;
	close(fd);
	errno = saved ? saved : ECONNREFUSED;
	return -1;
}

/* Associates with hop index k, from 0: a tunnel to it, then UDP ASSOCIATE.  On
 * success *fdp is the control connection and *relay the relay after the
 * fixup.  Returns -1 with errno set and nothing left open. */
static int associate_hop(const struct udpc_config *cfg, unsigned k,
                         const struct sockaddr *bind_addr, int *fdp,
                         struct udpc_socks_addr *relay)
{
	uint8_t dst[UDPC_SOCKS_HDR_MAX];
	char name[HOP_NAME_MAX];
	struct udpc_socks_hdr hdr;
	struct hop h;
	ssize_t dlen;
	int fd, saved, family;

	fd = open_tunnel(cfg, k, &h, &family);
	if (fd < 0)
		return -1;

	/* FR-P-05: declare 0.0.0.0:0 unless the application bound a concrete
	 * address.  Proxies pin the association to a declared address, so
	 * declaring one we will not send from breaks the association.  Only
	 * hop 1 sees datagrams from the application's socket; a later hop sees
	 * them from the previous hop's relay, whose address is not known, so it
	 * is always declared the unspecified address (D-44). */
	if (k == 0 && bind_addr != NULL && udpc_sa_len(bind_addr) != 0)
		dlen = encode_addr(dst, sizeof(dst), bind_addr);
	else
		dlen = encode_unspecified(dst, family);

	if (dlen < 0 || request(fd, cfg->connect_timeout_ms, CMD_UDP_ASSOCIATE,
	                        dst, (size_t)dlen, &hdr) != 0) {
		hop_failed(&h, "UDP ASSOCIATE failed", errno);
		goto fail;
	}

	if (!hdr.addr_valid) {
		/* A named relay would need a lookup we cannot do honestly here. */
		udpc_err("%sproxy returned a domain-name relay address, which is "
		         "not usable for a UDP association",
		         hop_name(&h, name, sizeof(name)));
		errno = EPROTO;
		goto fail;
	}

	memset(relay, 0, sizeof(*relay));
	relay->sa = hdr.addr;
	if (k == 0)
		udpc_socks_fixup_relay(&relay->sa, cfg);
	else
		udpc_socks_fixup_hop_relay(relay, &h.addr);
	*fdp = fd;
	return 0;

fail:
	saved = errno;
	close(fd);
	errno = saved ? saved : ECONNREFUSED;
	return -1;
}

int udpc_socks_associate(const struct udpc_config *cfg,
                         const struct sockaddr *bind_addr,
                         struct udpc_socks_conn *conn, int *out_errno)
{
	struct udpc_socks_addr relay;

	memset(conn, 0, sizeof(*conn));
	conn->control_fd = -1;

	if (cfg->nextra != 0) {
		*out_errno = EINVAL;
		return -1;
	}
	if (associate_hop(cfg, 0, bind_addr, &conn->control_fd, &relay) != 0) {
		*out_errno = errno;
		return -1;
	}
	conn->relay = relay.sa;
	return 0;
}

int udpc_socks_associate_chain(const struct udpc_config *cfg,
                               const struct sockaddr *bind_addr,
                               struct udpc_socks_chain *chain, int *out_errno)
{
	unsigned k;

	memset(chain, 0, sizeof(*chain));
	for (k = 0; k < UDPC_CHAIN_MAX; k++)
		chain->control_fd[k] = -1;

	if (cfg->nextra > UDPC_CHAIN_MAX - 1) {
		*out_errno = EINVAL;
		return -1;
	}

	/* Hop 1 first, so a dead first hop fails fastest.  Each hop's tunnel is
	 * built afresh through the hops before it: O(n^2) handshakes, every
	 * step with its own timeout. */
	for (k = 0; k <= cfg->nextra; k++) {
		if (associate_hop(cfg, k, k == 0 ? bind_addr : NULL,
		                  &chain->control_fd[k], &chain->relay[k]) != 0) {
			*out_errno = errno;
			udpc_socks_disconnect_chain(chain);
			return -1;
		}
		chain->n = k + 1;
	}
	return 0;
}

int udpc_socks_connect(const struct udpc_config *cfg, const struct sockaddr *dst,
                       int *out_errno)
{
	uint8_t req[UDPC_SOCKS_HDR_MAX];
	struct udpc_socks_hdr hdr;
	struct hop h;
	ssize_t dlen;
	int fd, saved, family;

	if (dst == NULL || udpc_sa_len(dst) == 0) {
		*out_errno = EAFNOSUPPORT;
		return -1;
	}
	if (cfg->nextra > UDPC_CHAIN_MAX - 1) {
		*out_errno = EINVAL;
		return -1;
	}

	fd = open_tunnel(cfg, cfg->nextra, &h, &family);
	if (fd < 0) {
		*out_errno = errno;
		return -1;
	}

	/* BND.ADDR is the proxy's outbound address for the tunnel.  The
	 * caller has no use for it, and a domain-form one is legal here. */
	dlen = encode_addr(req, sizeof(req), dst);
	if (dlen < 0 || request(fd, cfg->connect_timeout_ms, CMD_CONNECT, req,
	                        (size_t)dlen, &hdr) != 0) {
		saved = errno;
		hop_failed(&h, "CONNECT failed", saved);
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

void udpc_socks_disconnect_chain(struct udpc_socks_chain *chain)
{
	unsigned k;

	if (chain == NULL)
		return;
	for (k = 0; k < chain->n && k < UDPC_CHAIN_MAX; k++) {
		if (chain->control_fd[k] >= 0)
			close(chain->control_fd[k]);
		chain->control_fd[k] = -1;
	}
	chain->n = 0;
}

static bool control_alive(int fd)
{
	struct pollfd pfd;
	int r;

	if (fd < 0)
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
	 * a dead association until the send fails, which is already handled.
	 *
	 * Through a tunnel, a hop that drops the association closes its end of
	 * the tunnel, and the hops before it carry that close back here. */
	pfd.fd = fd;
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

bool udpc_socks_control_alive(const struct udpc_socks_conn *conn)
{
	return conn != NULL && control_alive(conn->control_fd);
}

bool udpc_socks_chain_alive(const struct udpc_socks_chain *chain)
{
	unsigned k;

	if (chain == NULL || chain->n == 0)
		return false;
	for (k = 0; k < chain->n && k < UDPC_CHAIN_MAX; k++)
		if (!control_alive(chain->control_fd[k]))
			return false;
	return true;
}

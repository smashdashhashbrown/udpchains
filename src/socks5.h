/* socks5.h -- SOCKS5 client (FR-P-01…FR-P-08).
 *
 * D-01: implemented clean-room from RFC 1928 (and RFC 1929 for the deferred
 * authentication path).  No reference implementation was consulted.
 *
 * RFC 1928 §7, the UDP request header this file encodes and decodes:
 *
 *   +-----+------+------+----------+----------+----------+
 *   | RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
 *   +-----+------+------+----------+----------+----------+
 *   |  2  |  1   |  1   | Variable |    2     | Variable |
 *   +-----+------+------+----------+----------+----------+
 */
#ifndef UDPCHAINS_SOCKS5_H
#define UDPCHAINS_SOCKS5_H

#include "compat.h"

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

#include "addr.h"
#include "config.h"

/* Largest possible header: RSV(2) + FRAG(1) + ATYP(1) + len(1) + domain(255) +
 * port(2).  The receive scratch buffer is sized max_datagram + this (D-11). */
#define UDPC_SOCKS_HDR_MAX 262

/* Smallest possible header: RSV(2) + FRAG(1) + ATYP(1) + IPv4(4) + port(2). */
#define UDPC_SOCKS_HDR_MIN 10

#define UDPC_ATYP_IPV4 0x01
#define UDPC_ATYP_DOMAIN 0x03
#define UDPC_ATYP_IPV6 0x04

/* --- header codec (FR-P-03, FR-P-04, FR-P-07) ------------------------------ */

/* Encodes a header addressed to dst.  Returns the header length, or -1 with
 * errno set to EAFNOSUPPORT for a family we cannot express.
 * FRAG is always emitted as 0 (FR-P-04). */
ssize_t udpc_socks_encode(uint8_t *buf, size_t buflen, const struct sockaddr *dst);

/* Encodes a header addressed to a hostname, for proxy-side resolution
 * (FR-P-07, ATYP 0x03).
 *
 * Note: no libc UDP entry point accepts a hostname -- sendto and friends take a
 * sockaddr -- so this form is not reachable from the hook path.  It exists
 * because the requirement calls for it and because a future non-socket entry
 * point (or a caller of this library) may have a name in hand.  It is covered
 * by unit tests rather than by the hook matrix. */
ssize_t udpc_socks_encode_domain(uint8_t *buf, size_t buflen, const char *host,
                                 uint16_t port);

struct udpc_socks_hdr {
	uint8_t frag;
	uint8_t atyp;
	struct sockaddr_storage addr; /* valid when atyp is IPV4 or IPV6 */
	bool addr_valid;
	char domain[256]; /* valid when atyp is DOMAIN */
	uint16_t port;
};

/* Decodes a header from the front of buf.  Returns the number of bytes
 * consumed (the payload starts there), or -1 if the datagram is malformed or
 * too short for its declared ATYP.
 *
 * A malformed datagram is never partially delivered: the caller discards it and
 * reads again (DESIGN.md 5.2). */
ssize_t udpc_socks_decode(const uint8_t *buf, size_t len,
                          struct udpc_socks_hdr *out);

/* --- association (FR-P-01, FR-P-02, FR-P-05) ------------------------------- */

struct udpc_socks_conn {
	int control_fd;                /* TCP, FD_CLOEXEC (FR-L-05) */
	struct sockaddr_storage relay; /* BND.ADDR/BND.PORT from the reply */
};

/* Opens the control connection, negotiates method 0x00, and issues UDP
 * ASSOCIATE.  On success fills conn and returns 0.  On failure returns -1 and
 * sets *out_errno to what the application's send call should report -- there is
 * no fallback to a direct send (SEC-01).
 *
 * bind_addr is the concrete address the application bound, or NULL.  FR-P-05:
 * the request declares 0.0.0.0:0 unless the application bound a concrete
 * address, because proxies pin the association to a declared address and
 * declaring one the shim will not send from breaks the association. */
/* Encodes an RFC 1929 username/password sub-negotiation request into buf.
 * Returns its length, or -1 with errno set: EINVAL for an empty or over-long
 * username, or an over-long password; ENOBUFS if buf is too small.
 *
 * Exposed so the byte layout can be asserted against the RFC directly, rather
 * than only through a live exchange with the fixture. */
ssize_t udpc_socks_encode_userpass(uint8_t *buf, size_t buflen, const char *user,
                                   const char *pass);

/* A chain of one only.  Given a chain it fails with EINVAL, rather than
 * associate with the first hop alone (D-37); use udpc_socks_associate_chain. */
int udpc_socks_associate(const struct udpc_config *cfg,
                         const struct sockaddr *bind_addr,
                         struct udpc_socks_conn *conn, int *out_errno);

/* Opens a TCP tunnel to dst through the proxy with SOCKS5 CONNECT (CMD 0x01),
 * negotiating and authenticating exactly as udpc_socks_associate does.  Through
 * a chain, the tunnel runs through every hop and the last one connects to dst.
 * Returns a connected, non-blocking, close-on-exec descriptor whose byte stream
 * is now dst's, or -1 with *out_errno set.
 *
 * Used only for the resolver's TCP fallback when a DNS answer is truncated
 * (D-22).  Application TCP is not proxied; that remains a non-goal. */
int udpc_socks_connect(const struct udpc_config *cfg, const struct sockaddr *dst,
                       int *out_errno);

/* udpc_socks_connect on fd, a caller's TCP socket not yet connected, rather
 * than a new one: fd is connected to hop 1 in its own address family (an
 * AF_INET6 socket reaches an IPv4 proxy v4-mapped), and the tunnel built over
 * it.  Its file status flags are as they were afterwards.  Returns 0, or -1
 * with *out_errno set; fd stays open either way, and after a failure may be
 * connected to the proxy, for the caller to disconnect.
 *
 * For supervisor mode, which carries a program's own TCP query to the system
 * resolver this way, so the program then reads and writes it natively
 * (D-52). */
int udpc_socks_connect_on(const struct udpc_config *cfg, int fd,
                          const struct sockaddr *dst, int *out_errno);

/* Closes the control connection, which is what tells the proxy to release the
 * association (baseline §0.5). */
/* Rewrites a BND.ADDR that cannot be taken literally.
 *
 * A wildcard relay (0.0.0.0 / ::) always means "the address you already reached
 * me on".  A LOOPBACK relay means the same thing whenever the proxy is not on
 * this host -- the proxy can only describe its own local view of the socket it
 * bound.  Both are replaced by the configured proxy address, keeping the port.
 *
 * Exposed separately from udpc_socks_associate so it can be tested: the
 * loopback case only arises with a non-local proxy, which no single-host
 * fixture run can produce. */
void udpc_socks_fixup_relay(struct sockaddr_storage *relay,
                            const struct udpc_config *cfg);

void udpc_socks_disconnect(struct udpc_socks_conn *conn);

/* True while the control connection is still open.  Used to detect an
 * association the proxy has expired, so the next send can transparently
 * re-associate (FR-P-08).  Does not consume application data: the control
 * connection carries none after the reply. */
bool udpc_socks_control_alive(const struct udpc_socks_conn *conn);

/* --- chains (D-37 to D-42) ------------------------------------------------- */

/* An address as SOCKS5 carries it: numeric, or a name the hop before it
 * resolves (ATYP 0x03).  Hops after the first, and their relays, take this
 * form, because they are never resolved here (D-39, D-40). */
struct udpc_socks_addr {
	bool named;
	struct sockaddr_storage sa; /* when !named, port included */
	char host[256];             /* when named */
	uint16_t port;              /* when named, host order */
};

/* Reads a later hop's address as written: a numeric address becomes sa, and a
 * name stays a name.  Never resolves (D-39).  Returns 0, or -1 with errno
 * EINVAL for a spec udpc_addr_split refuses. */
int udpc_socks_hop_addr(const char *spec, struct udpc_socks_addr *out);

/* Hop k's association, for k from 0: control_fd[k] is a stream to hop 1,
 * extended by CONNECT through hops 1 to k, on which hop k+1 was negotiated and
 * asked for UDP ASSOCIATE (FR-CH-03).  relay[k] is that hop's relay after the
 * fixup; relay[0] is always numeric, since it is what this host sends to. */
struct udpc_socks_chain {
	unsigned n; /* hops, 1 to UDPC_CHAIN_MAX */
	int control_fd[UDPC_CHAIN_MAX];
	struct udpc_socks_addr relay[UDPC_CHAIN_MAX];
};

/* Associates with every hop of cfg's chain, first to last (D-37: all of them or
 * none).  bind_addr is declared to hop 1 as udpc_socks_associate declares it;
 * later hops are declared the unspecified address, since datagrams reach them
 * from the previous hop's relay, whose port is not known (FR-P-05).
 *
 * Returns 0, or -1 with *out_errno set and nothing left open.  With a chain of
 * more than one, a failure is reported naming the hop (FR-CH-12).  A chain of
 * one does exactly what udpc_socks_associate does (FR-CH-01). */
int udpc_socks_associate_chain(const struct udpc_config *cfg,
                               const struct sockaddr *bind_addr,
                               struct udpc_socks_chain *chain, int *out_errno);

/* Closes every control connection.  The chain is empty afterwards. */
void udpc_socks_disconnect_chain(struct udpc_socks_chain *chain);

/* Supervisor mode (D-54): while cancelled is set, every wait of a handshake is
 * cut into short slices, and the handshake is abandoned with EINTR as soon as
 * cancelled(arg) is true -- a signal is waiting for the thread whose call needs
 * it.  NULL, the default and all the shim ever has, waits as before. */
void udpc_socks_set_cancel(bool (*cancelled)(void *), void *arg);

/* True while every control connection is open: losing any hop loses the
 * association (FR-CH-09). */
bool udpc_socks_chain_alive(const struct udpc_socks_chain *chain);

/* Room for udpc_socks_chain_path's longest result: a named relay is up to 255
 * bytes of name and ":65535", and each after the first adds ", then ". */
#define UDPC_SOCKS_CHAIN_PATH_MAX (UDPC_CHAIN_MAX * (UDPC_ADDRSTRLEN + 270))

/* Writes the relays a chain's datagrams pass, in order, for the association
 * line (FR-C-06, FR-CH-12): hop 1's, which is what a chain of one has always
 * printed, then each later hop's, by name where it is one -- "127.0.0.1:40001,
 * then 10.0.0.5:40002, then proxy.internal:40003". */
void udpc_socks_chain_path(const struct udpc_socks_chain *ch, char *buf,
                           size_t len);

/* The D-16 fixup for hop k >= 2 (D-40).  relay is numeric, as hop k returned
 * it; hop is hop k's address as given.  A wildcard relay becomes hop's address
 * with the relay's port, and may become a name.  A loopback relay is kept only
 * if hop was given as a loopback address, which puts it on the same host as
 * the hop before it; otherwise it is replaced the same way.  "localhost" counts
 * as a loopback address, and a wildcard from it becomes loopback, not the
 * name. */
void udpc_socks_fixup_hop_relay(struct udpc_socks_addr *relay,
                                const struct udpc_socks_addr *hop);

/* The family of the unspecified address hop k >= 2 is declared in UDP
 * ASSOCIATE (D-44): that of hop's own address when it was given as a number;
 * otherwise that of the address the hop before connected to it from, as the
 * CONNECT reply connect_reply gives it (NULL if there is none); otherwise
 * AF_INET.  Exposed so the choice can be tested without a proxy that reports
 * its outbound address. */
int udpc_socks_declared_family(const struct udpc_socks_addr *hop,
                               const struct udpc_socks_hdr *connect_reply);

/* --- chain codec (FR-CH-05, FR-CH-06) -------------------------------------- */

/* The most header bytes a chain can put in front of a payload. */
#define UDPC_SOCKS_CHAIN_HDR_MAX (UDPC_CHAIN_MAX * UDPC_SOCKS_HDR_MAX)

/* Encodes the headers a datagram to dst needs through ch: one per hop, the
 * layer hop 1 reads outermost and naming hop 2's relay, and so on inwards,
 * with dst in the innermost (FR-CH-05).  For a chain of one this is exactly
 * udpc_socks_encode.  Returns the total length, or -1 with errno set; with
 * inner_off non-NULL, stores where the innermost header starts. */
ssize_t udpc_socks_encode_chain(uint8_t *buf, size_t buflen,
                                const struct udpc_socks_chain *ch,
                                const struct sockaddr *dst, size_t *inner_off);

/* Why udpc_socks_decode_chain refused a datagram. */
enum udpc_socks_drop {
	UDPC_DROP_MALFORMED = 1, /* the layer does not decode */
	UDPC_DROP_FRAG,          /* FRAG is not 0 (FR-P-04) */
	UDPC_DROP_SOURCE         /* not from the relay it must come from */
};

/* Strips and checks a received datagram's headers, outermost first (D-41).
 * Every layer but the innermost must decode, have FRAG 0, and name as its
 * source the relay of the next hop (by port alone, when that relay is a
 * name).  The innermost layer is decoded into *inner and left to the caller,
 * as udpc_socks_decode's result is, FRAG included.
 *
 * Returns the total header length, where the payload starts; or -1 with
 * *layer, from 1 for the outermost, and *why saying what was wrong.  A
 * datagram refused here must be dropped whole (FR-CH-06).  For a chain of one
 * this is exactly udpc_socks_decode. */
ssize_t udpc_socks_decode_chain(const uint8_t *buf, size_t len,
                                const struct udpc_socks_chain *ch,
                                struct udpc_socks_hdr *inner, unsigned *layer,
                                enum udpc_socks_drop *why);

#endif /* UDPCHAINS_SOCKS5_H */

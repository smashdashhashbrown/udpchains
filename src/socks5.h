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
int udpc_socks_associate(const struct udpc_config *cfg,
                         const struct sockaddr *bind_addr,
                         struct udpc_socks_conn *conn, int *out_errno);

/* Closes the control connection, which is what tells the proxy to release the
 * association (baseline §0.5). */
void udpc_socks_disconnect(struct udpc_socks_conn *conn);

/* True while the control connection is still open.  Used to detect an
 * association the proxy has expired, so the next send can transparently
 * re-associate (FR-P-08).  Does not consume application data: the control
 * connection carries none after the reply. */
bool udpc_socks_control_alive(const struct udpc_socks_conn *conn);

#endif /* UDPCHAINS_SOCKS5_H */

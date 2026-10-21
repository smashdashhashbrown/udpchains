/* addr.h -- socket address helpers and destination classification.
 *
 * The classification predicates back D-05: with no bypass path in v1, the shim
 * must be able to say precisely why a destination cannot be carried, rather
 * than failing generically (rider R1) or silently misrouting (rider R2).
 */
#ifndef UDPCHAINS_ADDR_H
#define UDPCHAINS_ADDR_H

#include "compat.h"

#include <netinet/in.h>
#include <stdbool.h>
#include <sys/socket.h>

/* Text form of an address is at most "[" + INET6_ADDRSTRLEN + "%" + IFNAMSIZ +
 * "]:" + 5 digits + NUL.  Round up. */
#define UDPC_ADDRSTRLEN 96

/* Length of the sockaddr for a family, or 0 if the family is not one we
 * intercept (FR-I-06). */
socklen_t udpc_sa_len(const struct sockaddr *sa);

/* Copies a caller-supplied address of `len` bytes into a zeroed ss, checking
 * the length the way the kernel does: EINVAL if it is too short for its family
 * (16 bytes for AF_INET; 24 for AF_INET6, which the kernel accepts without the
 * scope field), EAFNOSUPPORT for a family the shim does not intercept.  Never
 * reads beyond `len` (review item L1).  Returns 0, or -1 with errno set. */
int udpc_sa_copy(const struct sockaddr *sa, socklen_t len,
                 struct sockaddr_storage *ss);

/* Port in host byte order, or 0 if the family is unsupported. */
uint16_t udpc_sa_port(const struct sockaddr *sa);
void udpc_sa_set_port(struct sockaddr *sa, uint16_t port);

/* Formats "1.2.3.4:53" or "[2001:db8::1]:53" into buf.  Never fails; on an
 * unsupported family it writes "<unknown>".  Used only for diagnostics, and
 * never with payload bytes (NFR-05). */
const char *udpc_addr_str(const struct sockaddr *sa, char *buf, size_t buflen);

/* Destination classification.  All take a sockaddr in AF_INET or AF_INET6. */
bool udpc_addr_is_loopback(const struct sockaddr *sa);
bool udpc_addr_is_multicast(const struct sockaddr *sa);
bool udpc_addr_is_broadcast(const struct sockaddr *sa);

/* True if the address belongs to an interface on this host.  Used once, at
 * configuration time, for the D-05 R2 loopback guard.  Walks getifaddrs and so
 * allocates -- never call this from the datagram path (NFR-02). */
bool udpc_addr_is_local(const struct sockaddr *sa);

/* Parses "host:port", "[v6]:port" or "host" (with a default port) into ss.
 * Resolves names via getaddrinfo.  Returns 0 on success, -1 on failure with a
 * human-readable reason in *err (a static string, never allocated). */
int udpc_addr_parse(const char *spec, uint16_t default_port,
                    struct sockaddr_storage *ss, const char **err);

/* Splits "host:port", "[v6]:port" or "host" into host (brackets removed) and
 * port, checking the form but resolving nothing -- for a hop that only the hop
 * before it may resolve (D-39).  Returns 0, or -1 with a static reason in *err. */
int udpc_addr_split(const char *spec, uint16_t default_port, char *host,
                    size_t hostlen, uint16_t *port, const char **err);

/* As udpc_addr_parse, but accepts only a numeric address, so it can never
 * cause a name lookup.  Used for the DNS resolver address (D-22), which would
 * otherwise need resolving before resolution works. */
int udpc_addr_parse_numeric(const char *spec, uint16_t default_port,
                            struct sockaddr_storage *ss, const char **err);

/* Compares two addresses for equality including port. */
bool udpc_addr_equal(const struct sockaddr *a, const struct sockaddr *b);

/* Rewrites `in` into the address family a socket of `family` can actually
 * reach, writing the result to out.  Returns 0, or -1 if no such form exists.
 *
 * The relay address comes from the proxy and has whatever family the control
 * connection used; the application's socket has whatever family the application
 * chose.  They need not match -- an AF_INET6 socket talking to a proxy reached
 * over IPv4 is the common case.  IPv4-mapped IPv6 (::ffff:a.b.c.d) bridges the
 * two; a genuine IPv6 relay simply cannot be reached from an AF_INET socket,
 * and that must fail rather than be papered over. */
int udpc_addr_for_family(const struct sockaddr *in, int family,
                         struct sockaddr_storage *out);

#endif /* UDPCHAINS_ADDR_H */

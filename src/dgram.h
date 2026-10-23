/* dgram.h -- the rules every proxied datagram follows, in either front end.
 *
 * The shim (core.c) and the supervisor (svcall.c, D-48) carry datagrams from
 * different places -- the program's own buffers, or bytes the supervisor has
 * copied out of the program -- but must refuse, wrap, check and unwrap them
 * identically.  What does not depend on where the bytes are lives here, so
 * there is one copy of each rule (D-48: a second front end, not a second
 * implementation).
 */
#ifndef UDPCHAINS_DGRAM_H
#define UDPCHAINS_DGRAM_H

#include "compat.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#include "config.h"
#include "socks5.h"

/* How long an association must have been idle before a send bothers to check
 * whether the proxy has expired it.  Busy sockets pay nothing; only sockets
 * that have actually been quiet -- the ones FR-P-08 is about -- take the extra
 * poll().  Well under the reference proxy's 60 s expiry (baseline §0.5). */
#define UDPC_IDLE_PROBE_SECS 1

/* D-05 R1: 0 if dst can be expressed to a SOCKS5 proxy, or ENETUNREACH, with a
 * rate-limited warning, for a multicast or broadcast destination. */
int udpc_dgram_unrepresentable(const struct sockaddr *dst);

/* D-36: MSG_MORE would join two sends, each with its own header, into one
 * datagram.  Warns (rate-limited) and returns EOPNOTSUPP. */
int udpc_dgram_refuse_cork(void);

/* D-36: true, with a rate-limited warning, if the control data in m asks for
 * UDP_SEGMENT (GSO), which the kernel would split without headers.  m and its
 * control buffer are in this process's memory. */
bool udpc_dgram_wants_gso(int fd, const struct msghdr *m);

/* True for the errors that mean the association has gone: what an expired idle
 * association looks like from a connected UDP socket (FR-P-08). */
bool udpc_dgram_assoc_dead(int err);

/* Receive scratch for cfg: the largest payload, plus a worst-case header for
 * every hop (D-42). */
size_t udpc_dgram_scratch_need(const struct udpc_config *cfg);

/* D-05 R2 / D-40: before an association is set up for a socket connected to
 * dst (NULL if not connected), warn that a loopback destination is resolved at
 * the exit hop, or refuse it under strict_loopback: -1 with *out_errno
 * ENETUNREACH.  Otherwise 0. */
int udpc_dgram_loopback_guard(const struct udpc_config *cfg, const struct sockaddr *dst,
                              int *out_errno);

/* Checks and strips the headers of a datagram read from the relay: n bytes in
 * buf, read with MSG_TRUNC into a buffer of buflen, so n > buflen means it did
 * not fit.  Every layer of ch is checked (D-41), FRAG must be 0 (FR-P-04), and
 * a socket connected to peer (NULL if not connected) accepts only datagrams
 * from it, in family's terms, as the kernel would.
 *
 * Returns the header length, where the payload starts, with the innermost
 * header in *hdr; or -1 if the datagram must be dropped whole, never partly
 * delivered.  Each reason is logged (never the payload, NFR-05). */
ssize_t udpc_dgram_unwrap(const uint8_t *buf, ssize_t n, size_t buflen,
                          const struct udpc_config *cfg,
                          const struct udpc_socks_chain *ch, int family,
                          const struct sockaddr_storage *peer,
                          struct udpc_socks_hdr *hdr);

/* The sender to report for a datagram with header hdr (FR-F-02), in a socket
 * of family's terms as the kernel would give it: the true origin, or for a
 * domain-form reply the connected peer, or nothing.  Returns the address's
 * length, written to *out, or 0 if there is none to report. */
socklen_t udpc_dgram_source(const struct udpc_socks_hdr *hdr, int family,
                            const struct sockaddr_storage *peer,
                            struct sockaddr_storage *out);

#endif /* UDPCHAINS_DGRAM_H */

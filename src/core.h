/* core.h -- the single send path and the single receive path.
 *
 * FR-I-02 is structural here, not a checklist item.  Every send variant funnels
 * into udpc_core_send and every receive variant into udpc_core_recv:
 *
 *     send    = sendto with a NULL destination
 *     write   = send with zero flags
 *     writev  = sendmsg with one iovec and no control data
 *     sendmmsg= sendmsg per element
 *     ... and symmetrically on the receive side.
 *
 * There is therefore no code path that wraps a datagram without a
 * corresponding path that unwraps one.  That is what makes it structurally hard
 * to ship the Proxando failure (baseline §0.3.2): a send path that works
 * alongside a receive path that hands the application a payload with the
 * 10-byte SOCKS header still attached.
 */
#ifndef UDPCHAINS_CORE_H
#define UDPCHAINS_CORE_H

#include "compat.h"

#include <sys/socket.h>
#include <sys/uio.h>

#include "fdtable.h"

/* Returns the entry for fd if this call should be intercepted, else NULL.
 * Declines while the shim is inside its own socket work (guard.h). */
struct udpc_fdent *udpc_intercept(int fd);

/* One application datagram out.  Returns the byte count the APPLICATION
 * supplied (FR-F-01), never the wrapped length. */
ssize_t udpc_core_send(int fd, struct udpc_fdent *e, const struct iovec *iov,
                       int iovcnt, const struct sockaddr *dst, socklen_t dstlen,
                       int flags);

/* One application datagram in.  Fills src from the SOCKS reply header
 * (FR-F-02) and reports truncation through *out_msgflags (FR-F-04). */
ssize_t udpc_core_recv(int fd, struct udpc_fdent *e, const struct iovec *iov,
                       int iovcnt, struct sockaddr *src, socklen_t *srclen,
                       int flags, int *out_msgflags);

#endif /* UDPCHAINS_CORE_H */

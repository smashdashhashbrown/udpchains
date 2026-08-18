/* guard.h -- re-entry guard.
 *
 * The shim performs socket work of its own: the TCP control connection, and
 * occasionally getaddrinfo() when the configured proxy is named rather than
 * numeric.  glibc's resolver sends over ordinary UDP sockets through libc, so
 * without a guard the shim's own lookup of the proxy's name would be
 * intercepted by the shim, which would try to establish an association, which
 * needs the proxy address that is still being resolved.
 *
 * A thread-local depth counter breaks that cycle.  While it is non-zero the
 * interception predicate (DESIGN.md 2.2) declines every call, so the shim's own
 * traffic passes straight through to libc.
 *
 * This is not a bypass in the D-05 sense: it covers only the shim's own
 * connection to the proxy and its own resolution of the proxy's name, never
 * application traffic.  The proxy-name lookup going direct is documented in the
 * README as an unavoidable property of naming a proxy by hostname.
 */
#ifndef UDPCHAINS_GUARD_H
#define UDPCHAINS_GUARD_H

#include "compat.h"

extern __thread int udpc_reentry_depth;

#define UDPC_GUARD_ENTER() (++udpc_reentry_depth)
#define UDPC_GUARD_LEAVE() (--udpc_reentry_depth)
#define UDPC_IN_SHIM() (udpc_reentry_depth != 0)

#endif /* UDPCHAINS_GUARD_H */

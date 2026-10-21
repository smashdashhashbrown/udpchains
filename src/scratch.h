/* scratch.h -- per-thread working buffers (NFR-02, D-11).
 *
 * NFR-02 forbids dynamic allocation on the per-datagram path.  These buffers
 * are allocated once per thread, on that thread's first intercepted datagram,
 * and reused thereafter; the datagram path only reads a thread-local pointer.
 *
 * D-11, why the send and receive paths differ:
 *
 *   Send is zero-copy.  The SOCKS5 header goes in `hdr` and is passed to the
 *   real sendmsg as the FIRST iovec entry, with the application's own buffers
 *   following in `iov`.  The payload is never copied, and scatter/gather
 *   (FR-F-10) falls out for free.  Through a chain, `hdr` holds one header
 *   per hop, still a single iovec entry (FR-CH-05).
 *
 *   Receive copies once, through `buf`.  Header length is not known until ATYP
 *   is read, so reserving a worst-case 262-byte header slot in the
 *   application's buffers would place the first payload bytes inside the
 *   reserved region and need a corrective memmove -- the copy comes back, with
 *   an off-by-one hazard attached.  Reading the whole datagram into `buf`
 *   instead makes FR-F-04 (exact true length for MSG_TRUNC), FR-F-05
 *   (MSG_PEEK) and FR-F-10 (a header can never straddle an application iovec
 *   boundary) straightforward rather than delicate.
 *
 *   The cost is one memcpy of at most max_datagram bytes -- around 200 ns for
 *   8 KB, against NFR-04's 100 us budget.  Through a chain, `buf` has room
 *   for a worst-case header per hop (D-42).
 */
#ifndef UDPCHAINS_SCRATCH_H
#define UDPCHAINS_SCRATCH_H

#include "compat.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/uio.h>

#include "socks5.h"

#ifndef IOV_MAX
#define IOV_MAX 1024
#endif

struct udpc_tls {
	uint8_t *buf;      /* receive scratch: max_datagram + a header per hop */
	size_t buflen;
	struct iovec *iov; /* IOV_MAX + 1, for the send-side header prepend */
	uint8_t hdr[UDPC_SOCKS_CHAIN_HDR_MAX];
};

/* Returns this thread's buffers, sized for at least `bufneed` bytes of receive
 * scratch.  Returns NULL only if allocation fails, in which case the caller
 * must fail closed rather than proceed. */
struct udpc_tls *udpc_tls_get(size_t bufneed);

#endif /* UDPCHAINS_SCRATCH_H */

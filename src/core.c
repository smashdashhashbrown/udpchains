#include "core.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "addr.h"
#include "assoc.h"
#include "dgram.h"
#include "guard.h"
#include "log.h"
#include "real.h"
#include "scratch.h"
#include "shim.h"
#include "socks5.h"

struct udpc_fdent *udpc_intercept(int fd)
{
	if (UDPC_IN_SHIM())
		return NULL;
	/* Verified, at the cost of one getsockopt per intercepted call: an
	 * entry whose socket was closed behind the shim's back must not claim
	 * whatever the kernel has since put at that number (D-23).  Calls on
	 * descriptors the shim does not track still cost two loads and no
	 * syscall. */
	return udpc_fd_lookup_verified(fd);
}

/* Saturates rather than wrapping: lengths summing past SIZE_MAX would
 * otherwise come out small, pass the max_datagram check, and reach a copy
 * sized by the individual entries (L2). */
static size_t iov_total(const struct iovec *iov, int iovcnt)
{
	size_t total = 0;
	int i;

	for (i = 0; i < iovcnt; i++) {
		if (iov[i].iov_len > SIZE_MAX - total)
			return SIZE_MAX;
		total += iov[i].iov_len;
	}
	return total;
}

/* Copies len bytes from src into the application's iovecs, stopping when they
 * are full.  Returns how much was copied. */
static size_t copy_to_iov(const uint8_t *src, size_t len, const struct iovec *iov,
                          int iovcnt)
{
	size_t off = 0;
	int i;

	for (i = 0; i < iovcnt && off < len; i++) {
		size_t take = len - off;

		if (take > iov[i].iov_len)
			take = iov[i].iov_len;
		if (take > 0)
			memcpy(iov[i].iov_base, src + off, take);
		off += take;
	}
	return off;
}

/* One datagram through a held association. */
static ssize_t send_via(int fd, struct udpc_fdent *e, struct udpc_assoc *a,
                        const struct udpc_config *cfg, const struct iovec *iov,
                        int iovcnt, const struct sockaddr *dst, int flags,
                        size_t paylen, int *out_errno)
{
	struct udpc_tls *tls;
	struct sockaddr_storage relay;
	struct msghdr msg;
	ssize_t hlen, n;
	size_t inner;
	int i;

	if (!udpc_assoc_relay_of(a, atomic_load_explicit(&e->family,
	                                                 memory_order_relaxed),
	                         &relay)) {
		*out_errno = ENETUNREACH;
		return -1;
	}

	tls = udpc_tls_get(udpc_dgram_scratch_need(cfg));
	if (tls == NULL) {
		*out_errno = ENOMEM;
		return -1;
	}

	/* One header per hop, in one buffer: still a single iovec entry ahead
	 * of the application's own (FR-CH-05). */
	hlen = udpc_socks_encode_chain(tls->hdr, sizeof(tls->hdr), &a->chain, dst,
	                               &inner);
	if (hlen < 0) {
		*out_errno = errno;
		return -1;
	}

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &relay;
	msg.msg_namelen = udpc_sa_len((const struct sockaddr *)&relay);
	msg.msg_iov = tls->iov;

	if (iovcnt < IOV_MAX) {
		/* D-11: the header is the first iovec entry and the
		 * application's own buffers follow.  The payload is never
		 * copied. */
		tls->iov[0].iov_base = tls->hdr;
		tls->iov[0].iov_len = (size_t)hlen;
		for (i = 0; i < iovcnt; i++)
			tls->iov[i + 1] = iov[i];
		msg.msg_iovlen = (size_t)iovcnt + 1;
	} else {
		/* L2: the application already used every iovec the kernel
		 * allows, so a separate header entry would make the send fail
		 * with EMSGSIZE where the unhooked call succeeds.  The header
		 * and the first buffer are joined in the receive scratch
		 * instead -- one copy, of at most max_datagram bytes, and only
		 * for this rare shape of call. */
		if (iov[0].iov_len > tls->buflen - (size_t)hlen) {
			*out_errno = EMSGSIZE;
			return -1;
		}
		memcpy(tls->buf, tls->hdr, (size_t)hlen);
		memcpy(tls->buf + hlen, iov[0].iov_base, iov[0].iov_len);
		tls->iov[0].iov_base = tls->buf;
		tls->iov[0].iov_len = (size_t)hlen + iov[0].iov_len;
		for (i = 1; i < iovcnt; i++)
			tls->iov[i] = iov[i];
		msg.msg_iovlen = (size_t)iovcnt;
	}

	n = REAL_SENDMSG(fd, &msg, flags);
	if (n < 0) {
		*out_errno = errno;
		return -1;
	}

	/* At -v, record where the datagram actually went and how it was
	 * addressed.  Without this, a proxy that accepts the association and
	 * then silently drops the traffic -- because it disliked the ATYP, say --
	 * is indistinguishable from the shim never sending at all, and there is
	 * nothing on either side to tell the two apart.
	 *
	 * Addresses, lengths and the ATYP byte only.  Never payload (NFR-05). */
	if (udpc_log_level() >= UDPC_DEBUG) {
		char dbuf[UDPC_ADDRSTRLEN], rbuf[UDPC_ADDRSTRLEN];

		udpc_debug("fd %d: sent %zu payload bytes to %s (ATYP 0x%02x) "
		           "via relay %s, %zd bytes on the wire",
		           fd, paylen,
		           udpc_addr_str(dst, dbuf, sizeof(dbuf)),
		           tls->hdr[inner + 3],
		           udpc_addr_str((const struct sockaddr *)&relay, rbuf,
		                         sizeof(rbuf)),
		           n);
	}

	/* FR-F-01: report what the application supplied, never the wrapped
	 * length.  A short write on a datagram socket is not a thing the kernel
	 * does, but if it somehow happened, reporting the application's length
	 * would be a lie -- so treat it as an error. */
	if ((size_t)n != (size_t)hlen + paylen) {
		udpc_debug("short datagram write: %zd of %zu", n,
		           (size_t)hlen + paylen);
		*out_errno = EIO;
		return -1;
	}

	return (ssize_t)paylen;
}

static ssize_t send_once(int fd, struct udpc_fdent *e,
                         const struct udpc_config *cfg, const struct iovec *iov,
                         int iovcnt, const struct sockaddr *dst, int flags,
                         size_t paylen, int *out_errno)
{
	struct udpc_assoc *a;
	ssize_t rc;

	/* One reference serves the whole datagram (D-24): establishing if
	 * needed, the FR-P-08 idle check, the relay address and the activity
	 * stamp all use it.  Taking a fresh one for each cost four pairs of
	 * atomic operations per send. */
	a = udpc_assoc_hold(fd, e, cfg, true, out_errno);
	if (a == NULL)
		return -1;
	rc = send_via(fd, e, a, cfg, iov, iovcnt, dst, flags, paylen, out_errno);
	if (rc >= 0)
		udpc_assoc_mark_used(a);
	else if (udpc_dgram_assoc_dead(*out_errno))
		/* Detach THIS association, so the retry re-associates -- not
		 * one another thread may already have put in its place. */
		udpc_assoc_drop(e, a);
	udpc_assoc_unref(a);
	return rc;
}

ssize_t udpc_core_send(int fd, struct udpc_fdent *e, const struct iovec *iov,
                       int iovcnt, const struct sockaddr *dst, socklen_t dstlen,
                       int flags)
{
	const struct udpc_config *cfg = udpc_shim_config();
	struct sockaddr_storage dstbuf;
	const struct sockaddr *target;
	size_t paylen;
	ssize_t rc;
	int err = 0;

	/* SEC-01: if the shim cannot proxy, the call fails.  It never falls
	 * through to sending the datagram directly. */
	if (cfg == NULL) {
		errno = udpc_shim_failure_errno();
		return -1;
	}

	if (iovcnt < 0 || iovcnt > IOV_MAX) {
		errno = EMSGSIZE;
		return -1;
	}
	/* L2: what the kernel says, rather than a crash in iov_total. */
	if (iovcnt > 0 && iov == NULL) {
		errno = EFAULT;
		return -1;
	}

	/* D-36: MSG_MORE asks the kernel to join this call to the next into one
	 * datagram.  Each call carries its own SOCKS header, so the joined
	 * datagram would arrive with a header in its middle. */
	if (flags & MSG_MORE) {
		errno = udpc_dgram_refuse_cork();
		return -1;
	}

	/* Destination: the explicit one if given, else the one recorded by
	 * connect() (FR-F-08).  An explicit one is checked against its length
	 * as the kernel would (L1): too short is EINVAL, never a read past the
	 * caller's buffer. */
	if (dst != NULL && dstlen > 0) {
		if (udpc_sa_copy(dst, dstlen, &dstbuf) != 0)
			return -1;
		target = (const struct sockaddr *)&dstbuf;
	} else if (atomic_load_explicit(&e->connected, memory_order_acquire)) {
		memcpy(&dstbuf, &e->app_dst, sizeof(dstbuf));
		target = (const struct sockaddr *)&dstbuf;
	} else {
		errno = EDESTADDRREQ;
		return -1;
	}

	if (udpc_sa_len(target) == 0) {
		errno = EAFNOSUPPORT;
		return -1;
	}

	err = udpc_dgram_unrepresentable(target);
	if (err != 0) {
		errno = err;
		return -1;
	}

	paylen = iov_total(iov, iovcnt);

	/* FR-F-07 / D-12: the limit is configured, since SOCKS5 offers no way
	 * to learn it.  Exceeding it is EMSGSIZE, never a silent drop. */
	if (paylen > cfg->max_datagram) {
		udpc_debug("payload %zu exceeds configured max_datagram %zu", paylen,
		           cfg->max_datagram);
		errno = EMSGSIZE;
		return -1;
	}

	/* send_once checks an idle association before using it (FR-P-08),
	 * rather than discovering it from a failure after the datagram has
	 * already gone to a relay port that no longer exists. */
	rc = send_once(fd, e, cfg, iov, iovcnt, target, flags, paylen, &err);
	if (rc >= 0)
		return rc;

	/* FR-P-08: the proxy expires idle associations.  Re-associate once,
	 * transparently, and retry -- the application should see a successful
	 * send, not an error it has to handle.  send_once has already detached
	 * the dead association. */
	if (udpc_dgram_assoc_dead(err)) {
		udpc_debug("fd %d: association appears expired (%s); "
		           "re-associating",
		           fd, strerror(err));
		rc = send_once(fd, e, cfg, iov, iovcnt, target, flags, paylen, &err);
		if (rc >= 0)
			return rc;
	}

	/* SEC-01 again: a second failure fails the call. */
	errno = err;
	return -1;
}

ssize_t udpc_core_recv(int fd, struct udpc_fdent *e, const struct iovec *iov,
                       int iovcnt, struct sockaddr *src, socklen_t *srclen,
                       int flags, int *out_msgflags)
{
	const struct udpc_config *cfg = udpc_shim_config();
	struct udpc_assoc *a;
	struct udpc_tls *tls;
	struct udpc_socks_hdr hdr;
	struct iovec sciov;
	struct msghdr msg;
	size_t capacity;
	int err = 0;
	int attempts = 0;

	if (cfg == NULL) {
		errno = udpc_shim_failure_errno();
		return -1;
	}
	if (iovcnt < 0 || iovcnt > IOV_MAX) {
		errno = EMSGSIZE;
		return -1;
	}
	if (iovcnt > 0 && iov == NULL) {
		errno = EFAULT;
		return -1;
	}

	/* A receive is a use of the socket, so it establishes the association
	 * if there is not one yet (FR-P-01): without a relay there is nothing
	 * to receive from.  The reference is held for the whole receive, which
	 * may block for as long as the application's socket does (D-24). */
	a = udpc_assoc_hold(fd, e, cfg, false, &err);
	if (a == NULL) {
		errno = err;
		return -1;
	}

	tls = udpc_tls_get(udpc_dgram_scratch_need(cfg));
	if (tls == NULL) {
		udpc_assoc_unref(a);
		errno = ENOMEM;
		return -1;
	}

	capacity = iov_total(iov, iovcnt);

	for (;;) {
		const struct sockaddr_storage *peer;
		struct sockaddr_storage shown;
		socklen_t shownlen;
		ssize_t n, hlen;
		size_t paylen, copied;

		sciov.iov_base = tls->buf;
		sciov.iov_len = tls->buflen;

		memset(&msg, 0, sizeof(msg));
		msg.msg_iov = &sciov;
		msg.msg_iovlen = 1;

		/* MSG_TRUNC is added so the kernel reports the datagram's true
		 * length even when it does not fit in scratch, which is how an
		 * oversized datagram is detected rather than silently clipped. */
		n = REAL_RECVMSG(fd, &msg, flags | MSG_TRUNC);
		if (n < 0) {
			/* FR-P-08: an expired association shows up here as a
			 * pending ICMP error on the connected socket. */
			if (udpc_dgram_assoc_dead(errno) && attempts == 0) {
				attempts++;
				udpc_debug("fd %d: association appears expired on "
				           "receive; re-associating",
				           fd);
				udpc_assoc_drop(e, a);
				udpc_assoc_unref(a);
				a = udpc_assoc_hold(fd, e, cfg, false, &err);
				if (a == NULL) {
					errno = err;
					return -1;
				}
				continue;
			}
			err = errno;
			udpc_assoc_unref(a);
			errno = err;
			return -1;
		}

		peer = atomic_load_explicit(&e->connected, memory_order_acquire)
		               ? &e->app_dst
		               : NULL;
		hlen = udpc_dgram_unwrap(tls->buf, n, tls->buflen, cfg, &a->chain,
		                         atomic_load_explicit(&e->family,
		                                              memory_order_relaxed),
		                         peer, &hdr);
		if (hlen < 0) {
			/* The application must never observe this datagram.  If
			 * we were only peeking, it is still queued, so consume
			 * it for real before looping -- otherwise the next
			 * receive would return the same garbage forever. */
			if (flags & MSG_PEEK) {
				sciov.iov_base = tls->buf;
				sciov.iov_len = tls->buflen;
				memset(&msg, 0, sizeof(msg));
				msg.msg_iov = &sciov;
				msg.msg_iovlen = 1;
				(void)REAL_RECVMSG(fd, &msg,
				                   (flags & ~MSG_PEEK) | MSG_TRUNC);
			}
			continue;
		}

		paylen = (size_t)n - (size_t)hlen;

		/* FR-F-03 / FR-F-06: exactly one application datagram, and a
		 * zero-length payload round-trips as zero -- distinct from "no
		 * datagram", which blocks or reports EAGAIN. */
		copied = copy_to_iov(tls->buf + hlen, paylen, iov, iovcnt);

		/* FR-F-02: the source is the true origin from the reply header,
		 * never the relay. */
		if (src != NULL && srclen != NULL && *srclen > 0) {
			shownlen = udpc_dgram_source(
				&hdr,
				atomic_load_explicit(&e->family, memory_order_relaxed),
				peer, &shown);
			memcpy(src, &shown, *srclen < shownlen ? *srclen : shownlen);
			*srclen = shownlen;
		}

		/* FR-F-04: when the application's buffers are shorter than the
		 * payload, the excess is discarded and MSG_TRUNC is reported,
		 * matching the kernel. */
		if (out_msgflags != NULL) {
			*out_msgflags = 0;
			if (paylen > capacity)
				*out_msgflags |= MSG_TRUNC;
		}

		udpc_assoc_mark_used(a);
		udpc_assoc_unref(a);

		/* recvmsg called WITH MSG_TRUNC returns the true payload
		 * length; without it, the amount actually delivered. */
		if (flags & MSG_TRUNC)
			return (ssize_t)paylen;
		return (ssize_t)copied;
	}
}

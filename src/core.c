#include "core.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "addr.h"
#include "assoc.h"
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
	return udpc_fd_lookup(fd);
}

static size_t iov_total(const struct iovec *iov, int iovcnt)
{
	size_t total = 0;
	int i;

	for (i = 0; i < iovcnt; i++)
		total += iov[i].iov_len;
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

/* D-05 R1: SOCKS5 cannot express multicast or broadcast, so these fail --
 * with a specific reason rather than a generic error the user has to guess at.
 * There is no bypass in v1 (D-05), so failing is the only honest outcome. */
static int reject_unrepresentable(const struct sockaddr *dst)
{
	char abuf[UDPC_ADDRSTRLEN];

	if (udpc_addr_is_multicast(dst)) {
		udpc_warn("cannot send to multicast %s: SOCKS5 has no way to "
		          "express a multicast destination, and udpchains does "
		          "not send anything directly",
		          udpc_addr_str(dst, abuf, sizeof(abuf)));
		errno = ENETUNREACH;
		return -1;
	}
	if (udpc_addr_is_broadcast(dst)) {
		udpc_warn("cannot send to broadcast %s: SOCKS5 has no way to "
		          "express a broadcast destination, and udpchains does "
		          "not send anything directly",
		          udpc_addr_str(dst, abuf, sizeof(abuf)));
		errno = ENETUNREACH;
		return -1;
	}
	return 0;
}

/* A connected UDP socket only receives from its connected peer -- the kernel
 * drops everything else before the application ever sees it.  Under the shim
 * every datagram arrives from the relay, so that filter can never fire on its
 * own and has to be reimplemented against the true origin in the SOCKS header.
 *
 * Without this the shim is MORE permissive than an unhooked socket, which is
 * the wrong direction for §3's "indistinguishable" mandate: a program that uses
 * connect() as a source filter would silently lose it.
 *
 * Both addresses are normalised to the socket's family before comparing.  An
 * AF_INET6 socket connected to ::ffff:a.b.c.d whose proxy reports the origin as
 * plain IPv4 is the same peer, and comparing the raw forms would reject every
 * datagram -- the same v4-mapped trap as D-14, in the other direction. */
static bool from_unconnected_peer(const struct udpc_fdent *e,
                                  const struct udpc_socks_hdr *hdr)
{
	struct sockaddr_storage got, want;
	int fam;

	if (!atomic_load_explicit(&e->connected, memory_order_acquire))
		return false;

	/* A domain-form reply carries no address to compare.  Delivering it is
	 * the lesser evil: the alternative is resolving a name on the receive
	 * path, which would both leak a lookup and be a lie. */
	if (!hdr->addr_valid)
		return false;

	fam = atomic_load_explicit(&e->family, memory_order_relaxed);

	if (udpc_addr_for_family((const struct sockaddr *)&hdr->addr, fam, &got) != 0)
		got = hdr->addr;
	if (udpc_addr_for_family((const struct sockaddr *)&e->app_dst, fam, &want) != 0)
		want = e->app_dst;

	return !udpc_addr_equal((const struct sockaddr *)&got,
	                        (const struct sockaddr *)&want);
}

/* True for the errors that mean "this association is gone", which is what an
 * expired idle association looks like from here: the relay port stops
 * existing, so a connected UDP socket reports the resulting ICMP error. */
static bool association_looks_dead(int e)
{
	return e == ECONNREFUSED || e == ENOTCONN || e == EPIPE ||
	       e == ECONNRESET || e == EHOSTUNREACH;
}

static ssize_t send_once(int fd, struct udpc_fdent *e,
                         const struct udpc_config *cfg, const struct iovec *iov,
                         int iovcnt, const struct sockaddr *dst, int flags,
                         size_t paylen, int *out_errno)
{
	struct udpc_tls *tls;
	struct sockaddr_storage relay;
	struct msghdr msg;
	ssize_t hlen, n;
	int i;

	if (udpc_assoc_ensure(fd, e, cfg, out_errno) != 0)
		return -1;
	if (!udpc_assoc_relay(e, &relay)) {
		*out_errno = ENETUNREACH;
		return -1;
	}

	tls = udpc_tls_get(cfg->max_datagram + UDPC_SOCKS_HDR_MAX);
	if (tls == NULL) {
		*out_errno = ENOMEM;
		return -1;
	}

	hlen = udpc_socks_encode(tls->hdr, sizeof(tls->hdr), dst);
	if (hlen < 0) {
		*out_errno = errno;
		return -1;
	}

	/* D-11: the header is the first iovec entry and the application's own
	 * buffers follow.  The payload is never copied. */
	tls->iov[0].iov_base = tls->hdr;
	tls->iov[0].iov_len = (size_t)hlen;
	for (i = 0; i < iovcnt; i++)
		tls->iov[i + 1] = iov[i];

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &relay;
	msg.msg_namelen = udpc_sa_len((const struct sockaddr *)&relay);
	msg.msg_iov = tls->iov;
	msg.msg_iovlen = (size_t)iovcnt + 1;

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
		           udpc_addr_str(dst, dbuf, sizeof(dbuf)), tls->hdr[3],
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

	/* Destination: the explicit one if given, else the one recorded by
	 * connect() (FR-F-08). */
	if (dst != NULL && dstlen > 0 && udpc_sa_len(dst) != 0) {
		target = dst;
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

	if (reject_unrepresentable(target) != 0)
		return -1;

	paylen = iov_total(iov, iovcnt);

	/* FR-F-07 / D-12: the limit is configured, since SOCKS5 offers no way
	 * to learn it.  Exceeding it is EMSGSIZE, never a silent drop. */
	if (paylen > cfg->max_datagram) {
		udpc_debug("payload %zu exceeds configured max_datagram %zu", paylen,
		           cfg->max_datagram);
		errno = EMSGSIZE;
		return -1;
	}

	/* FR-P-08: check up front whether an idle association has been expired,
	 * rather than discovering it from a failure after the datagram has
	 * already gone to a relay port that no longer exists. */
	udpc_assoc_revalidate(e);

	rc = send_once(fd, e, cfg, iov, iovcnt, target, flags, paylen, &err);
	if (rc >= 0) {
		udpc_assoc_touch(e);
		return rc;
	}

	/* FR-P-08: the proxy expires idle associations.  Re-associate once,
	 * transparently, and retry -- the application should see a successful
	 * send, not an error it has to handle. */
	if (association_looks_dead(err)) {
		udpc_debug("fd %d: association appears expired (%s); "
		           "re-associating",
		           fd, strerror(err));
		udpc_assoc_invalidate(e);
		rc = send_once(fd, e, cfg, iov, iovcnt, target, flags, paylen, &err);
		if (rc >= 0) {
			udpc_assoc_touch(e);
			return rc;
		}
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

	/* A receive is a use of the socket, so it establishes the association
	 * if there is not one yet (FR-P-01): without a relay there is nothing
	 * to receive from. */
	if (udpc_assoc_ensure(fd, e, cfg, &err) != 0) {
		errno = err;
		return -1;
	}

	tls = udpc_tls_get(cfg->max_datagram + UDPC_SOCKS_HDR_MAX);
	if (tls == NULL) {
		errno = ENOMEM;
		return -1;
	}

	capacity = iov_total(iov, iovcnt);

	for (;;) {
		ssize_t n, hlen;
		size_t paylen, copied;
		bool discard = false;

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
			if (association_looks_dead(errno) && attempts == 0) {
				attempts++;
				udpc_debug("fd %d: association appears expired on "
				           "receive; re-associating",
				           fd);
				udpc_assoc_invalidate(e);
				if (udpc_assoc_ensure(fd, e, cfg, &err) != 0) {
					errno = err;
					return -1;
				}
				continue;
			}
			return -1;
		}

		if ((size_t)n > tls->buflen) {
			udpc_warn("dropping a %zd-byte relayed datagram: larger "
			          "than max_datagram %zu plus header",
			          n, cfg->max_datagram);
			discard = true;
		} else {
			hlen = udpc_socks_decode(tls->buf, (size_t)n, &hdr);
			if (hlen < 0) {
				udpc_debug("dropping a malformed relayed datagram "
				           "(%zd bytes)",
				           n);
				discard = true;
			} else if (hdr.frag != 0) {
				/* FR-P-04: a fragmented datagram is discarded.
				 * The application never sees it. */
				udpc_debug("dropping a relayed datagram with "
				           "FRAG=%u",
				           hdr.frag);
				discard = true;
			} else if (from_unconnected_peer(e, &hdr)) {
				char sbuf[UDPC_ADDRSTRLEN];

				udpc_debug("dropping a relayed datagram from %s: "
				           "the socket is connected to a different "
				           "peer, and the kernel would drop it too",
				           udpc_addr_str((const struct sockaddr *)
				                                 &hdr.addr,
				                         sbuf, sizeof(sbuf)));
				discard = true;
			}
		}

		if (discard) {
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

		hlen = udpc_socks_decode(tls->buf, (size_t)n, &hdr);
		paylen = (size_t)n - (size_t)hlen;

		/* FR-F-03 / FR-F-06: exactly one application datagram, and a
		 * zero-length payload round-trips as zero -- distinct from "no
		 * datagram", which blocks or reports EAGAIN. */
		copied = copy_to_iov(tls->buf + hlen, paylen, iov, iovcnt);

		/* FR-F-02: the source is the true origin from the reply header,
		 * never the relay. */
		if (src != NULL && srclen != NULL && *srclen > 0) {
			if (hdr.addr_valid) {
				/* Report it in the SOCKET's family, as the kernel
				 * would.  An AF_INET6 dual-stack socket that
				 * received from an IPv4 peer must be told
				 * ::ffff:a.b.c.d, not an AF_INET sockaddr the
				 * application has nowhere to put. */
				struct sockaddr_storage shown;
				socklen_t want, give;

				if (udpc_addr_for_family(
					    (const struct sockaddr *)&hdr.addr,
					    atomic_load_explicit(&e->family,
					                         memory_order_relaxed),
					    &shown) != 0)
					shown = hdr.addr;

				want = udpc_sa_len((const struct sockaddr *)&shown);
				give = (*srclen < want) ? *srclen : want;
				memcpy(src, &shown, give);
				*srclen = want;
			} else if (atomic_load_explicit(&e->connected,
			                                memory_order_acquire)) {
				/* A domain-form reply cannot become a sockaddr
				 * without a lookup that would both leak and
				 * lie.  The peer the application addressed is
				 * the honest answer. */
				socklen_t want = udpc_sa_len(
					(const struct sockaddr *)&e->app_dst);
				socklen_t give = (*srclen < want) ? *srclen : want;
				memcpy(src, &e->app_dst, give);
				*srclen = want;
			} else {
				*srclen = 0;
			}
		}

		/* FR-F-04: when the application's buffers are shorter than the
		 * payload, the excess is discarded and MSG_TRUNC is reported,
		 * matching the kernel. */
		if (out_msgflags != NULL) {
			*out_msgflags = 0;
			if (paylen > capacity)
				*out_msgflags |= MSG_TRUNC;
		}

		udpc_assoc_touch(e);

		/* recvmsg called WITH MSG_TRUNC returns the true payload
		 * length; without it, the amount actually delivered. */
		if (flags & MSG_TRUNC)
			return (ssize_t)paylen;
		return (ssize_t)copied;
	}
}

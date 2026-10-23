#include "dgram.h"

#include <errno.h>
#include <netinet/udp.h>
#include <string.h>

#include "addr.h"
#include "log.h"

/* D-05 R1: SOCKS5 cannot express multicast or broadcast, so these fail --
 * with a specific reason rather than a generic error the user has to guess at.
 * There is no bypass in v1 (D-05), so failing is the only honest outcome. */
/* D-33: these fire per datagram, so a program retrying a multicast send in a
 * loop -- or a remote peer sending oversized replies -- would otherwise fill
 * stderr.  One report per second, with a count of the rest. */
static struct udpc_ratelimit g_rl_multicast, g_rl_broadcast, g_rl_oversize,
	g_rl_cork, g_rl_gso;

int udpc_dgram_unrepresentable(const struct sockaddr *dst)
{
	char abuf[UDPC_ADDRSTRLEN], note[80];
	unsigned n;

	if (udpc_addr_is_multicast(dst)) {
		if ((n = udpc_ratelimit(&g_rl_multicast)) != 0)
			udpc_warn("cannot send to multicast %s: SOCKS5 has no way "
			          "to express a multicast destination, and "
			          "udpchains does not send anything directly%s",
			          udpc_addr_str(dst, abuf, sizeof(abuf)),
			          udpc_ratelimit_note(n, note, sizeof(note)));
		return ENETUNREACH;
	}
	if (udpc_addr_is_broadcast(dst)) {
		if ((n = udpc_ratelimit(&g_rl_broadcast)) != 0)
			udpc_warn("cannot send to broadcast %s: SOCKS5 has no way "
			          "to express a broadcast destination, and "
			          "udpchains does not send anything directly%s",
			          udpc_addr_str(dst, abuf, sizeof(abuf)),
			          udpc_ratelimit_note(n, note, sizeof(note)));
		return ENETUNREACH;
	}
	return 0;
}

int udpc_dgram_refuse_cork(void)
{
	char note[80];
	unsigned n = udpc_ratelimit(&g_rl_cork);

	if (n != 0)
		udpc_warn("refusing MSG_MORE: each send carries its own SOCKS "
		          "header, so sends cannot be joined into one "
		          "datagram%s",
		          udpc_ratelimit_note(n, note, sizeof(note)));
	return EOPNOTSUPP;
}

/* D-36: a UDP_SEGMENT control message asks the kernel to split one buffer into
 * many datagrams (GSO).  Each would need its own SOCKS header, and the kernel
 * cannot add them, so the request is refused rather than sent as one garbled
 * datagram.  Other ancillary data on send is ignored (FR-F-11). */
bool udpc_dgram_wants_gso(int fd, const struct msghdr *m)
{
	struct cmsghdr *c;
	char note[80];
	unsigned n;

	if (m->msg_control == NULL || m->msg_controllen < sizeof(struct cmsghdr))
		return false;
	for (c = CMSG_FIRSTHDR(m); c != NULL;
	     c = CMSG_NXTHDR((struct msghdr *)(uintptr_t)m, c))
		if (c->cmsg_level == SOL_UDP && c->cmsg_type == UDP_SEGMENT)
			break;
	if (c == NULL)
		return false;
	if ((n = udpc_ratelimit(&g_rl_gso)) != 0)
		udpc_warn("refusing UDP_SEGMENT on descriptor %d: each datagram "
		          "needs its own SOCKS header, which the kernel cannot "
		          "add%s",
		          fd, udpc_ratelimit_note(n, note, sizeof(note)));
	return true;
}

/* An expired idle association: the relay port stops existing, so a connected
 * UDP socket reports the resulting ICMP error. */
bool udpc_dgram_assoc_dead(int e)
{
	return e == ECONNREFUSED || e == ENOTCONN || e == EPIPE ||
	       e == ECONNRESET || e == EHOSTUNREACH;
}

size_t udpc_dgram_scratch_need(const struct udpc_config *cfg)
{
	return cfg->max_datagram + (size_t)(cfg->nextra + 1) * UDPC_SOCKS_HDR_MAX;
}

/* D-05 R2: a loopback destination is resolved at the PROXY, so with a remote
 * proxy the datagram reaches the proxy host's loopback rather than this host's.
 * Silent misrouting is the same class of defect the project exists to remove,
 * so it is called out -- and can be promoted to a hard error.
 *
 * D-40: it is the EXIT hop that resolves it.  Only a chain of one can have its
 * exit on this host; a longer chain's exit is reached through other hops, so a
 * loopback destination there is always the far end's. */
int udpc_dgram_loopback_guard(const struct udpc_config *cfg, const struct sockaddr *dst,
                              int *out_errno)
{
	char abuf[UDPC_ADDRSTRLEN];

	if (cfg->nextra == 0 && cfg->proxy_is_local)
		return 0;
	if (dst == NULL || !udpc_addr_is_loopback(dst))
		return 0;

	if (cfg->strict_loopback) {
		if (cfg->nextra > 0)
			udpc_err("refusing loopback destination %s: it would be "
			         "resolved at the chain's last hop, not here "
			         "(strict_loopback is on)",
			         udpc_addr_str(dst, abuf, sizeof(abuf)));
		else
			udpc_err("refusing loopback destination %s: the proxy is not on "
			         "this host, so it would be resolved at the proxy "
			         "(strict_loopback is on)",
			         udpc_addr_str(dst, abuf, sizeof(abuf)));
		*out_errno = ENETUNREACH;
		return -1;
	}

	if (cfg->nextra > 0)
		udpc_warn("destination %s is loopback; it will be resolved at the "
		          "chain's last hop, not here",
		          udpc_addr_str(dst, abuf, sizeof(abuf)));
	else
		udpc_warn("destination %s is loopback but the proxy is not on this "
		          "host; it will be resolved at the proxy, not here",
		          udpc_addr_str(dst, abuf, sizeof(abuf)));
	return 0;
}

/* A connected UDP socket only receives from its connected peer -- the kernel
 * drops everything else before the application ever sees it.  Proxied, every
 * datagram arrives from the relay, so that filter can never fire on its own
 * and has to be reimplemented against the true origin in the SOCKS header.
 *
 * Without this the proxied socket is MORE permissive than an unhooked one,
 * which is the wrong direction for §3's "indistinguishable" mandate: a program
 * that uses connect() as a source filter would silently lose it.
 *
 * Both addresses are normalised to the socket's family before comparing.  An
 * AF_INET6 socket connected to ::ffff:a.b.c.d whose proxy reports the origin as
 * plain IPv4 is the same peer, and comparing the raw forms would reject every
 * datagram -- the same v4-mapped trap as D-14, in the other direction. */
static bool from_other_peer(const struct sockaddr_storage *peer, int family,
                            const struct udpc_socks_hdr *hdr)
{
	struct sockaddr_storage got, want;

	if (peer == NULL)
		return false;

	/* A domain-form reply carries no address to compare.  Delivering it is
	 * the lesser evil: the alternative is resolving a name on the receive
	 * path, which would both leak a lookup and be a lie. */
	if (!hdr->addr_valid)
		return false;

	if (udpc_addr_for_family((const struct sockaddr *)&hdr->addr, family, &got) != 0)
		got = hdr->addr;
	if (udpc_addr_for_family((const struct sockaddr *)peer, family, &want) != 0)
		want = *peer;

	return !udpc_addr_equal((const struct sockaddr *)&got,
	                        (const struct sockaddr *)&want);
}

ssize_t udpc_dgram_unwrap(const uint8_t *buf, ssize_t n, size_t buflen,
                          const struct udpc_config *cfg,
                          const struct udpc_socks_chain *ch, int family,
                          const struct sockaddr_storage *peer,
                          struct udpc_socks_hdr *hdr)
{
	enum udpc_socks_drop why;
	unsigned layer;
	ssize_t hlen;

	if ((size_t)n > buflen) {
		char note[80];
		unsigned k = udpc_ratelimit(&g_rl_oversize);

		if (k != 0)
			udpc_warn("dropping a %zd-byte relayed datagram: "
			          "larger than max_datagram %zu plus header%s",
			          n, cfg->max_datagram,
			          udpc_ratelimit_note(k, note, sizeof(note)));
		return -1;
	}

	/* D-41: every layer of a chain is checked before any of the datagram
	 * is delivered, and failing any one drops the whole of it.  A chain of
	 * one has one layer, which is checked just as before. */
	hlen = udpc_socks_decode_chain(buf, (size_t)n, ch, hdr, &layer, &why);
	if (hlen < 0 && layer < ch->n) {
		if (why == UDPC_DROP_SOURCE)
			udpc_debug("dropping a relayed datagram: its layer %u of %u "
			           "is not from hop %u's relay",
			           layer, ch->n, layer + 1);
		else
			udpc_debug("dropping a relayed datagram: its layer %u of %u %s",
			           layer, ch->n,
			           why == UDPC_DROP_FRAG ? "has FRAG set" : "is malformed");
		return -1;
	}
	if (hlen < 0) {
		udpc_debug("dropping a malformed relayed datagram (%zd bytes)", n);
		return -1;
	}
	if (hdr->frag != 0) {
		/* FR-P-04: a fragmented datagram is discarded.  The application
		 * never sees it. */
		udpc_debug("dropping a relayed datagram with FRAG=%u", hdr->frag);
		return -1;
	}
	if (from_other_peer(peer, family, hdr)) {
		char sbuf[UDPC_ADDRSTRLEN];

		udpc_debug("dropping a relayed datagram from %s: the socket is "
		           "connected to a different peer, and the kernel would "
		           "drop it too",
		           udpc_addr_str((const struct sockaddr *)&hdr->addr, sbuf,
		                         sizeof(sbuf)));
		return -1;
	}
	return hlen;
}

socklen_t udpc_dgram_source(const struct udpc_socks_hdr *hdr, int family,
                            const struct sockaddr_storage *peer,
                            struct sockaddr_storage *out)
{
	if (hdr->addr_valid) {
		/* Report it in the SOCKET's family, as the kernel would.  An
		 * AF_INET6 dual-stack socket that received from an IPv4 peer
		 * must be told ::ffff:a.b.c.d, not an AF_INET sockaddr the
		 * application has nowhere to put. */
		if (udpc_addr_for_family((const struct sockaddr *)&hdr->addr, family,
		                         out) != 0)
			*out = hdr->addr;
		return udpc_sa_len((const struct sockaddr *)out);
	}
	if (peer != NULL) {
		/* A domain-form reply cannot become a sockaddr without a lookup
		 * that would both leak and lie.  The peer the application
		 * addressed is the honest answer. */
		*out = *peer;
		return udpc_sa_len((const struct sockaddr *)out);
	}
	return 0;
}

/* dns.h -- DNS message codec for the shim's own resolver (D-22).
 *
 * Implemented from RFC 1035 (and RFC 6891 for the EDNS0 OPT record), clean-room
 * per D-01.  Only what the resolver needs: building a single-question query,
 * checking that a response answers it, and extracting addresses, the end of the
 * CNAME chain, and a PTR target.
 *
 * Every byte parsed here arrived through a proxy, from a resolver the shim does
 * not control, so the parser treats its input as hostile.  Every read is bounds
 * checked against the message end.  Name decompression is delegated to libc's
 * dn_expand, which rejects pointer loops and out-of-range pointers.  A CNAME
 * chain is followed by rescanning the message for at most UDPC_DNS_CHAIN_MAX
 * hops, never by recursion.
 */
#ifndef UDPCHAINS_DNS_H
#define UDPCHAINS_DNS_H

#include "compat.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

#define UDPC_DNS_TYPE_A 1
#define UDPC_DNS_TYPE_CNAME 5
#define UDPC_DNS_TYPE_PTR 12
#define UDPC_DNS_TYPE_AAAA 28
#define UDPC_DNS_TYPE_OPT 41
#define UDPC_DNS_CLASS_IN 1

#define UDPC_DNS_RCODE_NOERROR 0
#define UDPC_DNS_RCODE_SERVFAIL 2
#define UDPC_DNS_RCODE_NXDOMAIN 3

#define UDPC_DNS_HDR_LEN 12
/* The EDNS0 UDP payload size offered.  1232 is the DNS Flag Day 2020 value: it
 * fits an IPv6 minimum-MTU packet with headroom, which also keeps the reply
 * well inside a proxy's datagram limit. */
#define UDPC_DNS_EDNS_SIZE 1232
/* Presentation form: 253 characters, a possible trailing dot, and the NUL. */
#define UDPC_DNS_NAME_MAX 256
/* Longest possible single-question query: header, name, type, class, OPT. */
#define UDPC_DNS_QUERY_MAX (UDPC_DNS_HDR_LEN + 255 + 4 + 11)
/* Addresses kept from one answer.  glibc has no fixed limit; this one is far
 * above any realistic round-robin set, and anything past it is dropped rather
 * than growing the allocation without bound on data from the network. */
#define UDPC_DNS_MAX_ADDRS 256
#define UDPC_DNS_CHAIN_MAX 16

/* An address from an answer, family-tagged; port-less. */
struct udpc_dns_addr {
	int family; /* AF_INET or AF_INET6 */
	uint8_t bytes[16];
};

struct udpc_dns_result {
	int rcode;
	bool truncated;  /* TC set: the answer is incomplete and must not be used */
	size_t ancount;  /* answer records present, of any type */
	size_t naddr;
	struct udpc_dns_addr addr[UDPC_DNS_MAX_ADDRS];
	char canon[UDPC_DNS_NAME_MAX]; /* end of the CNAME chain */
	bool have_ptr;
	char ptr[UDPC_DNS_NAME_MAX];   /* PTR target, for a PTR query */
};

/* Builds a query for (name, qclass, qtype) with recursion desired, and an EDNS0
 * OPT record when edns_size is non-zero.  Returns the length, or -1 with errno:
 * EINVAL for a name that is empty, over-long, has an empty or over-long label,
 * or contains a byte that cannot appear in a hostname; ENOBUFS if buf is too
 * small. */
ssize_t udpc_dns_build_query(uint8_t *buf, size_t buflen, uint16_t id,
                             const char *name, uint16_t qclass, uint16_t qtype,
                             uint16_t edns_size);

/* True if resp answers query: same ID, the QR bit set, the query's opcode, and a
 * question section naming the same name (case-insensitively), type and class.
 * This is how a reply is matched to its query, so it is deliberately strict:
 * anything else arriving on the socket is someone else's, or forged. */
bool udpc_dns_answers(const uint8_t *query, size_t qlen, const uint8_t *resp,
                      size_t rlen);

/* Parses a response already known to answer a (name, qtype) query.  Fills out
 * and returns 0, or returns -1 if the message is malformed.  When the response
 * is truncated, only rcode and truncated are meaningful. */
int udpc_dns_parse(const uint8_t *resp, size_t rlen, const char *name,
                   uint16_t qtype, struct udpc_dns_result *out);

/* Writes the reverse-lookup name for an address: "4.3.2.1.in-addr.arpa", or
 * the nibble form under ip6.arpa.  A v4-mapped IPv6 address uses the IPv4 form.
 * Returns 0, or -1 for an unsupported family or a short buffer. */
int udpc_dns_ptr_name(const struct sockaddr *sa, char *out, size_t outlen);

/* Big-endian 16-bit read and write, bounds-checked by the caller. */
static inline uint16_t udpc_dns_get16(const uint8_t *p)
{
	return (uint16_t)((p[0] << 8) | p[1]);
}

static inline void udpc_dns_put16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)(v & 0xff);
}

#endif /* UDPCHAINS_DNS_H */

#include "dns.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

/* Header flag bits, in the third and fourth bytes. */
#define DNS_QR 0x80     /* byte 2: this is a response */
#define DNS_OPCODE 0x78 /* byte 2 */
#define DNS_TC 0x02     /* byte 2: truncated */
#define DNS_RD 0x01     /* byte 2: recursion desired */
#define DNS_RCODE 0x0f  /* byte 3 */

/* Encodes a presentation-form name as length-prefixed labels.
 *
 * Stricter than DNS itself, which allows any byte in a label: a hostname never
 * needs whitespace, control bytes, a backslash or bytes above 0x7e, and
 * accepting them would mean inventing an escape syntax for this one caller.
 * Non-ASCII names are refused before they get here (D-22, AI_IDN). */
static int encode_name(uint8_t *p, size_t room, const char *name, size_t *outlen)
{
	size_t len = strlen(name), start = 0, n = 0, i;

	if (len > 0 && name[len - 1] == '.')
		len--;
	if (len == 0 || len > 253) {
		errno = EINVAL;
		return -1;
	}
	for (i = 0; i < len; i++) {
		unsigned char c = (unsigned char)name[i];
		if (c <= 0x20 || c >= 0x7f || c == '\\') {
			errno = EINVAL;
			return -1;
		}
	}

	for (;;) {
		size_t end = start, l;

		while (end < len && name[end] != '.')
			end++;
		l = end - start;
		if (l == 0 || l > 63) {
			errno = EINVAL;
			return -1;
		}
		if (n + 1 + l > room) {
			errno = ENOBUFS;
			return -1;
		}
		p[n++] = (uint8_t)l;
		memcpy(p + n, name + start, l);
		n += l;
		if (end == len)
			break;
		start = end + 1;
	}

	if (n + 1 > room) {
		errno = ENOBUFS;
		return -1;
	}
	p[n++] = 0;
	*outlen = n;
	return 0;
}

ssize_t udpc_dns_build_query(uint8_t *buf, size_t buflen, uint16_t id,
                             const char *name, uint16_t qclass, uint16_t qtype,
                             uint16_t edns_size)
{
	size_t nlen, off;

	if (buf == NULL || name == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (buflen < UDPC_DNS_HDR_LEN) {
		errno = ENOBUFS;
		return -1;
	}

	memset(buf, 0, UDPC_DNS_HDR_LEN);
	udpc_dns_put16(buf, id);
	buf[2] = DNS_RD;
	udpc_dns_put16(buf + 4, 1);                      /* QDCOUNT */
	udpc_dns_put16(buf + 10, edns_size != 0 ? 1 : 0); /* ARCOUNT */

	if (encode_name(buf + UDPC_DNS_HDR_LEN, buflen - UDPC_DNS_HDR_LEN, name,
	                &nlen) != 0)
		return -1;
	off = UDPC_DNS_HDR_LEN + nlen;

	if (off + 4 > buflen) {
		errno = ENOBUFS;
		return -1;
	}
	udpc_dns_put16(buf + off, qtype);
	udpc_dns_put16(buf + off + 2, qclass);
	off += 4;

	if (edns_size != 0) {
		/* RFC 6891 OPT pseudo-record: root owner, type OPT, the class field
		 * carrying the UDP payload size, a zero extended RCODE/version/
		 * flags word, and no options. */
		if (off + 11 > buflen) {
			errno = ENOBUFS;
			return -1;
		}
		buf[off] = 0;
		udpc_dns_put16(buf + off + 1, UDPC_DNS_TYPE_OPT);
		udpc_dns_put16(buf + off + 3, edns_size);
		memset(buf + off + 5, 0, 6); /* TTL (4) and RDLENGTH (2) */
		off += 11;
	}
	return (ssize_t)off;
}

/* Expands the single question's name and returns the offset just past it, or
 * -1.  The type and class that follow are checked to be present. */
static long question_end(const uint8_t *msg, size_t len, char *name, size_t namelen)
{
	int n;

	if (len < UDPC_DNS_HDR_LEN || udpc_dns_get16(msg + 4) != 1)
		return -1;
	n = dn_expand(msg, msg + len, msg + UDPC_DNS_HDR_LEN, name, (int)namelen);
	if (n < 0 || (size_t)UDPC_DNS_HDR_LEN + (size_t)n + 4 > len)
		return -1;
	return UDPC_DNS_HDR_LEN + n;
}

bool udpc_dns_answers(const uint8_t *query, size_t qlen, const uint8_t *resp,
                      size_t rlen)
{
	char qname[UDPC_DNS_NAME_MAX], rname[UDPC_DNS_NAME_MAX];
	long qend, rend;

	if (query == NULL || resp == NULL || qlen < UDPC_DNS_HDR_LEN ||
	    rlen < UDPC_DNS_HDR_LEN)
		return false;
	if (memcmp(query, resp, 2) != 0)
		return false; /* ID */
	if (!(resp[2] & DNS_QR))
		return false;
	if ((query[2] ^ resp[2]) & DNS_OPCODE)
		return false;

	qend = question_end(query, qlen, qname, sizeof(qname));
	rend = question_end(resp, rlen, rname, sizeof(rname));
	if (qend < 0 || rend < 0)
		return false;
	if (strcasecmp(qname, rname) != 0)
		return false;
	/* QTYPE and QCLASS. */
	return memcmp(query + qend, resp + rend, 4) == 0;
}

/* One resource record, decoded just far enough to use. */
struct rr {
	char owner[UDPC_DNS_NAME_MAX];
	uint16_t type, rclass, rdlen;
	const uint8_t *rdata;
};

/* Decodes the record at *pp and advances past it.  Returns -1 if the record is
 * malformed or runs past the message end; the parser then rejects the whole
 * message rather than trusting whichever records happened to come first. */
static int next_rr(const uint8_t *msg, const uint8_t *end, const uint8_t **pp,
                   struct rr *rr)
{
	const uint8_t *p = *pp;
	int n;

	n = dn_expand(msg, end, p, rr->owner, (int)sizeof(rr->owner));
	if (n < 0)
		return -1;
	p += n;
	if (end - p < 10)
		return -1;
	rr->type = udpc_dns_get16(p);
	rr->rclass = udpc_dns_get16(p + 2);
	rr->rdlen = udpc_dns_get16(p + 8);
	p += 10;
	if (end - p < rr->rdlen)
		return -1;
	rr->rdata = p;
	*pp = p + rr->rdlen;
	return 0;
}

/* Expands a name held in RDATA, and checks it lies wholly within the record. */
static int rdata_name(const uint8_t *msg, const uint8_t *end, const struct rr *rr,
                      char *out, size_t outlen)
{
	int n = dn_expand(msg, end, rr->rdata, out, (int)outlen);

	return (n < 0 || n > rr->rdlen) ? -1 : 0;
}

int udpc_dns_parse(const uint8_t *resp, size_t rlen, const char *name,
                   uint16_t qtype, struct udpc_dns_result *out)
{
	const uint8_t *end, *p, *answers;
	char want[UDPC_DNS_NAME_MAX];
	unsigned qd, an, i, hop;
	struct rr rr;
	size_t wl;

	memset(out, 0, sizeof(*out));
	if (resp == NULL || name == NULL || rlen < UDPC_DNS_HDR_LEN)
		return -1;

	end = resp + rlen;
	out->rcode = resp[3] & DNS_RCODE;
	out->truncated = (resp[2] & DNS_TC) != 0;
	qd = udpc_dns_get16(resp + 4);
	an = udpc_dns_get16(resp + 6);

	p = resp + UDPC_DNS_HDR_LEN;
	for (i = 0; i < qd; i++) {
		int n = dn_skipname(p, end);
		if (n < 0 || end - (p + n) < 4)
			return -1;
		p += n + 4;
	}
	if (out->truncated)
		return 0;

	/* Validate the whole answer section before using any of it. */
	answers = p;
	for (i = 0; i < an; i++)
		if (next_rr(resp, end, &p, &rr) != 0)
			return -1;
	out->ancount = an;

	/* Follow the CNAME chain from the queried name.  Each hop rescans the
	 * section; the hop limit is what bounds a chain that loops. */
	snprintf(want, sizeof(want), "%s", name);
	wl = strlen(want);
	if (wl > 0 && want[wl - 1] == '.')
		want[wl - 1] = '\0';

	for (hop = 0; hop < UDPC_DNS_CHAIN_MAX; hop++) {
		bool followed = false;

		p = answers;
		for (i = 0; i < an; i++) {
			char target[UDPC_DNS_NAME_MAX];

			(void)next_rr(resp, end, &p, &rr);
			if (rr.type != UDPC_DNS_TYPE_CNAME ||
			    rr.rclass != UDPC_DNS_CLASS_IN ||
			    strcasecmp(rr.owner, want) != 0)
				continue;
			if (rdata_name(resp, end, &rr, target, sizeof(target)) != 0)
				return -1;
			snprintf(want, sizeof(want), "%s", target);
			followed = true;
			break;
		}
		if (!followed)
			break;
	}
	snprintf(out->canon, sizeof(out->canon), "%s", want);

	/* Records of the queried type, owned by the end of the chain. */
	p = answers;
	for (i = 0; i < an; i++) {
		(void)next_rr(resp, end, &p, &rr);
		if (rr.type != qtype || rr.rclass != UDPC_DNS_CLASS_IN ||
		    strcasecmp(rr.owner, want) != 0)
			continue;

		if (qtype == UDPC_DNS_TYPE_A && rr.rdlen == 4 &&
		    out->naddr < UDPC_DNS_MAX_ADDRS) {
			out->addr[out->naddr].family = AF_INET;
			memcpy(out->addr[out->naddr].bytes, rr.rdata, 4);
			out->naddr++;
		} else if (qtype == UDPC_DNS_TYPE_AAAA && rr.rdlen == 16 &&
		           out->naddr < UDPC_DNS_MAX_ADDRS) {
			out->addr[out->naddr].family = AF_INET6;
			memcpy(out->addr[out->naddr].bytes, rr.rdata, 16);
			out->naddr++;
		} else if (qtype == UDPC_DNS_TYPE_PTR && !out->have_ptr) {
			if (rdata_name(resp, end, &rr, out->ptr, sizeof(out->ptr)) != 0)
				return -1;
			out->have_ptr = true;
		}
	}
	return 0;
}

int udpc_dns_ptr_name(const struct sockaddr *sa, char *out, size_t outlen)
{
	const uint8_t *b;
	size_t off = 0;
	int i, n;

	if (sa == NULL || out == NULL)
		return -1;

	if (sa->sa_family == AF_INET) {
		b = (const uint8_t *)&((const struct sockaddr_in *)sa)->sin_addr;
	} else if (sa->sa_family == AF_INET6) {
		const struct in6_addr *a6 = &((const struct sockaddr_in6 *)sa)->sin6_addr;

		if (!IN6_IS_ADDR_V4MAPPED(a6)) {
			for (i = 15; i >= 0; i--) {
				n = snprintf(out + off, outlen - off, "%x.%x.",
				             a6->s6_addr[i] & 0x0f,
				             a6->s6_addr[i] >> 4);
				if (n < 0 || (size_t)n >= outlen - off)
					return -1;
				off += (size_t)n;
			}
			n = snprintf(out + off, outlen - off, "ip6.arpa");
			return (n < 0 || (size_t)n >= outlen - off) ? -1 : 0;
		}
		b = &a6->s6_addr[12];
	} else {
		return -1;
	}

	n = snprintf(out, outlen, "%u.%u.%u.%u.in-addr.arpa", b[3], b[2], b[1],
	             b[0]);
	return (n < 0 || (size_t)n >= outlen) ? -1 : 0;
}

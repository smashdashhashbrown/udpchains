/* test_dns.c -- unit tests for the DNS codec (D-22).
 *
 * Query layouts are asserted against RFC 1035 byte by byte, written out
 * literally rather than computed by the code under test.  The parser gets the
 * hostile inputs a resolver reached through a proxy may send: compression
 * loops, pointers past the end, records longer than the message, CNAME loops,
 * and answers to a question that was not asked.
 */
#include "tap.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <string.h>

#include "dns.h"

/* A response under construction. */
struct resp {
	uint8_t b[2048];
	size_t n;
};

static void r_bytes(struct resp *r, const void *p, size_t n)
{
	memcpy(r->b + r->n, p, n);
	r->n += n;
}

static void r_16(struct resp *r, uint16_t v)
{
	udpc_dns_put16(r->b + r->n, v);
	r->n += 2;
}

/* Header + the question copied from a query, as a server would echo it. */
static void r_start(struct resp *r, const uint8_t *q, size_t qlen, uint8_t flags2,
                    uint8_t flags3, uint16_t ancount)
{
	size_t qend = qlen;

	/* The question ends 4 bytes after the name's root label; any OPT
	 * record after it is not echoed. */
	{
		size_t off = 12;
		while (q[off] != 0)
			off += 1 + q[off];
		qend = off + 5;
	}
	r->n = 0;
	r_bytes(r, q, 2);
	r->b[r->n++] = flags2;
	r->b[r->n++] = flags3;
	r_16(r, 1);
	r_16(r, ancount);
	r_16(r, 0);
	r_16(r, 0);
	r_bytes(r, q + 12, qend - 12);
}

/* An answer record whose owner is a compression pointer. */
static void r_rr_ptr(struct resp *r, uint16_t owner_off, uint16_t type,
                     const void *rdata, uint16_t rdlen)
{
	r_16(r, (uint16_t)(0xc000 | owner_off));
	r_16(r, type);
	r_16(r, UDPC_DNS_CLASS_IN);
	r_16(r, 0);
	r_16(r, 300);
	r_16(r, rdlen);
	r_bytes(r, rdata, rdlen);
}

static void t_build(void)
{
	uint8_t b[512];
	ssize_t n;
	static const uint8_t want[] = {
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 'a', 0x04, 't', 'e', 's', 't', 0x00,
		0x00, 0x01, 0x00, 0x01
	};
	static const uint8_t opt[] = {
		0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	TAP_GROUP("D-22: query encoding, against RFC 1035 byte for byte");

	n = udpc_dns_build_query(b, sizeof(b), 0x1234, "a.test", 1, 1, 0);
	TAP_EQ_INT(n, (long long)sizeof(want), "A query for a.test is 24 bytes");
	TAP_EQ_MEM(b, want, sizeof(want),
	           "ID, RD, QDCOUNT 1, labels a/test, QTYPE A, QCLASS IN");

	n = udpc_dns_build_query(b, sizeof(b), 0x1234, "a.test.", 1, 1, 0);
	TAP_EQ_MEM(b, want, sizeof(want), "a trailing dot encodes identically");

	n = udpc_dns_build_query(b, sizeof(b), 0x1234, "a.test", 1, 1, 1232);
	TAP_EQ_INT(n, (long long)(sizeof(want) + sizeof(opt)), "with EDNS0: 35 bytes");
	TAP_EQ_INT(b[11], 1, "ARCOUNT is 1");
	TAP_EQ_MEM(b + sizeof(want), opt, sizeof(opt),
	           "OPT: root owner, type 41, UDP size 1232, no flags or options");
}

static void t_build_rejects(void)
{
	uint8_t b[512];
	char label64[80], name254[300];
	size_t i;

	TAP_GROUP("D-22: names the encoder refuses");

	memset(label64, 'x', 64);
	label64[64] = '\0';
	for (i = 0; i < 253; i++)
		name254[i] = (i % 2) ? '.' : 'a';
	name254[253] = 'a';
	name254[254] = '\0';

	errno = 0;
	TAP_OK(udpc_dns_build_query(b, sizeof(b), 1, "", 1, 1, 0) < 0 &&
	       errno == EINVAL, "empty name");
	TAP_OK(udpc_dns_build_query(b, sizeof(b), 1, ".", 1, 1, 0) < 0,
	       "the root alone");
	TAP_OK(udpc_dns_build_query(b, sizeof(b), 1, "a..test", 1, 1, 0) < 0,
	       "an empty label");
	TAP_OK(udpc_dns_build_query(b, sizeof(b), 1, label64, 1, 1, 0) < 0,
	       "a 64-byte label (the limit is 63)");
	TAP_OK(udpc_dns_build_query(b, sizeof(b), 1, name254, 1, 1, 0) < 0,
	       "a 254-character name (the limit is 253)");
	TAP_OK(udpc_dns_build_query(b, sizeof(b), 1, "a b.test", 1, 1, 0) < 0,
	       "whitespace");
	TAP_OK(udpc_dns_build_query(b, sizeof(b), 1, "a\\.test", 1, 1, 0) < 0,
	       "a backslash");
	TAP_OK(udpc_dns_build_query(b, sizeof(b), 1, "caf\xc3\xa9.test", 1, 1, 0) < 0,
	       "non-ASCII bytes");
	errno = 0;
	TAP_OK(udpc_dns_build_query(b, 16, 1, "a.test", 1, 1, 0) < 0 &&
	       errno == ENOBUFS, "a buffer too small is ENOBUFS");
}

static void t_answers(void)
{
	uint8_t q[512], q2[512];
	struct resp r;
	ssize_t ql = udpc_dns_build_query(q, sizeof(q), 0xbeef, "a.test", 1, 1, 1232);
	uint8_t ip[4] = { 192, 0, 2, 1 };

	TAP_GROUP("D-22: matching a reply to its query");

	r_start(&r, q, (size_t)ql, 0x81, 0x80, 1);
	r_rr_ptr(&r, 12, UDPC_DNS_TYPE_A, ip, 4);
	TAP_OK(udpc_dns_answers(q, (size_t)ql, r.b, r.n), "a proper reply matches");

	r.b[1] ^= 1;
	TAP_OK(!udpc_dns_answers(q, (size_t)ql, r.b, r.n), "a different ID does not");
	r.b[1] ^= 1;

	r.b[2] &= (uint8_t)~0x80;
	TAP_OK(!udpc_dns_answers(q, (size_t)ql, r.b, r.n),
	       "a message without QR -- a query, not a reply -- does not");
	r.b[2] |= 0x80;

	r.b[13] = 'A';
	TAP_OK(udpc_dns_answers(q, (size_t)ql, r.b, r.n),
	       "a name differing only in case matches");
	r.b[13] = 'b';
	TAP_OK(!udpc_dns_answers(q, (size_t)ql, r.b, r.n),
	       "an answer for another name does not");
	r.b[13] = 'a';

	ql = udpc_dns_build_query(q2, sizeof(q2), 0xbeef, "a.test", 1, 28, 0);
	TAP_OK(!udpc_dns_answers(q2, (size_t)ql, r.b, r.n),
	       "an A reply does not answer the AAAA query with the same ID");

	TAP_OK(!udpc_dns_answers(q, (size_t)ql, r.b, 11),
	       "a message shorter than a header does not");
}

static void t_parse(void)
{
	uint8_t q[512];
	struct resp r;
	struct udpc_dns_result res;
	ssize_t ql;
	uint8_t ip1[4] = { 192, 0, 2, 1 }, evil[4] = { 6, 6, 6, 6 };
	uint8_t cname_rdata[] = { 0x01, 'a', 0x04, 't', 'e', 's', 't', 0x00 };
	size_t a_owner;

	TAP_GROUP("D-22: parsing answers");

	ql = udpc_dns_build_query(q, sizeof(q), 7, "a.test", 1, 1, 0);
	r_start(&r, q, (size_t)ql, 0x81, 0x80, 2);
	r_rr_ptr(&r, 12, UDPC_DNS_TYPE_A, ip1, 4);
	/* An A record for a name nobody asked about, as a poisoning attempt
	 * would add.  It must be ignored. */
	r_bytes(&r, "\x04" "evil" "\x04" "test" "\x00", 11);
	r_16(&r, 1); r_16(&r, 1); r_16(&r, 0); r_16(&r, 60); r_16(&r, 4);
	r_bytes(&r, evil, 4);
	TAP_EQ_INT(udpc_dns_parse(r.b, r.n, "a.test", 1, &res), 0, "parses");
	TAP_EQ_INT(res.naddr, 1, "exactly one address: the unrelated record is ignored");
	TAP_EQ_MEM(res.addr[0].bytes, ip1, 4, "it is 192.0.2.1");
	TAP_EQ_STR(res.canon, "a.test", "canonical name is the queried name");

	/* alias.test CNAME a.test; a.test A 192.0.2.1; and an A record on the
	 * alias itself, which is not the end of the chain. */
	ql = udpc_dns_build_query(q, sizeof(q), 8, "alias.test", 1, 1, 0);
	r_start(&r, q, (size_t)ql, 0x81, 0x80, 3);
	r_rr_ptr(&r, 12, UDPC_DNS_TYPE_A, evil, 4);
	r_rr_ptr(&r, 12, UDPC_DNS_TYPE_CNAME, cname_rdata, sizeof(cname_rdata));
	a_owner = r.n - sizeof(cname_rdata);
	r_rr_ptr(&r, (uint16_t)a_owner, UDPC_DNS_TYPE_A, ip1, 4);
	TAP_EQ_INT(udpc_dns_parse(r.b, r.n, "alias.test", 1, &res), 0,
	           "a CNAME answer parses");
	TAP_EQ_STR(res.canon, "a.test", "the chain is followed to a.test");
	TAP_EQ_INT(res.naddr, 1, "only the chain end's address is taken");
	TAP_EQ_MEM(res.addr[0].bytes, ip1, 4, "and it is a.test's");

	ql = udpc_dns_build_query(q, sizeof(q), 9, "nx.test", 1, 1, 0);
	r_start(&r, q, (size_t)ql, 0x81, 0x83, 0);
	TAP_EQ_INT(udpc_dns_parse(r.b, r.n, "nx.test", 1, &res), 0, "NXDOMAIN parses");
	TAP_EQ_INT(res.rcode, UDPC_DNS_RCODE_NXDOMAIN, "rcode 3 is reported");
	TAP_EQ_INT(res.naddr, 0, "with no addresses");

	r_start(&r, q, (size_t)ql, 0x83, 0x80, 0);
	TAP_EQ_INT(udpc_dns_parse(r.b, r.n, "nx.test", 1, &res), 0, "TC parses");
	TAP_OK(res.truncated, "and is reported as truncated");

	/* An AAAA record with a 4-byte RDATA is wrong, and skipped. */
	ql = udpc_dns_build_query(q, sizeof(q), 10, "a.test", 1, 28, 0);
	r_start(&r, q, (size_t)ql, 0x81, 0x80, 1);
	r_rr_ptr(&r, 12, UDPC_DNS_TYPE_AAAA, ip1, 4);
	TAP_EQ_INT(udpc_dns_parse(r.b, r.n, "a.test", 28, &res), 0,
	           "an AAAA with the wrong RDATA length parses");
	TAP_EQ_INT(res.naddr, 0, "but yields no address");
}

static void t_hostile(void)
{
	uint8_t q[512];
	struct resp r;
	struct udpc_dns_result res;
	ssize_t ql = udpc_dns_build_query(q, sizeof(q), 11, "a.test", 1, 1, 0);
	uint8_t ip1[4] = { 192, 0, 2, 1 };
	size_t at;

	TAP_GROUP("D-22: hostile answers are rejected, not trusted in part");

	r_start(&r, q, (size_t)ql, 0x81, 0x80, 1);
	r_rr_ptr(&r, 12, UDPC_DNS_TYPE_A, ip1, 4);
	udpc_dns_put16(r.b + r.n - 6, 400); /* RDLENGTH past the end */
	TAP_EQ_INT(udpc_dns_parse(r.b, r.n, "a.test", 1, &res), -1,
	           "RDLENGTH running past the message");

	r_start(&r, q, (size_t)ql, 0x81, 0x80, 2);
	r_rr_ptr(&r, 12, UDPC_DNS_TYPE_A, ip1, 4);
	TAP_EQ_INT(udpc_dns_parse(r.b, r.n, "a.test", 1, &res), -1,
	           "ANCOUNT promising more records than present");

	r_start(&r, q, (size_t)ql, 0x81, 0x80, 1);
	at = r.n;
	r_rr_ptr(&r, (uint16_t)at, UDPC_DNS_TYPE_A, ip1, 4); /* owner points at itself */
	TAP_EQ_INT(udpc_dns_parse(r.b, r.n, "a.test", 1, &res), -1,
	           "a compression pointer to itself (a loop)");

	r_start(&r, q, (size_t)ql, 0x81, 0x80, 1);
	r_rr_ptr(&r, 0x3ff, UDPC_DNS_TYPE_A, ip1, 4);
	TAP_EQ_INT(udpc_dns_parse(r.b, r.n, "a.test", 1, &res), -1,
	           "a compression pointer past the end");

	TAP_EQ_INT(udpc_dns_parse(r.b, 5, "a.test", 1, &res), -1,
	           "a message shorter than a header");

	/* loop.test CNAME loop2.test; loop2.test CNAME loop.test. */
	{
		static const uint8_t l2[] = { 5, 'l', 'o', 'o', 'p', '2', 4, 't', 'e',
		                              's', 't', 0 };
		static const uint8_t l1[] = { 4, 'l', 'o', 'o', 'p', 4, 't', 'e', 's',
		                              't', 0 };
		size_t l2_at;

		ql = udpc_dns_build_query(q, sizeof(q), 12, "loop.test", 1, 1, 0);
		r_start(&r, q, (size_t)ql, 0x81, 0x80, 2);
		r_rr_ptr(&r, 12, UDPC_DNS_TYPE_CNAME, l2, sizeof(l2));
		l2_at = r.n - sizeof(l2);
		r_rr_ptr(&r, (uint16_t)l2_at, UDPC_DNS_TYPE_CNAME, l1, sizeof(l1));
		TAP_EQ_INT(udpc_dns_parse(r.b, r.n, "loop.test", 1, &res), 0,
		           "a CNAME loop terminates");
		TAP_EQ_INT(res.naddr, 0, "and yields no address");
	}
}

static void t_ptr(void)
{
	struct sockaddr_in a4;
	struct sockaddr_in6 a6;
	char out[128];
	uint8_t q[512];
	struct resp r;
	struct udpc_dns_result res;
	static const uint8_t target[] = { 1, 'a', 4, 't', 'e', 's', 't', 0 };
	ssize_t ql;

	TAP_GROUP("D-22: reverse names");

	memset(&a4, 0, sizeof(a4));
	a4.sin_family = AF_INET;
	inet_pton(AF_INET, "192.0.2.1", &a4.sin_addr);
	TAP_EQ_INT(udpc_dns_ptr_name((struct sockaddr *)&a4, out, sizeof(out)), 0,
	           "IPv4 reverse name");
	TAP_EQ_STR(out, "1.2.0.192.in-addr.arpa", "is octet-reversed under in-addr.arpa");

	memset(&a6, 0, sizeof(a6));
	a6.sin6_family = AF_INET6;
	inet_pton(AF_INET6, "2001:db8::1", &a6.sin6_addr);
	udpc_dns_ptr_name((struct sockaddr *)&a6, out, sizeof(out));
	TAP_EQ_STR(out,
	           "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
	           "IPv6 reverse name is nibble-reversed under ip6.arpa");

	inet_pton(AF_INET6, "::ffff:192.0.2.1", &a6.sin6_addr);
	udpc_dns_ptr_name((struct sockaddr *)&a6, out, sizeof(out));
	TAP_EQ_STR(out, "1.2.0.192.in-addr.arpa",
	           "a v4-mapped address uses the IPv4 form");

	TAP_EQ_INT(udpc_dns_ptr_name((struct sockaddr *)&a4, out, 10), -1,
	           "a short buffer is refused");

	ql = udpc_dns_build_query(q, sizeof(q), 13, "1.2.0.192.in-addr.arpa", 1, 12, 0);
	r_start(&r, q, (size_t)ql, 0x81, 0x80, 1);
	r_rr_ptr(&r, 12, UDPC_DNS_TYPE_PTR, target, sizeof(target));
	TAP_EQ_INT(udpc_dns_parse(r.b, r.n, "1.2.0.192.in-addr.arpa", 12, &res), 0,
	           "a PTR answer parses");
	TAP_OK(res.have_ptr, "and carries a target");
	TAP_EQ_STR(res.ptr, "a.test", "which is a.test");
}

int main(void)
{
	t_build();
	t_build_rejects();
	t_answers();
	t_parse();
	t_hostile();
	t_ptr();
	TAP_DONE();
}

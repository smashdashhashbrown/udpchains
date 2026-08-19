/* test_socks5.c -- SOCKS5 header codec unit tests.
 *
 * M2 gate: "unit tests for all three ATYP forms pass".
 * Covers FR-P-03 (encode/decode, all ATYP forms), FR-P-04 (FRAG), and
 * FR-P-07 (domain form for proxy-side resolution).
 *
 * Byte-level expectations are written out literally, from RFC 1928 §7, rather
 * than computed by the same code under test.
 */
#include "tap.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <string.h>

#include "socks5.h"

static void make_v4(struct sockaddr_in *sa, const char *ip, uint16_t port)
{
	memset(sa, 0, sizeof(*sa));
	sa->sin_family = AF_INET;
	sa->sin_port = htons(port);
	inet_pton(AF_INET, ip, &sa->sin_addr);
}

static void make_v6(struct sockaddr_in6 *sa, const char *ip, uint16_t port)
{
	memset(sa, 0, sizeof(*sa));
	sa->sin6_family = AF_INET6;
	sa->sin6_port = htons(port);
	inet_pton(AF_INET6, ip, &sa->sin6_addr);
}

int main(void)
{
	uint8_t buf[UDPC_SOCKS_HDR_MAX];
	struct udpc_socks_hdr hdr;
	ssize_t n;

	/* --- ATYP 0x01, IPv4 --------------------------------------------- */
	TAP_GROUP("ATYP 0x01 (IPv4)");
	{
		struct sockaddr_in sa;
		/* RFC 1928 §7: RSV RSV FRAG ATYP A A A A P P */
		const uint8_t want[10] = { 0x00, 0x00, 0x00, 0x01,
			                   192,  0,    2,    1,
			                   0x00, 0x35 };
		make_v4(&sa, "192.0.2.1", 53);

		n = udpc_socks_encode(buf, sizeof(buf), (struct sockaddr *)&sa);
		TAP_EQ_INT(n, 10, "IPv4 header is 10 bytes");
		TAP_EQ_MEM(buf, want, 10, "IPv4 header matches RFC 1928 layout");
		TAP_EQ_INT(buf[2], 0, "FR-P-04: FRAG is emitted as 0");

		n = udpc_socks_decode(buf, 10, &hdr);
		TAP_EQ_INT(n, 10, "IPv4 header decodes to 10 bytes consumed");
		TAP_EQ_INT(hdr.atyp, UDPC_ATYP_IPV4, "decoded ATYP is 0x01");
		TAP_EQ_INT(hdr.port, 53, "decoded port is 53");
		TAP_OK(hdr.addr_valid, "decoded address is usable");
		TAP_OK(memcmp(&((struct sockaddr_in *)&hdr.addr)->sin_addr,
		              &sa.sin_addr, 4) == 0,
		       "decoded IPv4 address round-trips");
	}

	/* --- ATYP 0x04, IPv6 --------------------------------------------- */
	TAP_GROUP("ATYP 0x04 (IPv6)");
	{
		struct sockaddr_in6 sa;
		make_v6(&sa, "2001:db8::1", 4433);

		n = udpc_socks_encode(buf, sizeof(buf), (struct sockaddr *)&sa);
		TAP_EQ_INT(n, 22, "IPv6 header is 22 bytes");
		TAP_EQ_INT(buf[3], UDPC_ATYP_IPV6, "ATYP is 0x04");
		TAP_EQ_INT(buf[2], 0, "FR-P-04: FRAG is emitted as 0");
		TAP_EQ_INT((buf[20] << 8) | buf[21], 4433, "port is big-endian");

		n = udpc_socks_decode(buf, 22, &hdr);
		TAP_EQ_INT(n, 22, "IPv6 header decodes to 22 bytes consumed");
		TAP_EQ_INT(hdr.atyp, UDPC_ATYP_IPV6, "decoded ATYP is 0x04");
		TAP_EQ_INT(hdr.port, 4433, "decoded port is 4433");
		TAP_OK(hdr.addr_valid, "decoded address is usable");
		TAP_OK(memcmp(&((struct sockaddr_in6 *)&hdr.addr)->sin6_addr,
		              &sa.sin6_addr, 16) == 0,
		       "decoded IPv6 address round-trips");
	}

	/* --- ATYP 0x03, domain (FR-P-07) --------------------------------- */
	TAP_GROUP("ATYP 0x03 (domain)");
	{
		n = udpc_socks_encode_domain(buf, sizeof(buf), "example.com", 443);
		TAP_EQ_INT(n, 7 + 11, "domain header is 7 + strlen bytes");
		TAP_EQ_INT(buf[3], UDPC_ATYP_DOMAIN, "ATYP is 0x03");
		TAP_EQ_INT(buf[4], 11, "length prefix is the domain length");
		TAP_EQ_MEM(buf + 5, "example.com", 11, "domain bytes are verbatim");
		TAP_EQ_INT((buf[16] << 8) | buf[17], 443, "port follows the domain");

		n = udpc_socks_decode(buf, (size_t)(7 + 11), &hdr);
		TAP_EQ_INT(n, 18, "domain header decodes to 18 bytes consumed");
		TAP_EQ_INT(hdr.atyp, UDPC_ATYP_DOMAIN, "decoded ATYP is 0x03");
		TAP_EQ_STR(hdr.domain, "example.com", "decoded domain round-trips");
		TAP_EQ_INT(hdr.port, 443, "decoded port is 443");
		TAP_OK(!hdr.addr_valid,
		       "a domain reply yields no sockaddr, as designed");

		/* Maximum-length domain: the 255-byte case that sizes
		 * UDPC_SOCKS_HDR_MAX. */
		{
			char big[256];
			memset(big, 'a', 255);
			big[255] = '\0';
			n = udpc_socks_encode_domain(buf, sizeof(buf), big, 1);
			TAP_EQ_INT(n, UDPC_SOCKS_HDR_MAX,
			           "255-byte domain fills the header exactly");
			n = udpc_socks_decode(buf, UDPC_SOCKS_HDR_MAX, &hdr);
			TAP_EQ_INT(n, UDPC_SOCKS_HDR_MAX,
			           "255-byte domain decodes");
			TAP_EQ_STR(hdr.domain, big, "255-byte domain round-trips");
		}
	}

	/* --- IPv4-mapped IPv6 destinations -------------------------------- */
	TAP_GROUP("v4-mapped destinations encode as ATYP 0x01, not 0x04");
	{
		struct sockaddr_in6 mapped;
		const uint8_t want[10] = { 0x00, 0x00, 0x00, 0x01,
			                   192,  0,    2,    1,
			                   0x00, 0x35 };

		/* This is what an application gets when it opens an AF_INET6
		 * dual-stack socket and connects to an IPv4 destination -- the
		 * default for getaddrinfo-based clients on a dual-stack host.
		 *
		 * Emitting ATYP 0x04 with ::ffff:192.0.2.1 asks the proxy to
		 * reach an IPv6 address that does not exist.  A proxy that takes
		 * that literally drops the datagram and reports nothing, while
		 * the association looks healthy from both ends.
		 *
		 * The in-repo fixture cannot catch this: it decodes the mapped
		 * address and sends from a dual-stack socket, where the kernel
		 * converts it back to IPv4.  Hence a unit test on the bytes. */
		make_v6(&mapped, "::ffff:192.0.2.1", 53);

		n = udpc_socks_encode(buf, sizeof(buf), (struct sockaddr *)&mapped);
		TAP_EQ_INT(n, 10,
		           "a v4-mapped destination encodes to a 10-byte header");
		TAP_EQ_INT(buf[3], UDPC_ATYP_IPV4, "with ATYP 0x01, not 0x04");
		TAP_EQ_MEM(buf, want, 10,
		           "and is byte-identical to the plain IPv4 encoding");

		/* A genuine IPv6 destination must still use ATYP 0x04. */
		make_v6(&mapped, "2001:db8::1", 53);
		n = udpc_socks_encode(buf, sizeof(buf), (struct sockaddr *)&mapped);
		TAP_EQ_INT(n, 22, "a real IPv6 destination still encodes as 22 bytes");
		TAP_EQ_INT(buf[3], UDPC_ATYP_IPV6, "with ATYP 0x04");

		/* ::ffff:0:0/96 boundary: ::1 is not v4-mapped. */
		make_v6(&mapped, "::1", 53);
		n = udpc_socks_encode(buf, sizeof(buf), (struct sockaddr *)&mapped);
		TAP_EQ_INT(buf[3], UDPC_ATYP_IPV6, "::1 is not treated as v4-mapped");
	}

	/* --- FRAG (FR-P-04) ---------------------------------------------- */
	TAP_GROUP("FR-P-04: FRAG handling");
	{
		struct sockaddr_in sa;
		make_v4(&sa, "10.0.0.1", 9);
		udpc_socks_encode(buf, sizeof(buf), (struct sockaddr *)&sa);
		buf[2] = 0x03; /* as a hostile or broken proxy might send */
		n = udpc_socks_decode(buf, 10, &hdr);
		TAP_EQ_INT(n, 10, "a FRAG != 0 header still parses");
		TAP_EQ_INT(hdr.frag, 3,
		           "FRAG is reported so the caller can discard it");
	}

	/* --- malformed input --------------------------------------------- */
	TAP_GROUP("malformed headers are never partially delivered");
	{
		uint8_t bad[UDPC_SOCKS_HDR_MAX];

		memset(bad, 0, sizeof(bad));
		bad[3] = UDPC_ATYP_IPV4;
		TAP_EQ_INT(udpc_socks_decode(bad, 9, &hdr), -1,
		           "IPv4 header one byte short is rejected");
		TAP_EQ_INT(udpc_socks_decode(bad, 3, &hdr), -1,
		           "a 3-byte datagram is rejected");

		bad[3] = UDPC_ATYP_IPV6;
		TAP_EQ_INT(udpc_socks_decode(bad, 21, &hdr), -1,
		           "IPv6 header one byte short is rejected");

		bad[3] = UDPC_ATYP_DOMAIN;
		bad[4] = 200;
		TAP_EQ_INT(udpc_socks_decode(bad, 100, &hdr), -1,
		           "domain length exceeding the datagram is rejected");
		bad[4] = 0;
		TAP_EQ_INT(udpc_socks_decode(bad, 20, &hdr), -1,
		           "zero-length domain is rejected");

		bad[3] = 0x02; /* not a valid ATYP */
		bad[4] = 0;
		TAP_EQ_INT(udpc_socks_decode(bad, 22, &hdr), -1,
		           "unknown ATYP is rejected");

		memset(bad, 0, sizeof(bad));
		bad[0] = 0xff; /* RSV must be zero */
		bad[3] = UDPC_ATYP_IPV4;
		TAP_EQ_INT(udpc_socks_decode(bad, 10, &hdr), -1,
		           "non-zero RSV is rejected");
	}

	/* --- encode buffer bounds ---------------------------------------- */
	TAP_GROUP("encode respects the destination buffer");
	{
		struct sockaddr_in sa4;
		struct sockaddr_in6 sa6;
		struct sockaddr_un_stub {
			sa_family_t sa_family;
			char pad[64];
		} weird;

		make_v4(&sa4, "10.0.0.1", 1);
		make_v6(&sa6, "::1", 1);

		TAP_EQ_INT(udpc_socks_encode(buf, 9, (struct sockaddr *)&sa4), -1,
		           "IPv4 encode into 9 bytes fails");
		TAP_EQ_INT(udpc_socks_encode(buf, 21, (struct sockaddr *)&sa6), -1,
		           "IPv6 encode into 21 bytes fails");
		TAP_EQ_INT(udpc_socks_encode_domain(buf, 10, "example.com", 1), -1,
		           "domain encode into a short buffer fails");

		memset(&weird, 0, sizeof(weird));
		weird.sa_family = AF_UNIX;
		errno = 0;
		TAP_EQ_INT(udpc_socks_encode(buf, sizeof(buf),
		                             (struct sockaddr *)&weird),
		           -1, "an unsupported family is refused");
		TAP_EQ_INT(errno, EAFNOSUPPORT, "and reports EAFNOSUPPORT");

		TAP_EQ_INT(udpc_socks_encode(buf, sizeof(buf), NULL), -1,
		           "a NULL destination is refused");
	}


	/* The relay address a proxy advertises in BND.ADDR cannot always be
	 * taken literally.  The loopback case is only reachable with a NON-local
	 * proxy, so no single-host fixture run can produce it -- it reached a
	 * real proxy undetected on 2026-08-19 and cost an afternoon.  These
	 * assertions are the only guard against it regressing. */
	TAP_GROUP("BND.ADDR relay addresses that cannot be taken literally");
	{
		struct udpc_config cfg;
		struct sockaddr_storage relay;
		struct sockaddr_in *r4 = (struct sockaddr_in *)&relay;
		struct sockaddr_in6 *r6 = (struct sockaddr_in6 *)&relay;
		struct sockaddr_in proxy4;

		/* A remote proxy at 203.0.113.9:1080 (TEST-NET-3). */
		memset(&cfg, 0, sizeof(cfg));
		make_v4(&proxy4, "203.0.113.9", 1080);
		memcpy(&cfg.proxy, &proxy4, sizeof(proxy4));
		cfg.proxy_is_local = false;

		/* Loopback relay from a REMOTE proxy: unusable as given.  The
		 * port must survive; only the address is replaced. */
		make_v4(r4, "127.0.0.1", 51464);
		udpc_socks_fixup_relay(&relay, &cfg);
		TAP_EQ_INT(relay.ss_family, AF_INET, "family is preserved");
		TAP_OK(r4->sin_addr.s_addr == proxy4.sin_addr.s_addr,
		       "a loopback relay from a remote proxy becomes the proxy "
		       "address");
		TAP_EQ_INT(ntohs(r4->sin_port), 51464,
		           "and keeps the relay PORT, not the proxy's");

		/* Wildcard from a remote proxy: same substitution. */
		make_v4(r4, "0.0.0.0", 40000);
		udpc_socks_fixup_relay(&relay, &cfg);
		TAP_OK(r4->sin_addr.s_addr == proxy4.sin_addr.s_addr,
		       "a wildcard relay becomes the proxy address");
		TAP_EQ_INT(ntohs(r4->sin_port), 40000, "keeping its port");

		/* A routable relay from a remote proxy is left ALONE.  A proxy
		 * that relays from a different host than it accepts control
		 * connections on is legitimate. */
		make_v4(r4, "198.51.100.7", 5555);
		udpc_socks_fixup_relay(&relay, &cfg);
		TAP_OK(r4->sin_addr.s_addr != proxy4.sin_addr.s_addr,
		       "a routable relay from a remote proxy is left untouched");
		TAP_EQ_INT(ntohs(r4->sin_port), 5555, "port untouched too");

		/* Now a LOCAL proxy.  Here a loopback relay is correct and must
		 * survive verbatim -- this is every test run before today, and
		 * substituting would break it. */
		cfg.proxy_is_local = true;
		make_v4(&proxy4, "127.0.0.1", 1080);
		memcpy(&cfg.proxy, &proxy4, sizeof(proxy4));

		make_v4(r4, "127.0.0.1", 51464);
		udpc_socks_fixup_relay(&relay, &cfg);
		TAP_EQ_INT(ntohs(r4->sin_port), 51464,
		           "a loopback relay from a LOCAL proxy is untouched");
		TAP_OK(ntohl(r4->sin_addr.s_addr) == INADDR_LOOPBACK,
		       "still loopback, not rewritten");

		/* A wildcard is substituted even for a local proxy: 0.0.0.0 is
		 * never a usable destination. */
		make_v4(r4, "0.0.0.0", 41000);
		udpc_socks_fixup_relay(&relay, &cfg);
		TAP_OK(ntohl(r4->sin_addr.s_addr) == INADDR_LOOPBACK,
		       "a wildcard is substituted even for a local proxy");

		/* IPv6, remote proxy: ::1 is as unusable as 127.0.0.1. */
		{
			struct sockaddr_in6 proxy6;

			memset(&cfg, 0, sizeof(cfg));
			make_v6(&proxy6, "2001:db8::9", 1080);
			memcpy(&cfg.proxy, &proxy6, sizeof(proxy6));
			cfg.proxy_is_local = false;

			make_v6(r6, "::1", 6000);
			udpc_socks_fixup_relay(&relay, &cfg);
			TAP_EQ_INT(relay.ss_family, AF_INET6,
			           "IPv6 family preserved");
			TAP_OK(memcmp(&r6->sin6_addr, &proxy6.sin6_addr, 16) == 0,
			       "a ::1 relay from a remote proxy becomes the proxy "
			       "address");
			TAP_EQ_INT(ntohs(r6->sin6_port), 6000, "keeping its port");

			make_v6(r6, "::", 6001);
			udpc_socks_fixup_relay(&relay, &cfg);
			TAP_OK(memcmp(&r6->sin6_addr, &proxy6.sin6_addr, 16) == 0,
			       "a :: relay is substituted too");
		}
	}

	TAP_DONE();
}

/* test_addr.c -- address helpers and destination classification.
 *
 * These predicates back D-05: with no bypass in v1, the shim must be able to
 * say precisely WHY a destination cannot be carried (rider R1) and must notice
 * a loopback destination that would be resolved at a remote proxy (rider R2).
 * Getting the classification wrong means either a wrong diagnostic or a
 * wrongly-refused datagram.
 */
#include "tap.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

#include "addr.h"

static struct sockaddr_storage v4(const char *ip, uint16_t port)
{
	struct sockaddr_storage ss;
	struct sockaddr_in *a = (struct sockaddr_in *)&ss;

	memset(&ss, 0, sizeof(ss));
	a->sin_family = AF_INET;
	a->sin_port = htons(port);
	inet_pton(AF_INET, ip, &a->sin_addr);
	return ss;
}

static struct sockaddr_storage v6(const char *ip, uint16_t port)
{
	struct sockaddr_storage ss;
	struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;

	memset(&ss, 0, sizeof(ss));
	a->sin6_family = AF_INET6;
	a->sin6_port = htons(port);
	inet_pton(AF_INET6, ip, &a->sin6_addr);
	return ss;
}

#define SA(x) ((const struct sockaddr *)&(x))

int main(void)
{
	struct sockaddr_storage a, b;

	TAP_GROUP("loopback classification (D-05 R2)");
	{
		a = v4("127.0.0.1", 53);
		TAP_OK(udpc_addr_is_loopback(SA(a)), "127.0.0.1 is loopback");
		a = v4("127.0.0.53", 53);
		TAP_OK(udpc_addr_is_loopback(SA(a)),
		       "127.0.0.53 is loopback (the systemd-resolved stub)");
		a = v4("127.255.255.254", 1);
		TAP_OK(udpc_addr_is_loopback(SA(a)), "all of 127/8 is loopback");
		a = v4("128.0.0.1", 1);
		TAP_OK(!udpc_addr_is_loopback(SA(a)), "128.0.0.1 is not loopback");
		a = v4("8.8.8.8", 53);
		TAP_OK(!udpc_addr_is_loopback(SA(a)), "8.8.8.8 is not loopback");

		a = v6("::1", 53);
		TAP_OK(udpc_addr_is_loopback(SA(a)), "::1 is loopback");
		a = v6("::ffff:127.0.0.1", 53);
		TAP_OK(udpc_addr_is_loopback(SA(a)),
		       "a v4-mapped loopback is still loopback");
		a = v6("2001:db8::1", 53);
		TAP_OK(!udpc_addr_is_loopback(SA(a)), "2001:db8::1 is not loopback");
	}

	TAP_GROUP("multicast classification (D-05 R1 / ADD-01)");
	{
		a = v4("224.0.0.1", 1);
		TAP_OK(udpc_addr_is_multicast(SA(a)), "224.0.0.1 is multicast");
		a = v4("224.0.0.251", 5353);
		TAP_OK(udpc_addr_is_multicast(SA(a)), "mDNS 224.0.0.251 is multicast");
		a = v4("239.255.255.250", 1900);
		TAP_OK(udpc_addr_is_multicast(SA(a)), "SSDP 239.255.255.250 is multicast");
		a = v4("223.255.255.255", 1);
		TAP_OK(!udpc_addr_is_multicast(SA(a)),
		       "223.255.255.255 is just below the multicast range");
		a = v4("240.0.0.1", 1);
		TAP_OK(!udpc_addr_is_multicast(SA(a)),
		       "240.0.0.1 is above the multicast range");

		a = v6("ff02::fb", 5353);
		TAP_OK(udpc_addr_is_multicast(SA(a)), "ff02::fb is multicast");
		a = v6("::ffff:224.0.0.251", 5353);
		TAP_OK(udpc_addr_is_multicast(SA(a)),
		       "a v4-mapped multicast address is still multicast");
		a = v6("2001:db8::1", 1);
		TAP_OK(!udpc_addr_is_multicast(SA(a)), "2001:db8::1 is not multicast");
	}

	TAP_GROUP("broadcast classification");
	{
		a = v4("255.255.255.255", 67);
		TAP_OK(udpc_addr_is_broadcast(SA(a)),
		       "255.255.255.255 is the limited broadcast address");
		a = v4("192.168.1.255", 67);
		TAP_OK(!udpc_addr_is_broadcast(SA(a)),
		       "a subnet broadcast is not detected -- documented, and safe "
		       "because it is still proxied rather than sent directly");
	}

	TAP_GROUP("address family adaptation (relay vs application socket)");
	{
		a = v4("127.0.0.1", 1080);

		/* The common case: proxy reached over IPv4, application socket
		 * is AF_INET6.  Without this the relay is unreachable. */
		TAP_EQ_INT(udpc_addr_for_family(SA(a), AF_INET6, &b), 0,
		           "an IPv4 relay adapts to an AF_INET6 socket");
		TAP_EQ_INT(b.ss_family, AF_INET6, "the result is AF_INET6");
		TAP_OK(IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6 *)&b)->sin6_addr),
		       "as a v4-mapped address");
		TAP_EQ_INT(udpc_sa_port(SA(b)), 1080, "with the port preserved");

		TAP_EQ_INT(udpc_addr_for_family(SA(a), AF_INET, &b), 0,
		           "an IPv4 relay passes through unchanged for AF_INET");
		TAP_EQ_INT(b.ss_family, AF_INET, "still AF_INET");

		a = v6("::ffff:127.0.0.1", 1080);
		TAP_EQ_INT(udpc_addr_for_family(SA(a), AF_INET, &b), 0,
		           "a v4-mapped relay unmaps for an AF_INET socket");
		TAP_EQ_INT(b.ss_family, AF_INET, "the result is AF_INET");
		TAP_EQ_INT(udpc_sa_port(SA(b)), 1080, "with the port preserved");

		/* A genuine IPv6 relay simply cannot be reached from an AF_INET
		 * socket.  Failing is correct; papering over it would produce a
		 * silently wrong destination. */
		a = v6("2001:db8::1", 1080);
		TAP_EQ_INT(udpc_addr_for_family(SA(a), AF_INET, &b), -1,
		           "a real IPv6 relay cannot be reached from AF_INET");
	}

	TAP_GROUP("parsing proxy specifications");
	{
		const char *err = NULL;

		TAP_EQ_INT(udpc_addr_parse("127.0.0.1:1080", 1080, &a, &err), 0,
		           "host:port parses");
		TAP_EQ_INT(a.ss_family, AF_INET, "as AF_INET");
		TAP_EQ_INT(udpc_sa_port(SA(a)), 1080, "with port 1080");

		TAP_EQ_INT(udpc_addr_parse("127.0.0.1", 9999, &a, &err), 0,
		           "a bare host uses the default port");
		TAP_EQ_INT(udpc_sa_port(SA(a)), 9999, "which is 9999");

		TAP_EQ_INT(udpc_addr_parse("[::1]:1080", 1080, &a, &err), 0,
		           "[v6]:port parses");
		TAP_EQ_INT(a.ss_family, AF_INET6, "as AF_INET6");
		TAP_EQ_INT(udpc_sa_port(SA(a)), 1080, "with port 1080");

		TAP_EQ_INT(udpc_addr_parse("::1", 1080, &a, &err), 0,
		           "a bare IPv6 literal parses with the default port");
		TAP_EQ_INT(a.ss_family, AF_INET6, "as AF_INET6");

		TAP_EQ_INT(udpc_addr_parse("[::1", 1080, &a, &err), -1,
		           "an unterminated IPv6 literal is rejected");
		TAP_EQ_INT(udpc_addr_parse("127.0.0.1:abc", 1080, &a, &err), -1,
		           "a non-numeric port is rejected");
		TAP_EQ_INT(udpc_addr_parse("127.0.0.1:0", 1080, &a, &err), -1,
		           "port 0 is rejected");
		TAP_EQ_INT(udpc_addr_parse("127.0.0.1:70000", 1080, &a, &err), -1,
		           "a port above 65535 is rejected");
		TAP_EQ_INT(udpc_addr_parse("", 1080, &a, &err), -1,
		           "an empty specification is rejected");
	}

	TAP_GROUP("formatting and comparison");
	{
		char buf[UDPC_ADDRSTRLEN];

		a = v4("192.0.2.1", 53);
		TAP_EQ_STR(udpc_addr_str(SA(a), buf, sizeof(buf)), "192.0.2.1:53",
		           "IPv4 formats as addr:port");

		a = v6("2001:db8::1", 443);
		TAP_EQ_STR(udpc_addr_str(SA(a), buf, sizeof(buf)), "[2001:db8::1]:443",
		           "IPv6 formats as [addr]:port");

		a = v4("10.0.0.1", 1);
		b = v4("10.0.0.1", 1);
		TAP_OK(udpc_addr_equal(SA(a), SA(b)), "identical addresses compare equal");
		b = v4("10.0.0.1", 2);
		TAP_OK(!udpc_addr_equal(SA(a), SA(b)), "a differing port compares unequal");
		b = v6("::1", 1);
		TAP_OK(!udpc_addr_equal(SA(a), SA(b)),
		       "a differing family compares unequal");
	}

	TAP_GROUP("sockaddr length (FR-I-06 family filter)");
	{
		a = v4("1.2.3.4", 1);
		TAP_EQ_INT(udpc_sa_len(SA(a)), sizeof(struct sockaddr_in),
		           "AF_INET has the right length");
		a = v6("::1", 1);
		TAP_EQ_INT(udpc_sa_len(SA(a)), sizeof(struct sockaddr_in6),
		           "AF_INET6 has the right length");
		{
			struct sockaddr_storage un;
			memset(&un, 0, sizeof(un));
			un.ss_family = AF_UNIX;
			TAP_EQ_INT(udpc_sa_len(SA(un)), 0,
			           "an unsupported family reports 0, so it is never "
			           "intercepted");
		}
	}

	TAP_DONE();
}

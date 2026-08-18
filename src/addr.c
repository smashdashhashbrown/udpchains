#include "addr.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

socklen_t udpc_sa_len(const struct sockaddr *sa)
{
	if (sa == NULL)
		return 0;
	switch (sa->sa_family) {
	case AF_INET:
		return sizeof(struct sockaddr_in);
	case AF_INET6:
		return sizeof(struct sockaddr_in6);
	default:
		return 0;
	}
}

uint16_t udpc_sa_port(const struct sockaddr *sa)
{
	if (sa == NULL)
		return 0;
	switch (sa->sa_family) {
	case AF_INET:
		return ntohs(((const struct sockaddr_in *)sa)->sin_port);
	case AF_INET6:
		return ntohs(((const struct sockaddr_in6 *)sa)->sin6_port);
	default:
		return 0;
	}
}

void udpc_sa_set_port(struct sockaddr *sa, uint16_t port)
{
	if (sa == NULL)
		return;
	switch (sa->sa_family) {
	case AF_INET:
		((struct sockaddr_in *)sa)->sin_port = htons(port);
		break;
	case AF_INET6:
		((struct sockaddr_in6 *)sa)->sin6_port = htons(port);
		break;
	default:
		break;
	}
}

const char *udpc_addr_str(const struct sockaddr *sa, char *buf, size_t buflen)
{
	char host[INET6_ADDRSTRLEN];

	if (sa == NULL) {
		snprintf(buf, buflen, "<null>");
		return buf;
	}

	switch (sa->sa_family) {
	case AF_INET: {
		const struct sockaddr_in *in = (const struct sockaddr_in *)sa;
		if (inet_ntop(AF_INET, &in->sin_addr, host, sizeof(host)) == NULL)
			break;
		snprintf(buf, buflen, "%s:%u", host, ntohs(in->sin_port));
		return buf;
	}
	case AF_INET6: {
		const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)sa;
		if (inet_ntop(AF_INET6, &in6->sin6_addr, host, sizeof(host)) == NULL)
			break;
		snprintf(buf, buflen, "[%s]:%u", host, ntohs(in6->sin6_port));
		return buf;
	}
	default:
		break;
	}

	snprintf(buf, buflen, "<unknown family %d>", (int)sa->sa_family);
	return buf;
}

bool udpc_addr_is_loopback(const struct sockaddr *sa)
{
	if (sa == NULL)
		return false;
	if (sa->sa_family == AF_INET) {
		uint32_t a = ntohl(((const struct sockaddr_in *)sa)->sin_addr.s_addr);
		return (a >> 24) == 127; /* 127.0.0.0/8 */
	}
	if (sa->sa_family == AF_INET6) {
		const struct in6_addr *a6 =
			&((const struct sockaddr_in6 *)sa)->sin6_addr;
		if (IN6_IS_ADDR_LOOPBACK(a6))
			return true;
		/* ::ffff:127.0.0.0/8 -- a v4-mapped loopback is still loopback,
		 * and an app on a dual-stack socket will produce these. */
		if (IN6_IS_ADDR_V4MAPPED(a6)) {
			uint32_t v4;
			memcpy(&v4, &a6->s6_addr[12], 4);
			return (ntohl(v4) >> 24) == 127;
		}
	}
	return false;
}

bool udpc_addr_is_multicast(const struct sockaddr *sa)
{
	if (sa == NULL)
		return false;
	if (sa->sa_family == AF_INET) {
		uint32_t a = ntohl(((const struct sockaddr_in *)sa)->sin_addr.s_addr);
		return (a & 0xf0000000u) == 0xe0000000u; /* 224.0.0.0/4 */
	}
	if (sa->sa_family == AF_INET6) {
		const struct in6_addr *a6 =
			&((const struct sockaddr_in6 *)sa)->sin6_addr;
		if (IN6_IS_ADDR_MULTICAST(a6))
			return true; /* ff00::/8 */
		if (IN6_IS_ADDR_V4MAPPED(a6)) {
			uint32_t v4;
			memcpy(&v4, &a6->s6_addr[12], 4);
			return (ntohl(v4) & 0xf0000000u) == 0xe0000000u;
		}
	}
	return false;
}

bool udpc_addr_is_broadcast(const struct sockaddr *sa)
{
	/* Only the limited broadcast address is detected here.
	 *
	 * Subnet-directed broadcast (192.168.1.255 and friends) would require
	 * knowing the local netmask for every interface, checked per datagram.
	 * Not detecting it is safe rather than merely convenient: an
	 * undetected subnet broadcast is still sent to the proxy and dropped
	 * there, so it fails -- it is never sent directly, and SEC-01 holds.
	 * The user gets a less specific diagnostic, not a leak. */
	if (sa == NULL)
		return false;
	if (sa->sa_family == AF_INET) {
		uint32_t a = ntohl(((const struct sockaddr_in *)sa)->sin_addr.s_addr);
		return a == INADDR_BROADCAST;
	}
	/* IPv6 has no broadcast; the equivalent is link-local all-nodes
	 * multicast, already caught by udpc_addr_is_multicast. */
	return false;
}

bool udpc_addr_is_local(const struct sockaddr *sa)
{
	struct ifaddrs *ifa = NULL, *p;
	bool found = false;

	if (sa == NULL)
		return false;
	if (udpc_addr_is_loopback(sa))
		return true;
	if (getifaddrs(&ifa) != 0)
		return false;

	for (p = ifa; p != NULL; p = p->ifa_next) {
		if (p->ifa_addr == NULL || p->ifa_addr->sa_family != sa->sa_family)
			continue;
		if (sa->sa_family == AF_INET) {
			const struct sockaddr_in *a = (const struct sockaddr_in *)sa;
			const struct sockaddr_in *b =
				(const struct sockaddr_in *)p->ifa_addr;
			if (a->sin_addr.s_addr == b->sin_addr.s_addr) {
				found = true;
				break;
			}
		} else if (sa->sa_family == AF_INET6) {
			const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)sa;
			const struct sockaddr_in6 *b =
				(const struct sockaddr_in6 *)p->ifa_addr;
			if (memcmp(&a->sin6_addr, &b->sin6_addr,
			           sizeof(struct in6_addr)) == 0) {
				found = true;
				break;
			}
		}
	}

	freeifaddrs(ifa);
	return found;
}

int udpc_addr_for_family(const struct sockaddr *in, int family,
                         struct sockaddr_storage *out)
{
	if (in == NULL || udpc_sa_len(in) == 0)
		return -1;

	memset(out, 0, sizeof(*out));

	if (in->sa_family == family) {
		memcpy(out, in, udpc_sa_len(in));
		return 0;
	}

	if (family == AF_INET6 && in->sa_family == AF_INET) {
		/* ::ffff:a.b.c.d -- reachable from a dual-stack AF_INET6
		 * socket, which is the default on Linux. */
		const struct sockaddr_in *in4 = (const struct sockaddr_in *)in;
		struct sockaddr_in6 *out6 = (struct sockaddr_in6 *)out;

		out6->sin6_family = AF_INET6;
		out6->sin6_port = in4->sin_port;
		out6->sin6_addr.s6_addr[10] = 0xff;
		out6->sin6_addr.s6_addr[11] = 0xff;
		memcpy(&out6->sin6_addr.s6_addr[12], &in4->sin_addr, 4);
		return 0;
	}

	if (family == AF_INET && in->sa_family == AF_INET6) {
		const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)in;
		struct sockaddr_in *out4 = (struct sockaddr_in *)out;

		/* Only a v4-mapped address can be unwrapped.  A genuine IPv6
		 * address is unreachable from an AF_INET socket. */
		if (!IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr))
			return -1;

		out4->sin_family = AF_INET;
		out4->sin_port = in6->sin6_port;
		memcpy(&out4->sin_addr, &in6->sin6_addr.s6_addr[12], 4);
		return 0;
	}

	return -1;
}

int udpc_addr_parse(const char *spec, uint16_t default_port,
                    struct sockaddr_storage *ss, const char **err)
{
	char hostbuf[256];
	char portbuf[16];
	const char *host = hostbuf;
	const char *port = portbuf;
	struct addrinfo hints, *res = NULL;
	size_t len;

	if (err)
		*err = NULL;
	if (spec == NULL || *spec == '\0') {
		if (err)
			*err = "empty address";
		return -1;
	}

	snprintf(portbuf, sizeof(portbuf), "%u", default_port);

	if (*spec == '[') {
		/* [2001:db8::1]:1080 */
		const char *close = strchr(spec, ']');
		if (close == NULL) {
			if (err)
				*err = "missing ']' in IPv6 literal";
			return -1;
		}
		len = (size_t)(close - spec - 1);
		if (len == 0 || len >= sizeof(hostbuf)) {
			if (err)
				*err = "IPv6 literal too long or empty";
			return -1;
		}
		memcpy(hostbuf, spec + 1, len);
		hostbuf[len] = '\0';
		if (close[1] == ':' && close[2] != '\0') {
			snprintf(portbuf, sizeof(portbuf), "%s", close + 2);
		} else if (close[1] != '\0') {
			if (err)
				*err = "trailing junk after IPv6 literal";
			return -1;
		}
	} else {
		/* host:port, or a bare IPv6 literal with no port, or host. */
		const char *colon = strrchr(spec, ':');
		if (colon != NULL && strchr(spec, ':') == colon) {
			len = (size_t)(colon - spec);
			if (len == 0 || len >= sizeof(hostbuf)) {
				if (err)
					*err = "host too long or empty";
				return -1;
			}
			memcpy(hostbuf, spec, len);
			hostbuf[len] = '\0';
			snprintf(portbuf, sizeof(portbuf), "%s", colon + 1);
		} else {
			/* No colon, or many colons (bare IPv6 literal). */
			if (strlen(spec) >= sizeof(hostbuf)) {
				if (err)
					*err = "host too long";
				return -1;
			}
			snprintf(hostbuf, sizeof(hostbuf), "%s", spec);
		}
	}

	if (portbuf[0] == '\0' || strspn(portbuf, "0123456789") != strlen(portbuf)) {
		if (err)
			*err = "port is not a number";
		return -1;
	}
	{
		long p = strtol(portbuf, NULL, 10);
		if (p <= 0 || p > 65535) {
			if (err)
				*err = "port out of range";
			return -1;
		}
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM; /* the control connection is TCP */
	if (getaddrinfo(host, port, &hints, &res) != 0 || res == NULL) {
		if (err)
			*err = "cannot resolve host";
		return -1;
	}

	memset(ss, 0, sizeof(*ss));
	memcpy(ss, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	return 0;
}

bool udpc_addr_equal(const struct sockaddr *a, const struct sockaddr *b)
{
	if (a == NULL || b == NULL || a->sa_family != b->sa_family)
		return false;
	if (a->sa_family == AF_INET) {
		const struct sockaddr_in *x = (const struct sockaddr_in *)a;
		const struct sockaddr_in *y = (const struct sockaddr_in *)b;
		return x->sin_addr.s_addr == y->sin_addr.s_addr &&
		       x->sin_port == y->sin_port;
	}
	if (a->sa_family == AF_INET6) {
		const struct sockaddr_in6 *x = (const struct sockaddr_in6 *)a;
		const struct sockaddr_in6 *y = (const struct sockaddr_in6 *)b;
		return memcmp(&x->sin6_addr, &y->sin6_addr,
		              sizeof(struct in6_addr)) == 0 &&
		       x->sin6_port == y->sin6_port;
	}
	return false;
}

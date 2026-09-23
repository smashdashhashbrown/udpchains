/* test_resolve.c -- the shim's own resolver, end to end (D-22).
 *
 * Run under the shim, with UDPCHAINS_DNS naming the dnsd fixture and the
 * fixture proxy in between; test_resolve.sh sets that up.  Every name below is
 * answered by dnsd, reached only through the proxy.  The host's resolver knows
 * none of them, so a lookup that succeeds proves the path.
 *
 * usage: test_resolve main | nodns | down | noconnect
 *   main       everything works: every hooked entry point, all record shapes
 *   nodns      no resolver configured: names fail EAI_FAIL, local sources work
 *   down       the proxy is unreachable: names fail EAI_AGAIN, local sources work
 *   noconnect  the proxy refuses CONNECT: a truncated answer fails, others work
 */
#include "tap.h"

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <resolv.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/* The first IPv4 or IPv6 address getaddrinfo returned for name, as text. */
static int gai(const char *name, const char *service, int family, int flags,
               int socktype, char *out, size_t outlen, struct addrinfo **keep)
{
	struct addrinfo h, *res = NULL;
	int rc;

	memset(&h, 0, sizeof(h));
	h.ai_family = family;
	h.ai_flags = flags;
	h.ai_socktype = socktype;
	rc = getaddrinfo(name, service, &h, &res);
	if (out != NULL)
		out[0] = '\0';
	if (rc != 0)
		return rc;
	if (out != NULL) {
		if (res->ai_family == AF_INET)
			inet_ntop(AF_INET, &((struct sockaddr_in *)res->ai_addr)->sin_addr,
			          out, (socklen_t)outlen);
		else
			inet_ntop(AF_INET6,
			          &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr, out,
			          (socklen_t)outlen);
	}
	if (keep != NULL)
		*keep = res;
	else
		freeaddrinfo(res);
	return 0;
}

static size_t count(const struct addrinfo *res)
{
	size_t n = 0;

	for (; res != NULL; res = res->ai_next)
		n++;
	return n;
}

/* Names answered locally must work in every mode: they never need DNS. */
static void t_local(void)
{
	char a[64];
	struct addrinfo *res = NULL;

	TAP_GROUP("D-22: local sources answer without DNS");

	TAP_EQ_INT(gai("localhost", NULL, AF_INET, 0, SOCK_DGRAM, a, sizeof(a), NULL),
	           0, "localhost resolves");
	TAP_EQ_STR(a, "127.0.0.1", "to 127.0.0.1");
	TAP_EQ_INT(gai("printer.localhost", NULL, AF_INET6, 0, SOCK_DGRAM, a, sizeof(a),
	               NULL),
	           0, "a name under .localhost resolves (RFC 6761)");
	TAP_EQ_STR(a, "::1", "to ::1");
	TAP_EQ_INT(gai("hostsonly.test", NULL, AF_INET, 0, SOCK_DGRAM, a, sizeof(a),
	               NULL),
	           0, "a hosts-file name resolves");
	TAP_EQ_STR(a, "203.0.113.5", "to its hosts-file address");
	TAP_EQ_INT(gai("192.0.2.99", "53", AF_UNSPEC, 0, 0, NULL, 0, &res), 0,
	           "a numeric address resolves");
	TAP_EQ_INT(count(res), 3, "with glibc's expansion: stream, datagram, raw");
	freeaddrinfo(res);
}

static void t_forward(void)
{
	char a[64];
	struct addrinfo *res = NULL;

	TAP_GROUP("D-22: getaddrinfo through the proxy");

	TAP_EQ_INT(gai("a.test", NULL, AF_INET, 0, SOCK_DGRAM, a, sizeof(a), NULL), 0,
	           "A lookup succeeds");
	TAP_EQ_STR(a, "192.0.2.1", "with the zone's address");
	TAP_EQ_INT(gai("a.test", NULL, AF_INET6, 0, SOCK_DGRAM, a, sizeof(a), NULL), 0,
	           "AAAA lookup succeeds");
	TAP_EQ_STR(a, "2001:db8::1", "with the zone's address");

	TAP_EQ_INT(gai("a.test", NULL, AF_UNSPEC, 0, SOCK_DGRAM, NULL, 0, &res), 0,
	           "AF_UNSPEC lookup succeeds");
	TAP_EQ_INT(count(res), 2, "with both families");
	freeaddrinfo(res);

	TAP_EQ_INT(gai("multi.test", NULL, AF_INET, 0, SOCK_DGRAM, NULL, 0, &res), 0,
	           "a multi-address name resolves");
	TAP_EQ_INT(count(res), 2, "to both addresses");
	freeaddrinfo(res);

	TAP_EQ_INT(gai("alias.test", NULL, AF_INET, AI_CANONNAME, SOCK_DGRAM, a,
	               sizeof(a), &res),
	           0, "a CNAME resolves");
	TAP_EQ_STR(a, "192.0.2.1", "to its target's address");
	TAP_EQ_STR(res->ai_canonname, "a.test",
	           "AI_CANONNAME reports the end of the chain");
	freeaddrinfo(res);

	TAP_EQ_INT(gai("a.test", "domain", AF_INET, 0, SOCK_DGRAM, NULL, 0, &res), 0,
	           "a named service resolves alongside the host");
	TAP_EQ_INT(ntohs(((struct sockaddr_in *)res->ai_addr)->sin_port), 53,
	           "to its port");
	freeaddrinfo(res);

	TAP_EQ_INT(gai("a.test", "no-such-service", AF_INET, 0, SOCK_DGRAM, NULL, 0,
	               NULL),
	           EAI_SERVICE, "an unknown service is EAI_SERVICE, as in glibc");
	TAP_EQ_INT(gai("nx.test", NULL, AF_INET, 0, SOCK_DGRAM, NULL, 0, NULL),
	           EAI_NONAME, "NXDOMAIN is EAI_NONAME");
	TAP_EQ_INT(gai("v4only.test", NULL, AF_INET6, 0, SOCK_DGRAM, NULL, 0, NULL),
	           EAI_NODATA, "a name with no AAAA is EAI_NODATA for AF_INET6");
	TAP_EQ_INT(gai("v4only.test", NULL, AF_INET6, AI_V4MAPPED, SOCK_DGRAM, a,
	               sizeof(a), NULL),
	           0, "with AI_V4MAPPED it resolves");
	TAP_EQ_STR(a, "::ffff:192.0.2.4", "to the mapped IPv4 address");
	TAP_EQ_INT(gai("loop.test", NULL, AF_INET, 0, SOCK_DGRAM, NULL, 0, NULL),
	           EAI_NODATA, "a CNAME loop terminates, with no address");
	TAP_EQ_INT(gai("host", NULL, AF_INET, 0, SOCK_DGRAM, a, sizeof(a), NULL), 0,
	           "a single label resolves through dns_search");
	TAP_EQ_STR(a, "192.0.2.20", "as host.search.test");

	TAP_EQ_INT(gai("big.test", NULL, AF_INET, 0, SOCK_DGRAM, NULL, 0, &res), 0,
	           "a truncated UDP answer is repeated over TCP");
	TAP_EQ_INT(count(res), 100, "and all 100 addresses arrive");
	freeaddrinfo(res);

	TAP_EQ_INT(gai("caf\xc3\xa9.test", NULL, AF_INET, 0, SOCK_DGRAM, NULL, 0, NULL),
	           EAI_IDN_ENCODE, "a non-ASCII name is refused (D-22)");
}

static void t_reverse(void)
{
	struct sockaddr_in s4;
	struct sockaddr_in6 s6;
	char host[256];

	TAP_GROUP("D-22: getnameinfo through the proxy");

	memset(&s4, 0, sizeof(s4));
	s4.sin_family = AF_INET;
	inet_pton(AF_INET, "192.0.2.1", &s4.sin_addr);
	TAP_EQ_INT(getnameinfo((struct sockaddr *)&s4, sizeof(s4), host, sizeof(host),
	                       NULL, 0, NI_NAMEREQD),
	           0, "PTR lookup succeeds");
	TAP_EQ_STR(host, "a.test", "with the zone's name");

	memset(&s6, 0, sizeof(s6));
	s6.sin6_family = AF_INET6;
	inet_pton(AF_INET6, "2001:db8::1", &s6.sin6_addr);
	TAP_EQ_INT(getnameinfo((struct sockaddr *)&s6, sizeof(s6), host, sizeof(host),
	                       NULL, 0, NI_NAMEREQD),
	           0, "IPv6 PTR lookup succeeds");
	TAP_EQ_STR(host, "a.test", "with the zone's name");

	inet_pton(AF_INET, "192.0.2.77", &s4.sin_addr);
	TAP_EQ_INT(getnameinfo((struct sockaddr *)&s4, sizeof(s4), host, sizeof(host),
	                       NULL, 0, NI_NAMEREQD),
	           EAI_NONAME, "an address with no PTR is EAI_NONAME under NI_NAMEREQD");
	TAP_EQ_INT(getnameinfo((struct sockaddr *)&s4, sizeof(s4), host, sizeof(host),
	                       NULL, 0, 0),
	           0, "and falls back to numeric without it");
	TAP_EQ_STR(host, "192.0.2.77", "as the address itself");

	inet_pton(AF_INET, "203.0.113.5", &s4.sin_addr);
	TAP_EQ_INT(getnameinfo((struct sockaddr *)&s4, sizeof(s4), host, sizeof(host),
	                       NULL, 0, NI_NAMEREQD),
	           0, "a hosts-file address reverses locally");
	TAP_EQ_STR(host, "hostsonly.test", "to its hosts-file name");

	inet_pton(AF_INET, "192.0.2.1", &s4.sin_addr);
	TAP_EQ_INT(getnameinfo((struct sockaddr *)&s4, sizeof(s4), host, 4, NULL, 0,
	                       NI_NAMEREQD),
	           EAI_OVERFLOW, "a host buffer too small is EAI_OVERFLOW");
}

static void t_hostent(void)
{
	struct hostent *he, hb, *res = NULL;
	char buf[16], a[64];
	int herr = 0;

	TAP_GROUP("D-22: gethostbyname and gethostbyaddr through the proxy");

	he = gethostbyname("a.test");
	TAP_OK(he != NULL, "gethostbyname succeeds");
	if (he != NULL) {
		inet_ntop(AF_INET, he->h_addr_list[0], a, sizeof(a));
		TAP_EQ_STR(a, "192.0.2.1", "with the zone's address");
		TAP_EQ_STR(he->h_name, "a.test", "and name");
		TAP_OK(he->h_addr_list[1] == NULL, "and one address");
	}
	he = gethostbyname2("a.test", AF_INET6);
	TAP_OK(he != NULL && he->h_length == 16, "gethostbyname2(AF_INET6) succeeds");

	he = gethostbyname("nx.test");
	TAP_OK(he == NULL && h_errno == HOST_NOT_FOUND,
	       "NXDOMAIN is NULL with HOST_NOT_FOUND");

	TAP_EQ_INT(gethostbyname_r("a.test", &hb, buf, sizeof(buf), &res, &herr),
	           ERANGE, "gethostbyname_r with a small buffer is ERANGE");
	TAP_OK(res == NULL && herr == NETDB_INTERNAL, "with NETDB_INTERNAL, as in glibc");

	{
		struct in_addr ia;

		inet_pton(AF_INET, "192.0.2.1", &ia);
		he = gethostbyaddr(&ia, 4, AF_INET);
		TAP_OK(he != NULL, "gethostbyaddr succeeds");
		if (he != NULL)
			TAP_EQ_STR(he->h_name, "a.test", "with the zone's name");
	}
}

static void t_res(void)
{
	unsigned char q[512], ans[4096];
	int n, qn;

	TAP_GROUP("D-22: the res_* query API through the proxy");

	n = res_query("a.test", ns_c_in, ns_t_a, ans, sizeof(ans));
	TAP_OK(n > 12, "res_query succeeds (%d bytes)", n);
	if (n > 12)
		TAP_EQ_INT((ans[6] << 8) | ans[7], 1, "with one answer record");

	h_errno = 0;
	TAP_EQ_INT(res_query("nx.test", ns_c_in, ns_t_a, ans, sizeof(ans)), -1,
	           "res_query for NXDOMAIN is -1");
	TAP_EQ_INT(h_errno, HOST_NOT_FOUND, "with HOST_NOT_FOUND");

	TAP_OK(res_search("host", ns_c_in, ns_t_a, ans, sizeof(ans)) > 12,
	       "res_search applies dns_search");

	qn = res_mkquery(ns_o_query, "a.test", ns_c_in, ns_t_aaaa, NULL, 0, NULL, q,
	                 sizeof(q));
	n = res_send(q, qn, ans, sizeof(ans));
	TAP_OK(n > 12, "res_send carries a caller-built query");
	if (n > 12)
		TAP_OK(ans[0] == q[0] && ans[1] == q[1] && (ans[2] & 0x80),
		       "and returns the reply to it");
}

static void *worker(void *arg)
{
	int i, *ok = arg;

	for (i = 0; i < 10; i++) {
		char a[64];
		if (gai(i % 2 ? "a.test" : "multi.test", NULL, AF_INET, 0, SOCK_DGRAM,
		        a, sizeof(a), NULL) != 0)
			return NULL;
	}
	*ok = 1;
	return NULL;
}

static void t_concurrency_and_fork(void)
{
	pthread_t tid[8];
	int ok[8] = { 0 }, i, all = 1, status = 0;
	pid_t pid;

	TAP_GROUP("D-22: the association pool under threads and fork");

	for (i = 0; i < 8; i++)
		pthread_create(&tid[i], NULL, worker, &ok[i]);
	for (i = 0; i < 8; i++) {
		pthread_join(tid[i], NULL);
		all &= ok[i];
	}
	TAP_OK(all, "8 threads x 10 lookups all succeed through a 4-entry pool");

	pid = fork();
	if (pid == 0) {
		char a[64];
		_exit(gai("a.test", NULL, AF_INET, 0, SOCK_DGRAM, a, sizeof(a), NULL) == 0 &&
		              strcmp(a, "192.0.2.1") == 0
		          ? 0
		          : 1);
	}
	waitpid(pid, &status, 0);
	TAP_OK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	       "a forked child resolves on its own association");
	TAP_EQ_INT(gai("a.test", NULL, AF_INET, 0, SOCK_DGRAM, NULL, 0, NULL), 0,
	           "and the parent still resolves afterwards");
}

static void t_getaddrinfo_a(void)
{
	struct gaicb cb, *list[1] = { &cb };

	TAP_GROUP("D-22: getaddrinfo_a fails closed");

	memset(&cb, 0, sizeof(cb));
	cb.ar_name = "a.test";
	TAP_EQ_INT(getaddrinfo_a(GAI_WAIT, list, 1, NULL), EAI_SYSTEM,
	           "getaddrinfo_a is refused rather than resolved directly");
}

/* Every name that needs DNS must fail with `want`, and nothing else. */
static void t_names_fail(int want, const char *why)
{
	struct sockaddr_in s4;
	char host[256];
	unsigned char ans[512];

	TAP_GROUP(why);

	TAP_EQ_INT(gai("a.test", NULL, AF_INET, 0, SOCK_DGRAM, NULL, 0, NULL), want,
	           "getaddrinfo fails as expected");
	TAP_OK(gethostbyname("a.test") == NULL, "gethostbyname fails");
	TAP_EQ_INT(res_query("a.test", ns_c_in, ns_t_a, ans, sizeof(ans)), -1,
	           "res_query fails");

	memset(&s4, 0, sizeof(s4));
	s4.sin_family = AF_INET;
	inet_pton(AF_INET, "192.0.2.1", &s4.sin_addr);
	TAP_EQ_INT(getnameinfo((struct sockaddr *)&s4, sizeof(s4), host, sizeof(host),
	                       NULL, 0, NI_NAMEREQD),
	           want, "getnameinfo with NI_NAMEREQD fails as expected");
	TAP_EQ_INT(getnameinfo((struct sockaddr *)&s4, sizeof(s4), host, sizeof(host),
	                       NULL, 0, 0),
	           0, "getnameinfo without it falls back to numeric");
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "main";

	t_local();

	if (strcmp(mode, "main") == 0) {
		t_forward();
		t_reverse();
		t_hostent();
		t_res();
		t_concurrency_and_fork();
		t_getaddrinfo_a();
	} else if (strcmp(mode, "nodns") == 0) {
		t_names_fail(EAI_FAIL, "D-22: no resolver configured -- names fail closed");
	} else if (strcmp(mode, "down") == 0) {
		t_names_fail(EAI_AGAIN, "D-22: proxy unreachable -- names fail closed");
	} else if (strcmp(mode, "noconnect") == 0) {
		TAP_GROUP("D-22: a proxy refusing CONNECT");
		TAP_EQ_INT(gai("a.test", NULL, AF_INET, 0, SOCK_DGRAM, NULL, 0, NULL), 0,
		           "an ordinary lookup still works over UDP");
		TAP_EQ_INT(gai("big.test", NULL, AF_INET, 0, SOCK_DGRAM, NULL, 0, NULL),
		           EAI_AGAIN,
		           "a truncated answer fails: its TCP retry cannot be proxied");
	} else {
		fprintf(stderr, "usage: test_resolve main|nodns|down|noconnect\n");
		return 2;
	}
	TAP_DONE();
}

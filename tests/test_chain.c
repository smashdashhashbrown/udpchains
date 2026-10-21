/* test_chain.c -- chain setup against chained fixtures, and the chain codec
 * (FR-CH-01 to FR-CH-07, FR-CH-09, FR-CH-12; D-37 to D-41, D-43 to D-45).
 *
 * Links the shim's objects directly, like the other unit tests, and starts its
 * own fixture proxies from the directory it was built in, so it runs the same
 * under the suite and under the sanitisers.
 *
 * The round trips here wrap and unwrap the layers by hand with the
 * single-header codec, independently of the chain codec they also test: what
 * they prove is that the relays chain setup returns are the ones a datagram
 * must take.  The datagram path itself is tested through chains by running the
 * integration tests with a chain (FR-CH-T2, tests/run.sh).
 *
 * usage: test_chain           (from the build directory, or by path)
 */
#include "tap.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "addr.h"
#include "config.h"
#include "socks5.h"

/* --- fixtures --------------------------------------------------------------- */

static char g_dir[4096];
static pid_t g_pids[16];
static int g_npids;

static void stop_fixtures(void)
{
	int i;

	for (i = 0; i < g_npids; i++) {
		kill(g_pids[i], SIGTERM);
		waitpid(g_pids[i], NULL, 0);
	}
	g_npids = 0;
}

/* Starts a fixture from the build directory and returns the port it printed
 * ("PORT <n>"), or exits: without its fixtures this test proves nothing. */
static uint16_t start_fixture(const char *prog, const char *const args[])
{
	char path[4200], line[64];
	char *argv[16];
	int p[2], n = 0, devnull;
	unsigned port = 0;
	FILE *f;
	pid_t pid;

	snprintf(path, sizeof(path), "%s/%s", g_dir, prog);
	argv[n++] = path;
	while (args[n - 1] != NULL && n < 15) {
		argv[n] = (char *)(uintptr_t)args[n - 1];
		n++;
	}
	argv[n] = NULL;

	if (pipe(p) != 0 || g_npids >= (int)(sizeof(g_pids) / sizeof(g_pids[0]))) {
		perror("pipe");
		exit(2);
	}
	pid = fork();
	if (pid < 0) {
		perror("fork");
		exit(2);
	}
	if (pid == 0) {
		devnull = open("/dev/null", O_WRONLY);
		dup2(p[1], 1);
		if (devnull >= 0)
			dup2(devnull, 2);
		close(p[0]);
		execv(path, argv);
		_exit(127);
	}
	close(p[1]);
	g_pids[g_npids++] = pid;

	/* The read end stays open for the fixture's life, so a late write to
	 * its stdout never meets a closed pipe. */
	f = fdopen(p[0], "r");
	while (f != NULL && fgets(line, sizeof(line), f) != NULL)
		if (sscanf(line, "PORT %u", &port) == 1)
			break;
	if (port == 0 || port > 65535) {
		fprintf(stderr, "fixture %s did not report a port\n", prog);
		stop_fixtures();
		exit(2);
	}
	return (uint16_t)port;
}

/* --- helpers ---------------------------------------------------------------- */

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

/* The lowest free descriptor.  Equal before and after a call means the call
 * left nothing open. */
static int lowest_free_fd(void)
{
	int fd = dup(0);

	if (fd >= 0)
		close(fd);
	return fd;
}

/* A configuration whose chain is specs[0..n), finalised as the shim would see
 * it.  Credentials are set by the caller afterwards. */
static struct udpc_config g_cfg;

static struct udpc_config *chain_cfg(const char *const specs[], unsigned n)
{
	const char *err = NULL;
	unsigned i;

	udpc_config_init(&g_cfg);
	udpc_config_defaults(&g_cfg);
	g_cfg.connect_timeout_ms = 2000;
	if (udpc_config_set(&g_cfg, "proxy", specs[0], &err) != 0)
		goto bad;
	for (i = 1; i < n; i++)
		if (udpc_config_append_hop(&g_cfg, specs[i], &err) != 0)
			goto bad;
	if (udpc_config_finalize(&g_cfg, &err) != 0)
		goto bad;
	return &g_cfg;

bad:
	fprintf(stderr, "chain_cfg: %s\n", err ? err : "?");
	stop_fixtures();
	exit(2);
}

static void hop_creds(struct udpc_config *cfg, unsigned hop, const char *user,
                      const char *pass)
{
	struct udpc_hop *h = &cfg->hops[hop - 2];

	h->have_credentials = true;
	snprintf(h->username, sizeof(h->username), "%s", user);
	snprintf(h->password, sizeof(h->password), "%s", pass);
}

static bool chain_is_empty(const struct udpc_socks_chain *ch)
{
	unsigned k;

	if (ch->n != 0)
		return false;
	for (k = 0; k < UDPC_CHAIN_MAX; k++)
		if (ch->control_fd[k] != -1)
			return false;
	return true;
}

/* An address's IPv4 form, if it has one, so a reply source seen as
 * ::ffff:127.0.0.1 compares equal to 127.0.0.1. */
static void canonical(const struct sockaddr_storage *in, struct sockaddr_storage *out)
{
	const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)in;

	*out = *in;
	if (in->ss_family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr)) {
		struct sockaddr_in *o = (struct sockaddr_in *)out;
		uint16_t port = in6->sin6_port;
		struct in_addr a;

		memcpy(&a, &in6->sin6_addr.s6_addr[12], 4);
		memset(out, 0, sizeof(*out));
		o->sin_family = AF_INET;
		o->sin_addr = a;
		o->sin_port = port;
	}
}

static bool same_addr(const struct sockaddr_storage *a,
                      const struct sockaddr_storage *b)
{
	struct sockaddr_storage x, y;

	canonical(a, &x);
	canonical(b, &y);
	return udpc_addr_equal((const struct sockaddr *)&x,
	                       (const struct sockaddr *)&y);
}

/* Wraps payload in one header per hop -- the target innermost, then each
 * later hop's relay outwards -- sends it to hop 1's relay, and unwraps the
 * echo, checking every layer's source: the relay of the next hop (its port
 * only, where that relay is a name, D-41), and the target innermost.
 * Returns the number of layers that checked out, or -1 if nothing came back:
 * a full success is ch->n. */
static int round_trip(const struct udpc_socks_chain *ch,
                      const struct sockaddr *target)
{
	static const char payload[] = "through the chain";
	uint8_t pkt[UDPC_CHAIN_MAX * UDPC_SOCKS_HDR_MAX + sizeof(payload)];
	struct sockaddr_storage target_ss;
	struct udpc_socks_hdr hdr;
	struct pollfd pfd;
	size_t off = 0, len;
	ssize_t n;
	unsigned k;
	int fd, good = 0;

	for (k = 1; k < ch->n; k++) {
		const struct udpc_socks_addr *r = &ch->relay[k];

		n = r->named ? udpc_socks_encode_domain(pkt + off, sizeof(pkt) - off,
		                                        r->host, r->port)
		             : udpc_socks_encode(pkt + off, sizeof(pkt) - off,
		                                 (const struct sockaddr *)&r->sa);
		if (n < 0)
			return -1;
		off += (size_t)n;
	}
	n = udpc_socks_encode(pkt + off, sizeof(pkt) - off, target);
	if (n < 0)
		return -1;
	off += (size_t)n;
	memcpy(pkt + off, payload, sizeof(payload));
	off += sizeof(payload);

	fd = socket(ch->relay[0].sa.ss_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	if (sendto(fd, pkt, off, 0, (const struct sockaddr *)&ch->relay[0].sa,
	           udpc_sa_len((const struct sockaddr *)&ch->relay[0].sa)) !=
	    (ssize_t)off) {
		close(fd);
		return -1;
	}

	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	if (poll(&pfd, 1, 3000) != 1) {
		close(fd);
		return -1;
	}
	n = recv(fd, pkt, sizeof(pkt), 0);
	close(fd);
	if (n < 0)
		return -1;

	len = (size_t)n;
	off = 0;
	memset(&target_ss, 0, sizeof(target_ss));
	memcpy(&target_ss, target, udpc_sa_len(target));
	for (k = 1; k <= ch->n; k++) {
		n = udpc_socks_decode(pkt + off, len - off, &hdr);
		if (n < 0 || hdr.frag != 0 || !hdr.addr_valid)
			return good;
		off += (size_t)n;
		if (k < ch->n) {
			const struct udpc_socks_addr *r = &ch->relay[k];

			if (r->named ? hdr.port != r->port
			             : !same_addr(&hdr.addr, &r->sa))
				return good;
		} else if (!same_addr(&hdr.addr, &target_ss)) {
			return good;
		}
		good++;
	}
	if (len - off != sizeof(payload) || memcmp(pkt + off, payload, len - off) != 0)
		return good - 1;
	return good;
}

/* Builds a reply as a 3-hop chain delivers it: layer 1 from l1, layer 2 from
 * l2 (NULL: some address with port 3000, the named relay's in the D-41 tests),
 * the innermost from src, then "data".  Returns its length. */
static size_t build_reply(uint8_t *pkt, size_t len, const struct sockaddr *l1,
                          const struct sockaddr *l2, const struct sockaddr_in *src)
{
	struct sockaddr_in some;
	size_t off = 0;
	ssize_t n;

	make_v4(&some, "10.9.9.9", 3000);
	n = udpc_socks_encode(pkt, len, l1);
	off += (size_t)n;
	n = udpc_socks_encode(pkt + off, len - off,
	                      l2 != NULL ? l2 : (const struct sockaddr *)&some);
	off += (size_t)n;
	n = udpc_socks_encode(pkt + off, len - off, (const struct sockaddr *)src);
	off += (size_t)n;
	memcpy(pkt + off, "data", 4);
	return off + 4;
}

/* A hop that answers every step, but slowly: each reply comes step_ms after
 * the request.  It requires RFC 1929 authentication, so a handshake with it is
 * three steps -- greeting, credentials, request -- each within its own timeout
 * however long they take together (D-45).  Serves connections one at a time
 * until the listener is closed. */
struct slow_hop {
	int listen_fd;
	int step_ms;
};

/* One step: a request read, a pause, a reply written.  0 on success. */
static int slow_step(int c, uint8_t *buf, size_t len, int step_ms,
                     const uint8_t *reply, size_t replylen)
{
	if (read(c, buf, len) <= 0)
		return -1;
	usleep((useconds_t)step_ms * 1000);
	return write(c, reply, replylen) == (ssize_t)replylen ? 0 : -1;
}

static void *slow_hop_main(void *arg)
{
	const struct slow_hop *sh = arg;
	uint8_t buf[600];

	for (;;) {
		static const uint8_t method[2] = { 0x05, 0x02 }, auth_ok[2] = { 0x01, 0x00 };
		static const uint8_t ok[10] = { 0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1,
			                        0x00, 0x09 };
		int c = accept(sh->listen_fd, NULL, NULL);

		if (c < 0)
			return NULL;
		/* Each read takes what the client sent for the step; the client
		 * sends nothing more until it has the reply. */
		if (slow_step(c, buf, sizeof(buf), sh->step_ms, method, 2) == 0 &&
		    slow_step(c, buf, sizeof(buf), sh->step_ms, auth_ok, 2) == 0)
			(void)slow_step(c, buf, sizeof(buf), sh->step_ms, ok, sizeof(ok));
		/* Held open until the client lets go, like a control connection. */
		while (read(c, buf, sizeof(buf)) > 0)
			;
		close(c);
	}
}

static long long elapsed_ms(const struct timespec *t0)
{
	struct timespec t1;

	clock_gettime(CLOCK_MONOTONIC, &t1);
	return (long long)(t1.tv_sec - t0->tv_sec) * 1000 +
	       (t1.tv_nsec - t0->tv_nsec) / 1000000;
}

/* Puts stderr in a file around a failing call, so its diagnostics can be
 * checked: they are part of the behaviour (FR-CH-01, FR-CH-12). */
static char g_stderr[4096];

/* A hop's failure is reported at most once a second, so a test that checks
 * that report first waits out the previous one's second. */
static void next_report_window(void)
{
	usleep(1100 * 1000);
}

static void capture_begin(int *saved)
{
	char tmpl[] = "/tmp/test_chain.XXXXXX";
	int fd = mkstemp(tmpl);

	fflush(stderr);
	*saved = dup(2);
	if (fd >= 0) {
		unlink(tmpl);
		dup2(fd, 2);
		close(fd);
	}
}

static const char *capture_end(int saved)
{
	ssize_t n;

	fflush(stderr);
	memset(g_stderr, 0, sizeof(g_stderr));
	if (lseek(2, 0, SEEK_SET) == 0) {
		n = read(2, g_stderr, sizeof(g_stderr) - 1);
		if (n < 0)
			g_stderr[0] = '\0';
	}
	dup2(saved, 2);
	close(saved);
	return g_stderr;
}

int main(int argc, char **argv)
{
	static const char *const plain[] = { "--port", "0", "--quiet", NULL };
	static const char *const authd[] = { "--port", "0", "--quiet",
		                             "--auth-required", "--auth-user",
		                             "hopuser", "--auth-pass", "hoppass",
		                             NULL };
	static const char *const noconn[] = { "--port", "0", "--quiet",
		                              "--no-connect", NULL };
	static const char *const refuse[] = { "--port", "0", "--quiet",
		                              "--refuse-associate", NULL };
	static const char *const expire[] = { "--port", "0", "--quiet",
		                              "--expire-after", "1", NULL };
	static const char *const echo[] = { "--port", "0", "--quiet", NULL };
	char a[32], b[32], c[32], named_c[32], n_[32], r_[32], x_[32], dead[32];
	struct sockaddr_in echo_sa, a_sa, held;
	struct udpc_socks_chain ch;
	struct udpc_config *cfg;
	uint16_t pa, pb, pc, pn, pr, px, pe;
	int e, before, saved, hold;
	socklen_t hlen = sizeof(held);
	const char *slash = strrchr(argv[0], '/');

	(void)argc;
	if (slash != NULL)
		snprintf(g_dir, sizeof(g_dir), "%.*s", (int)(slash - argv[0]), argv[0]);
	else
		snprintf(g_dir, sizeof(g_dir), ".");
	signal(SIGPIPE, SIG_IGN);

	pa = start_fixture("socks5d", plain);
	pb = start_fixture("socks5d", authd);
	pc = start_fixture("socks5d", plain);
	pn = start_fixture("socks5d", noconn);
	pr = start_fixture("socks5d", refuse);
	px = start_fixture("socks5d", expire);
	pe = start_fixture("udpecho", echo);

	snprintf(a, sizeof(a), "127.0.0.1:%u", pa);
	snprintf(b, sizeof(b), "127.0.0.1:%u", pb);
	snprintf(c, sizeof(c), "127.0.0.1:%u", pc);
	snprintf(named_c, sizeof(named_c), "localhost:%u", pc);
	snprintf(n_, sizeof(n_), "127.0.0.1:%u", pn);
	snprintf(r_, sizeof(r_), "127.0.0.1:%u", pr);
	snprintf(x_, sizeof(x_), "127.0.0.1:%u", px);
	make_v4(&echo_sa, "127.0.0.1", pe);
	make_v4(&a_sa, "127.0.0.1", pa);

	/* A port bound with nothing listening: refused, and no one else can
	 * take it while it is held. */
	hold = socket(AF_INET, SOCK_STREAM, 0);
	make_v4(&held, "127.0.0.1", 0);
	if (hold < 0 || bind(hold, (struct sockaddr *)&held, sizeof(held)) != 0 ||
	    getsockname(hold, (struct sockaddr *)&held, &hlen) != 0) {
		perror("hold");
		stop_fixtures();
		return 2;
	}
	snprintf(dead, sizeof(dead), "127.0.0.1:%u", ntohs(held.sin_port));

	/* ------------------------------------------------------------------ */
	TAP_GROUP("D-39: a later hop's address is taken as written");
	{
		struct udpc_socks_addr ad;
		const struct sockaddr_in *s4 = (const struct sockaddr_in *)&ad.sa;
		const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)&ad.sa;

		TAP_EQ_INT(udpc_socks_hop_addr("10.0.0.5:1081", &ad), 0,
		           "an IPv4 hop parses");
		TAP_OK(!ad.named && ad.sa.ss_family == AF_INET &&
		       ntohl(s4->sin_addr.s_addr) == 0x0a000005 &&
		       ntohs(s4->sin_port) == 1081,
		       "as a numeric IPv4 address and port");

		TAP_EQ_INT(udpc_socks_hop_addr("[2001:db8::7]:1082", &ad), 0,
		           "an IPv6 hop parses");
		TAP_OK(!ad.named && ad.sa.ss_family == AF_INET6 &&
		       s6->sin6_addr.s6_addr[15] == 7 && ntohs(s6->sin6_port) == 1082,
		       "as a numeric IPv6 address and port");

		TAP_EQ_INT(udpc_socks_hop_addr("proxy.internal:1083", &ad), 0,
		           "a named hop parses");
		TAP_OK(ad.named && strcmp(ad.host, "proxy.internal") == 0 &&
		       ad.port == 1083 && ad.sa.ss_family == AF_UNSPEC,
		       "and stays a name, unresolved");

		TAP_EQ_INT(udpc_socks_hop_addr("proxy.internal", &ad), 0,
		           "a hop without a port parses");
		TAP_EQ_INT(ad.port, UDPC_DEFAULT_PROXY_PORT, "with the default port");

		errno = 0;
		TAP_EQ_INT(udpc_socks_hop_addr("proxy.internal:0", &ad), -1,
		           "port 0 is refused");
		TAP_EQ_INT(errno, EINVAL, "with EINVAL");
	}

	/* ------------------------------------------------------------------ */
	TAP_GROUP("D-40: the relay fixup for later hops");
	{
		struct udpc_socks_addr relay, hop;
		struct sockaddr_in *r4 = (struct sockaddr_in *)&relay.sa;
		struct sockaddr_in6 *r6 = (struct sockaddr_in6 *)&relay.sa;

		/* Wildcard, numeric hop: the hop's address, the relay's port. */
		memset(&relay, 0, sizeof(relay));
		make_v4(r4, "0.0.0.0", 40001);
		udpc_socks_hop_addr("10.0.0.5:1080", &hop);
		udpc_socks_fixup_hop_relay(&relay, &hop);
		TAP_OK(!relay.named && ntohl(r4->sin_addr.s_addr) == 0x0a000005,
		       "a wildcard relay becomes the hop's address");
		TAP_EQ_INT(ntohs(r4->sin_port), 40001, "keeping the relay's port");

		/* Wildcard, named hop: a name, for the hop before to resolve. */
		memset(&relay, 0, sizeof(relay));
		make_v4(r4, "0.0.0.0", 40002);
		udpc_socks_hop_addr("proxy.internal:1080", &hop);
		udpc_socks_fixup_hop_relay(&relay, &hop);
		TAP_OK(relay.named && strcmp(relay.host, "proxy.internal") == 0,
		       "a wildcard relay from a named hop becomes that name");
		TAP_EQ_INT(relay.port, 40002, "with the relay's port");

		/* Loopback, hop given as loopback: same host as the hop
		 * before, so the relay is reachable from there as it is. */
		memset(&relay, 0, sizeof(relay));
		make_v4(r4, "127.0.0.1", 40003);
		udpc_socks_hop_addr("127.0.0.1:1080", &hop);
		udpc_socks_fixup_hop_relay(&relay, &hop);
		TAP_OK(!relay.named && ntohl(r4->sin_addr.s_addr) == INADDR_LOOPBACK &&
		       ntohs(r4->sin_port) == 40003,
		       "a loopback relay from a hop given as loopback is kept");

		/* Loopback, remote numeric hop: the hop's own view. */
		memset(&relay, 0, sizeof(relay));
		make_v4(r4, "127.0.0.1", 40004);
		udpc_socks_hop_addr("10.0.0.5:1080", &hop);
		udpc_socks_fixup_hop_relay(&relay, &hop);
		TAP_OK(!relay.named && ntohl(r4->sin_addr.s_addr) == 0x0a000005 &&
		       ntohs(r4->sin_port) == 40004,
		       "a loopback relay from a remote hop becomes its address");

		/* Loopback, named hop: replaced by the name. */
		memset(&relay, 0, sizeof(relay));
		make_v4(r4, "127.0.0.1", 40005);
		udpc_socks_hop_addr("proxy.internal:1080", &hop);
		udpc_socks_fixup_hop_relay(&relay, &hop);
		TAP_OK(relay.named && relay.port == 40005,
		       "a loopback relay from a named hop becomes the name");

		/* "localhost" is a loopback address (RFC 6761), whatever its
		 * case and with or without the root dot. */
		memset(&relay, 0, sizeof(relay));
		make_v4(r4, "127.0.0.1", 40009);
		udpc_socks_hop_addr("localhost:1080", &hop);
		udpc_socks_fixup_hop_relay(&relay, &hop);
		TAP_OK(!relay.named && ntohl(r4->sin_addr.s_addr) == INADDR_LOOPBACK &&
		       ntohs(r4->sin_port) == 40009,
		       "a loopback relay from a hop given as localhost is kept, "
		       "as an address");

		memset(&relay, 0, sizeof(relay));
		make_v4(r4, "0.0.0.0", 40010);
		udpc_socks_hop_addr("LocalHost.:1080", &hop);
		udpc_socks_fixup_hop_relay(&relay, &hop);
		TAP_OK(!relay.named && ntohl(r4->sin_addr.s_addr) == INADDR_LOOPBACK &&
		       ntohs(r4->sin_port) == 40010,
		       "a wildcard relay from localhost becomes 127.0.0.1, not the "
		       "name");

		memset(&relay, 0, sizeof(relay));
		make_v6(r6, "::", 40011);
		udpc_socks_hop_addr("localhost:1080", &hop);
		udpc_socks_fixup_hop_relay(&relay, &hop);
		TAP_OK(!relay.named && relay.sa.ss_family == AF_INET6 &&
		       IN6_IS_ADDR_LOOPBACK(&r6->sin6_addr) &&
		       ntohs(r6->sin6_port) == 40011,
		       "and an IPv6 wildcard from localhost becomes ::1");

		/* Only "localhost" itself: another name is still a name. */
		memset(&relay, 0, sizeof(relay));
		make_v4(r4, "127.0.0.1", 40012);
		udpc_socks_hop_addr("localhost.example:1080", &hop);
		udpc_socks_fixup_hop_relay(&relay, &hop);
		TAP_OK(relay.named && strcmp(relay.host, "localhost.example") == 0,
		       "a name that merely starts with localhost is a name");

		/* Routable: left alone. */
		memset(&relay, 0, sizeof(relay));
		make_v4(r4, "198.51.100.7", 40006);
		udpc_socks_hop_addr("10.0.0.5:1080", &hop);
		udpc_socks_fixup_hop_relay(&relay, &hop);
		TAP_OK(!relay.named && ntohl(r4->sin_addr.s_addr) == 0xc6336407 &&
		       ntohs(r4->sin_port) == 40006,
		       "a routable relay is left alone");

		/* IPv6: :: and ::1 likewise. */
		memset(&relay, 0, sizeof(relay));
		make_v6(r6, "::", 40007);
		udpc_socks_hop_addr("[2001:db8::7]:1080", &hop);
		udpc_socks_fixup_hop_relay(&relay, &hop);
		TAP_OK(!relay.named && relay.sa.ss_family == AF_INET6 &&
		       r6->sin6_addr.s6_addr[15] == 7 && ntohs(r6->sin6_port) == 40007,
		       "an IPv6 wildcard relay becomes the hop's address");

		memset(&relay, 0, sizeof(relay));
		make_v6(r6, "::1", 40008);
		udpc_socks_hop_addr("[::1]:1080", &hop);
		udpc_socks_fixup_hop_relay(&relay, &hop);
		TAP_OK(!relay.named && IN6_IS_ADDR_LOOPBACK(&r6->sin6_addr) &&
		       ntohs(r6->sin6_port) == 40008,
		       "a ::1 relay from a hop given as ::1 is kept");
	}

	/* ------------------------------------------------------------------ */
	TAP_GROUP("D-44: the family a later hop is declared");
	{
		struct udpc_socks_addr hop;
		struct udpc_socks_hdr bnd;

		udpc_socks_hop_addr("[2001:db8::7]:1080", &hop);
		memset(&bnd, 0, sizeof(bnd));
		make_v4((struct sockaddr_in *)&bnd.addr, "192.0.2.1", 4000);
		bnd.addr_valid = true;
		TAP_EQ_INT(udpc_socks_declared_family(&hop, &bnd), AF_INET6,
		           "a hop given as IPv6 is declared ::, whatever the reply");

		udpc_socks_hop_addr("proxy.internal:1080", &hop);
		TAP_EQ_INT(udpc_socks_declared_family(&hop, NULL), AF_INET,
		           "a named hop with no reply to go on is declared 0.0.0.0");

		memset(&bnd, 0, sizeof(bnd));
		make_v6((struct sockaddr_in6 *)&bnd.addr, "2001:db8::1", 4000);
		bnd.addr_valid = true;
		TAP_EQ_INT(udpc_socks_declared_family(&hop, &bnd), AF_INET6,
		           "a named hop reached over IPv6 is declared ::");

		memset(&bnd, 0, sizeof(bnd));
		make_v6((struct sockaddr_in6 *)&bnd.addr, "::ffff:192.0.2.1", 4000);
		bnd.addr_valid = true;
		TAP_EQ_INT(udpc_socks_declared_family(&hop, &bnd), AF_INET,
		           "a v4-mapped reply counts as IPv4");

		memset(&bnd, 0, sizeof(bnd));
		make_v6((struct sockaddr_in6 *)&bnd.addr, "::", 0);
		bnd.addr_valid = true;
		TAP_EQ_INT(udpc_socks_declared_family(&hop, &bnd), AF_INET,
		           "a reply of :: is not taken as a signal");

		memset(&bnd, 0, sizeof(bnd));
		bnd.atyp = UDPC_ATYP_DOMAIN;
		bnd.addr_valid = false;
		TAP_EQ_INT(udpc_socks_declared_family(&hop, &bnd), AF_INET,
		           "nor is a reply naming a domain");
	}

	/* ------------------------------------------------------------------ */
	TAP_GROUP("FR-CH-05: one header per hop, outermost first");
	{
		struct udpc_socks_chain c3;
		struct sockaddr_in dst;
		uint8_t out[UDPC_SOCKS_CHAIN_HDR_MAX], one[UDPC_SOCKS_HDR_MAX];
		size_t inner = 0;
		ssize_t len;
		/* RFC 1928 §7 three times over, written out by hand: hop 1 reads
		 * the first and sends the rest to hop 2's relay, 10.0.0.5:2000;
		 * hop 2 reads the second and sends the rest to hop 3's relay,
		 * which is a name; hop 3 reads the last and sends the payload to
		 * 192.0.2.1:53. */
		static const uint8_t want[] = {
			0x00, 0x00, 0x00, 0x01, 10, 0, 0, 5, 0x07, 0xd0,
			0x00, 0x00, 0x00, 0x03, 14,
			'p', 'r', 'o', 'x', 'y', '.', 'i', 'n', 't', 'e', 'r', 'n',
			'a', 'l', 0x0b, 0xb8,
			0x00, 0x00, 0x00, 0x01, 192, 0, 2, 1, 0x00, 0x35,
		};

		memset(&c3, 0, sizeof(c3));
		c3.n = 3;
		make_v4((struct sockaddr_in *)&c3.relay[0].sa, "127.0.0.1", 1000);
		make_v4((struct sockaddr_in *)&c3.relay[1].sa, "10.0.0.5", 2000);
		c3.relay[2].named = true;
		snprintf(c3.relay[2].host, sizeof(c3.relay[2].host), "proxy.internal");
		c3.relay[2].port = 3000;
		make_v4(&dst, "192.0.2.1", 53);

		len = udpc_socks_encode_chain(out, sizeof(out), &c3,
		                              (struct sockaddr *)&dst, &inner);
		TAP_EQ_INT(len, (ssize_t)sizeof(want),
		           "three headers: 10 + 21 + 10 bytes");
		TAP_EQ_MEM(out, want, sizeof(want),
		           "byte for byte: hop 2's relay, hop 3's by name, the target");
		TAP_EQ_INT(inner, 31, "the target's header starts after the other two");

		errno = 0;
		TAP_EQ_INT(udpc_socks_encode_chain(out, 20, &c3, (struct sockaddr *)&dst,
		                                   NULL), -1,
		           "a buffer too small for all three is refused");
		TAP_EQ_INT(errno, ENOBUFS, "with ENOBUFS");

		c3.n = 1;
		len = udpc_socks_encode_chain(out, sizeof(out), &c3,
		                              (struct sockaddr *)&dst, &inner);
		TAP_OK(len == udpc_socks_encode(one, sizeof(one), (struct sockaddr *)&dst) &&
		       len > 0 && memcmp(out, one, (size_t)len) == 0 && inner == 0,
		       "a chain of one encodes exactly the single header");
	}

	/* ------------------------------------------------------------------ */
	TAP_GROUP("D-41: every layer of a received datagram is checked");
	{
		struct udpc_socks_chain c3;
		struct udpc_socks_hdr in;
		struct sockaddr_in src, other;
		struct sockaddr_in6 mapped;
		uint8_t pkt[UDPC_SOCKS_CHAIN_HDR_MAX + 16];
		enum udpc_socks_drop why;
		unsigned layer;
		size_t off;
		ssize_t n, h;

		memset(&c3, 0, sizeof(c3));
		c3.n = 3;
		make_v4((struct sockaddr_in *)&c3.relay[0].sa, "127.0.0.1", 1000);
		make_v4((struct sockaddr_in *)&c3.relay[1].sa, "10.0.0.5", 2000);
		c3.relay[2].named = true;
		snprintf(c3.relay[2].host, sizeof(c3.relay[2].host), "proxy.internal");
		c3.relay[2].port = 3000;
		make_v4(&src, "192.0.2.1", 53);


		off = build_reply(pkt, sizeof(pkt), (struct sockaddr *)&c3.relay[1].sa,
		                  NULL, &src);
		h = udpc_socks_decode_chain(pkt, off, &c3, &in, &layer, &why);
		TAP_EQ_INT(h, (ssize_t)off - 4, "a genuine reply decodes, the payload after "
		                                 "all three headers");
		TAP_OK(in.addr_valid && ((struct sockaddr_in *)&in.addr)->sin_port ==
		                            htons(53),
		       "and the source reported is the innermost: the target");

		make_v6(&mapped, "::ffff:10.0.0.5", 2000);
		off = build_reply(pkt, sizeof(pkt), (struct sockaddr *)&mapped,
		                  NULL, &src);
		TAP_OK(udpc_socks_decode_chain(pkt, off, &c3, &in, &layer, &why) > 0,
		       "hop 2's relay reported v4-mapped is the same relay");

		make_v4(&other, "10.0.0.6", 2000);
		off = build_reply(pkt, sizeof(pkt), (struct sockaddr *)&other,
		                  NULL, &src);
		TAP_EQ_INT(udpc_socks_decode_chain(pkt, off, &c3, &in, &layer, &why), -1,
		           "layer 1 from another address is refused");
		TAP_OK(layer == 1 && why == UDPC_DROP_SOURCE,
		       "at layer 1, for its source");

		make_v4(&other, "10.0.0.5", 2001);
		off = build_reply(pkt, sizeof(pkt), (struct sockaddr *)&other,
		                  NULL, &src);
		TAP_EQ_INT(udpc_socks_decode_chain(pkt, off, &c3, &in, &layer, &why), -1,
		           "layer 1 from the right address but another port is refused");

		make_v4(&other, "10.0.0.5", 3001);
		off = build_reply(pkt, sizeof(pkt), (struct sockaddr *)&c3.relay[1].sa,
		                  (struct sockaddr *)&other, &src);
		TAP_EQ_INT(udpc_socks_decode_chain(pkt, off, &c3, &in, &layer, &why), -1,
		           "layer 2, from the wrong port for a relay known by name, "
		           "is refused");
		TAP_OK(layer == 2 && why == UDPC_DROP_SOURCE, "at layer 2");

		/* A layer from a named relay can only be checked by port: its
		 * address would need the name resolved here (D-39, D-41). */
		make_v4(&other, "198.51.100.1", 3000);
		off = build_reply(pkt, sizeof(pkt), (struct sockaddr *)&c3.relay[1].sa,
		                  (struct sockaddr *)&other, &src);
		TAP_OK(udpc_socks_decode_chain(pkt, off, &c3, &in, &layer, &why) > 0,
		       "a named relay's layer is checked by port alone");

		off = build_reply(pkt, sizeof(pkt), (struct sockaddr *)&c3.relay[1].sa,
		                  NULL, &src);
		pkt[10 + 2] = 1; /* layer 2's FRAG */
		TAP_EQ_INT(udpc_socks_decode_chain(pkt, off, &c3, &in, &layer, &why), -1,
		           "FRAG set at a middle layer is refused");
		TAP_OK(layer == 2 && why == UDPC_DROP_FRAG, "at layer 2, for FRAG");

		off = build_reply(pkt, sizeof(pkt), (struct sockaddr *)&c3.relay[1].sa,
		                  NULL, &src);
		pkt[20 + 2] = 1; /* the innermost layer's FRAG */
		h = udpc_socks_decode_chain(pkt, off, &c3, &in, &layer, &why);
		TAP_OK(h > 0 && in.frag == 1,
		       "FRAG at the innermost layer is left in the header, for the "
		       "caller to drop as for a single proxy (FR-P-04)");

		off = build_reply(pkt, sizeof(pkt), (struct sockaddr *)&c3.relay[1].sa,
		                  NULL, &src);
		TAP_EQ_INT(udpc_socks_decode_chain(pkt, 15, &c3, &in, &layer, &why), -1,
		           "a datagram cut short in layer 2 is refused");
		TAP_OK(layer == 2 && why == UDPC_DROP_MALFORMED, "as malformed");
		TAP_EQ_INT(udpc_socks_decode_chain(pkt, 25, &c3, &in, &layer, &why), -1,
		           "and one cut short in the innermost");
		TAP_EQ_INT(layer, 3, "at layer 3");

		/* The defect D-41 exists to prevent: a datagram with fewer layers
		 * than the chain, its header read as the next one's, or its payload
		 * as a header.  One sent straight to hop 1's relay by anyone at all
		 * arrives with hop 1's single layer naming the sender. */
		n = udpc_socks_encode(pkt, sizeof(pkt), (struct sockaddr *)&src);
		memcpy(pkt + n, "data-that-is-not-a-header", 25);
		TAP_EQ_INT(udpc_socks_decode_chain(pkt, (size_t)n + 25, &c3, &in, &layer,
		                                   &why), -1,
		           "a datagram injected at hop 1's relay is refused, not "
		           "delivered with its payload read as headers");

		c3.n = 1;
		n = udpc_socks_encode(pkt, sizeof(pkt), (struct sockaddr *)&src);
		memcpy(pkt + n, "data", 4);
		h = udpc_socks_decode_chain(pkt, (size_t)n + 4, &c3, &in, &layer, &why);
		TAP_OK(h == n && udpc_socks_decode(pkt, (size_t)n + 4, &in) == n,
		       "a chain of one decodes exactly the single header");
	}

	/* ------------------------------------------------------------------ */
	TAP_GROUP("FR-CH-01: a chain of one is 0.1.0's association");
	{
		const char *const one[] = { a };
		struct udpc_socks_conn conn;

		cfg = chain_cfg(one, 1);
		e = 0;
		TAP_EQ_INT(udpc_socks_associate_chain(cfg, NULL, &ch, &e), 0,
		           "a chain of one associates");
		TAP_EQ_INT(ch.n, 1, "with one hop");
		TAP_OK(ch.control_fd[0] >= 0 && !ch.relay[0].named,
		       "one control connection and a numeric relay");
		TAP_EQ_INT(round_trip(&ch, (struct sockaddr *)&echo_sa), 1,
		           "a datagram goes to the target and back");

		TAP_EQ_INT(udpc_socks_associate(cfg, NULL, &conn, &e), 0,
		           "udpc_socks_associate still associates");
		TAP_OK(conn.relay.ss_family == ch.relay[0].sa.ss_family &&
		       udpc_addr_is_loopback((struct sockaddr *)&conn.relay),
		       "with a relay of the same form");
		udpc_socks_disconnect(&conn);
		udpc_socks_disconnect_chain(&ch);
		TAP_OK(chain_is_empty(&ch), "disconnecting empties the chain");

		/* Its diagnostics are 0.1.0's: a dead proxy says nothing, and
		 * the errno is the report. */
		{
			const char *const gone[] = { dead };

			cfg = chain_cfg(gone, 1);
			capture_begin(&saved);
			e = 0;
			TAP_EQ_INT(udpc_socks_associate_chain(cfg, NULL, &ch, &e), -1,
			           "a dead proxy fails");
			capture_end(saved);
			TAP_EQ_INT(e, ECONNREFUSED, "with ECONNREFUSED");
			TAP_EQ_STR(g_stderr, "", "and no hop is named");
		}
	}

	/* ------------------------------------------------------------------ */
	TAP_GROUP("D-37: udpc_socks_associate never runs a chain as its first hop");
	{
		const char *const two[] = { a, c };
		struct udpc_socks_conn conn;

		cfg = chain_cfg(two, 2);
		before = lowest_free_fd();
		e = 0;
		TAP_EQ_INT(udpc_socks_associate(cfg, NULL, &conn, &e), -1,
		           "given a chain of two, it fails");
		TAP_EQ_INT(e, EINVAL, "with EINVAL");
		TAP_EQ_INT(conn.control_fd, -1, "with no control connection");
		TAP_EQ_INT(lowest_free_fd(), before, "and nothing opened");
	}

	/* ------------------------------------------------------------------ */
	TAP_GROUP("FR-CH-03: two hops, the second reached through the first");
	{
		const char *const two[] = { a, c };

		cfg = chain_cfg(two, 2);
		e = 0;
		TAP_EQ_INT(udpc_socks_associate_chain(cfg, NULL, &ch, &e), 0,
		           "a chain of two associates");
		TAP_EQ_INT(ch.n, 2, "with two hops");
		TAP_OK(ch.control_fd[0] >= 0 && ch.control_fd[1] >= 0 &&
		       ch.control_fd[0] != ch.control_fd[1],
		       "and a control connection for each");
		TAP_OK(!ch.relay[1].named &&
		       udpc_addr_is_loopback((struct sockaddr *)&ch.relay[1].sa),
		       "hop 2 was given as loopback, so its loopback relay is kept");
		TAP_OK(udpc_socks_chain_alive(&ch), "the chain is alive");
		TAP_EQ_INT(round_trip(&ch, (struct sockaddr *)&echo_sa), 2,
		           "a datagram crosses both hops and back, every layer "
		           "from the right relay");
		udpc_socks_disconnect_chain(&ch);
		TAP_OK(chain_is_empty(&ch), "disconnecting empties the chain");
	}

	/* ------------------------------------------------------------------ */
	TAP_GROUP("D-38, D-39: three hops, per-hop credentials, a named hop");
	{
		const char *const three[] = { a, b, named_c };

		cfg = chain_cfg(three, 3);
		hop_creds(cfg, 2, "hopuser", "hoppass");
		e = 0;
		TAP_EQ_INT(udpc_socks_associate_chain(cfg, NULL, &ch, &e), 0,
		           "a chain of three associates");
		TAP_EQ_INT(ch.n, 3, "with three hops");
		TAP_OK(!ch.relay[2].named &&
		       udpc_addr_is_loopback((struct sockaddr *)&ch.relay[2].sa),
		       "hop 3 was given as localhost, so its loopback relay is "
		       "kept as an address");
		TAP_EQ_INT(round_trip(&ch, (struct sockaddr *)&echo_sa), 3,
		           "a datagram crosses all three and back");
		udpc_socks_disconnect_chain(&ch);
	}

	/* ------------------------------------------------------------------ */
	TAP_GROUP("D-40: a relay that becomes a name is crossed by name");
	{
		/* This host's own name, if it resolves to an address here: the
		 * hop before resolves it, and every local address reaches the
		 * fixture's relay, which listens on all of them.  The relay comes
		 * back as loopback, so it is replaced by the name. */
		char host[256], spec[300];
		struct addrinfo hints, *res = NULL;
		bool usable = false;

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_DGRAM;
		if (gethostname(host, sizeof(host)) == 0 &&
		    strcasecmp(host, "localhost") != 0 &&
		    getaddrinfo(host, NULL, &hints, &res) == 0 && res != NULL) {
			usable = udpc_addr_is_loopback(res->ai_addr) ||
			         udpc_addr_is_local(res->ai_addr);
			freeaddrinfo(res);
		}

		if (usable) {
			const char *two[2];

			snprintf(spec, sizeof(spec), "%s:%u", host, pc);
			two[0] = a;
			two[1] = spec;
			cfg = chain_cfg(two, 2);
			e = 0;
			TAP_EQ_INT(udpc_socks_associate_chain(cfg, NULL, &ch, &e), 0,
			           "a chain through this host's name associates");
			TAP_OK(ch.relay[1].named && strcmp(ch.relay[1].host, host) == 0,
			       "its loopback relay becomes the name");
			TAP_EQ_INT(round_trip(&ch, (struct sockaddr *)&echo_sa), 2,
			           "a datagram crosses it by name and back, that "
			           "layer checked by port");
			udpc_socks_disconnect_chain(&ch);
		} else {
			TAP_OK(1, "# SKIP this host's name does not resolve to a "
			          "local address");
			TAP_OK(1, "# SKIP");
			TAP_OK(1, "# SKIP");
		}
	}

	/* ------------------------------------------------------------------ */
	TAP_GROUP("FR-CH-03: each hop authenticates with its own credentials");
	{
		const char *const two[] = { a, b };

		cfg = chain_cfg(two, 2);
		before = lowest_free_fd();
		next_report_window();
		capture_begin(&saved);
		e = 0;
		TAP_EQ_INT(udpc_socks_associate_chain(cfg, NULL, &ch, &e), -1,
		           "hop 2 without credentials fails");
		capture_end(saved);
		TAP_EQ_INT(e, EACCES, "with EACCES");
		TAP_OK(strstr(g_stderr, "UDPCHAINS_USERNAME_2") != NULL,
		       "naming hop 2's variables");
		TAP_OK(strstr(g_stderr, "negotiation failed") == NULL,
		       "with no vaguer line after the specific one (D-43)");
		TAP_OK(chain_is_empty(&ch), "leaving no hop");
		TAP_EQ_INT(lowest_free_fd(), before, "and nothing open");

		hop_creds(cfg, 2, "hopuser", "wrong");
		capture_begin(&saved);
		e = 0;
		TAP_EQ_INT(udpc_socks_associate_chain(cfg, NULL, &ch, &e), -1,
		           "a wrong password for hop 2 fails");
		capture_end(saved);
		TAP_EQ_INT(e, EACCES, "with EACCES");
		TAP_OK(strstr(g_stderr, "hop 2 of 2 (") != NULL &&
		       strstr(g_stderr, "rejected the supplied credentials") != NULL,
		       "and the diagnostic names hop 2 (FR-CH-12)");

		/* Hop 1's credentials are not hop 2's. */
		cfg->have_credentials = true;
		snprintf(cfg->username, sizeof(cfg->username), "hopuser");
		snprintf(cfg->password, sizeof(cfg->password), "hoppass");
		cfg->hops[0].have_credentials = false;
		capture_begin(&saved);
		e = 0;
		TAP_EQ_INT(udpc_socks_associate_chain(cfg, NULL, &ch, &e), -1,
		           "hop 1's credentials are not offered to hop 2");
		capture_end(saved);
		TAP_EQ_INT(e, EACCES, "so it still fails");
	}

	/* ------------------------------------------------------------------ */
	TAP_GROUP("D-37: a dead or refusing hop fails the whole chain");
	{
		const char *const dead2[] = { a, dead };
		const char *const dead1[] = { dead, a };
		const char *const noconn1[] = { n_, a };
		const char *const refuse3[] = { a, c, r_ };

		cfg = chain_cfg(dead2, 2);
		before = lowest_free_fd();
		next_report_window();
		capture_begin(&saved);
		e = 0;
		TAP_EQ_INT(udpc_socks_associate_chain(cfg, NULL, &ch, &e), -1,
		           "hop 2 not listening: the chain fails");
		capture_end(saved);
		TAP_EQ_INT(e, ECONNREFUSED,
		           "with ECONNREFUSED, from hop 1's CONNECT reply");
		TAP_OK(strstr(g_stderr, "hop 2 of 2 (") != NULL &&
		       strstr(g_stderr, "hop 1 could not reach it") != NULL,
		       "the diagnostic names hop 2, and hop 1 as what failed "
		       "to reach it");
		TAP_OK(chain_is_empty(&ch), "no hop is left associated");
		TAP_EQ_INT(lowest_free_fd(), before, "and nothing open");

		cfg = chain_cfg(dead1, 2);
		next_report_window();
		capture_begin(&saved);
		e = 0;
		TAP_EQ_INT(udpc_socks_associate_chain(cfg, NULL, &ch, &e), -1,
		           "hop 1 not listening: the chain fails");
		capture_end(saved);
		TAP_EQ_INT(e, ECONNREFUSED, "with ECONNREFUSED");
		TAP_OK(strstr(g_stderr, "hop 1 of 2 (") != NULL,
		       "the diagnostic names hop 1");

		cfg = chain_cfg(noconn1, 2);
		capture_begin(&saved);
		e = 0;
		TAP_EQ_INT(udpc_socks_associate_chain(cfg, NULL, &ch, &e), -1,
		           "hop 1 refusing CONNECT: the chain fails");
		capture_end(saved);
		TAP_EQ_INT(e, EOPNOTSUPP, "with EOPNOTSUPP (command not supported)");
		TAP_OK(chain_is_empty(&ch), "no hop is left associated");

		cfg = chain_cfg(refuse3, 3);
		before = lowest_free_fd();
		next_report_window();
		capture_begin(&saved);
		e = 0;
		TAP_EQ_INT(udpc_socks_associate_chain(cfg, NULL, &ch, &e), -1,
		           "the last hop refusing UDP ASSOCIATE: the chain fails");
		capture_end(saved);
		TAP_EQ_INT(e, ECONNREFUSED, "with ECONNREFUSED (general failure)");
		TAP_OK(strstr(g_stderr, "hop 3 of 3 (") != NULL &&
		       strstr(g_stderr, "UDP ASSOCIATE failed") != NULL,
		       "the diagnostic names hop 3 and UDP ASSOCIATE");
		TAP_OK(chain_is_empty(&ch),
		       "hops 1 and 2, already associated, are released");
		TAP_EQ_INT(lowest_free_fd(), before, "and nothing open");
	}

	/* ------------------------------------------------------------------ */
	TAP_GROUP("D-22: CONNECT tunnels through the whole chain");
	{
		const char *const three[] = { a, b, named_c };
		const char *const one[] = { c };
		uint8_t greet[3] = { 0x05, 0x01, 0x00 }, reply[2] = { 0, 0 };
		struct pollfd pfd;
		int fd;

		/* The target is hop A's own listener: a SOCKS5 greeting sent
		 * down the tunnel and answered proves the stream ends there. */
		cfg = chain_cfg(three, 3);
		hop_creds(cfg, 2, "hopuser", "hoppass");
		e = 0;
		fd = udpc_socks_connect(cfg, (struct sockaddr *)&a_sa, &e);
		TAP_OK(fd >= 0, "a stream through three hops opens");
		if (fd >= 0) {
			pfd.fd = fd;
			pfd.events = POLLIN;
			TAP_OK(write(fd, greet, sizeof(greet)) == sizeof(greet) &&
			       poll(&pfd, 1, 3000) == 1 &&
			       read(fd, reply, sizeof(reply)) == sizeof(reply),
			       "and carries a request and its answer");
			TAP_OK(reply[0] == 0x05 && reply[1] == 0x00,
			       "from the target at the far end");
			close(fd);
		}

		cfg = chain_cfg(one, 1);
		e = 0;
		fd = udpc_socks_connect(cfg, (struct sockaddr *)&a_sa, &e);
		TAP_OK(fd >= 0, "a chain of one opens a stream as before");
		if (fd >= 0)
			close(fd);
	}

	/* ------------------------------------------------------------------ */
	TAP_GROUP("D-45: a chain's setup has a deadline, and chain_timeout sets it");
	{
		struct slow_hop sh;
		struct sockaddr_in la;
		socklen_t ll = sizeof(la);
		struct timespec t0;
		pthread_t th;
		char slow[32];
		long long took;

		sh.step_ms = 800;
		sh.listen_fd = socket(AF_INET, SOCK_STREAM, 0);
		make_v4(&la, "127.0.0.1", 0);
		if (sh.listen_fd < 0 ||
		    bind(sh.listen_fd, (struct sockaddr *)&la, sizeof(la)) != 0 ||
		    listen(sh.listen_fd, 4) != 0 ||
		    getsockname(sh.listen_fd, (struct sockaddr *)&la, &ll) != 0 ||
		    pthread_create(&th, NULL, slow_hop_main, &sh) != 0) {
			perror("slow hop");
			stop_fixtures();
			return 2;
		}
		snprintf(slow, sizeof(slow), "127.0.0.1:%u", ntohs(la.sin_port));

		/* Alone, it is 0.1.0: three steps of 0.8 s, each within the 1 s
		 * connect_timeout, so it succeeds after 2.4 s. */
		{
			const char *const one[] = { slow };

			cfg = chain_cfg(one, 1);
			cfg->connect_timeout_ms = 1000;
			cfg->have_credentials = true;
			snprintf(cfg->username, sizeof(cfg->username), "u");
			snprintf(cfg->password, sizeof(cfg->password), "p");
			e = 0;
			clock_gettime(CLOCK_MONOTONIC, &t0);
			TAP_EQ_INT(udpc_socks_associate_chain(cfg, NULL, &ch, &e), 0,
			           "a slow proxy alone associates: every step is in time");
			took = elapsed_ms(&t0);
			TAP_OK(took >= 2300, "taking as long as its steps (%lld ms)", took);
			udpc_socks_disconnect_chain(&ch);
		}

		/* chain_timeout raises a chain's deadline, or with 0 lifts it:
		 * hop 2's 2.4 s then fits. */
		{
			const char *const two[] = { a, slow };
			static const char *const values[] = { "3500", "0" };
			unsigned i;

			for (i = 0; i < 2; i++) {
				const char *err = NULL;

				cfg = chain_cfg(two, 2);
				cfg->connect_timeout_ms = 1000;
				hop_creds(cfg, 2, "u", "p");
				TAP_EQ_INT(udpc_config_set(cfg, "chain_timeout", values[i], &err),
				           0, "chain_timeout %s is accepted", values[i]);
				e = 0;
				clock_gettime(CLOCK_MONOTONIC, &t0);
				TAP_EQ_INT(udpc_socks_associate_chain(cfg, NULL, &ch, &e), 0,
				           "with chain_timeout %s, the slow hop 2 of 2 "
				           "associates (%s)",
				           values[i], strerror(e));
				took = elapsed_ms(&t0);
				TAP_OK(took >= 2300, "past the default 2 s (%lld ms)", took);
				udpc_socks_disconnect_chain(&ch);
			}
		}

		/* Set, chain_timeout applies to a chain of one too. */
		{
			const char *const one[] = { slow };
			const char *err = NULL;

			cfg = chain_cfg(one, 1);
			cfg->connect_timeout_ms = 1000;
			cfg->have_credentials = true;
			snprintf(cfg->username, sizeof(cfg->username), "u");
			snprintf(cfg->password, sizeof(cfg->password), "p");
			udpc_config_set(cfg, "chain_timeout", "1500", &err);
			e = 0;
			clock_gettime(CLOCK_MONOTONIC, &t0);
			TAP_EQ_INT(udpc_socks_associate_chain(cfg, NULL, &ch, &e), -1,
			           "with chain_timeout 1500, the slow proxy alone is "
			           "cut off");
			took = elapsed_ms(&t0);
			TAP_EQ_INT(e, ETIMEDOUT, "with ETIMEDOUT");
			TAP_OK(took >= 1400 && took < 1800, "at 1.5 s (%lld ms)", took);
			TAP_OK(chain_is_empty(&ch), "with nothing left associated");
			udpc_socks_disconnect_chain(&ch);
			/* The slow hop is still part-way through that
			 * handshake; let it finish before the next one. */
			usleep(1200 * 1000);
		}

		/* As hop 2 of 2, the same steps overrun the chain's 2 s. */
		{
			const char *const two[] = { a, slow };

			cfg = chain_cfg(two, 2);
			cfg->connect_timeout_ms = 1000;
			hop_creds(cfg, 2, "u", "p");
			next_report_window();
			capture_begin(&saved);
			e = 0;
			clock_gettime(CLOCK_MONOTONIC, &t0);
			TAP_EQ_INT(udpc_socks_associate_chain(cfg, NULL, &ch, &e), -1,
			           "as hop 2 of 2, it is cut off by the chain's deadline");
			took = elapsed_ms(&t0);
			capture_end(saved);
			TAP_EQ_INT(e, ETIMEDOUT, "with ETIMEDOUT");
			TAP_OK(took >= 1800 && took < 2300,
			       "at 2 s, connect_timeout for each of its hops (%lld ms)",
			       took);
			TAP_OK(strstr(g_stderr, "hop 2 of 2 (") != NULL,
			       "naming hop 2 as where the time ran out");
			TAP_OK(chain_is_empty(&ch), "with nothing left associated");
			/* Had it associated after all, the slow hop would hold
			 * its connection open, and the join below would wait. */
			udpc_socks_disconnect_chain(&ch);
		}

		shutdown(sh.listen_fd, SHUT_RDWR);
		close(sh.listen_fd);
		pthread_join(th, NULL);
	}

	/* ------------------------------------------------------------------ */
	TAP_GROUP("FR-CH-09: losing any hop loses the chain");
	{
		const char *const two[] = { a, x_ };

		/* The second hop drops its association after a second idle.
		 * Its end of the tunnel closes, and hop 1 carries that back. */
		cfg = chain_cfg(two, 2);
		e = 0;
		TAP_EQ_INT(udpc_socks_associate_chain(cfg, NULL, &ch, &e), 0,
		           "a chain whose last hop expires associates");
		TAP_OK(udpc_socks_chain_alive(&ch), "and is alive at first");
		{
			int i;

			for (i = 0; i < 40 && udpc_socks_chain_alive(&ch); i++)
				usleep(100 * 1000);
		}
		TAP_OK(!udpc_socks_chain_alive(&ch),
		       "once hop 2 expires it, the chain is not alive");
		{
			struct udpc_socks_conn first;

			first.control_fd = ch.control_fd[0];
			TAP_OK(udpc_socks_control_alive(&first),
			       "although hop 1's own association is still up");
		}
		udpc_socks_disconnect_chain(&ch);
		TAP_OK(!udpc_socks_chain_alive(&ch), "an empty chain is not alive");
	}

	close(hold);
	stop_fixtures();
	TAP_DONE();
}

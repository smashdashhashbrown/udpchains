/* test_chain.c -- chain setup against chained fixtures (FR-CH-01 to FR-CH-04,
 * FR-CH-07, FR-CH-09, FR-CH-12; D-37 to D-40).
 *
 * Links the shim's objects directly, like the other unit tests, and starts its
 * own fixture proxies from the directory it was built in, so it runs the same
 * under the suite and under the sanitisers.
 *
 * The datagram path does not carry chains yet (step 4 of
 * docs/FUTURE-UDP-CHAINS.md §7), so the round trips here wrap and unwrap the
 * layers by hand with the single-header codec.  What they prove is that the
 * relays chain setup returns are the ones a datagram must take.
 *
 * usage: test_chain           (from the build directory, or by path)
 */
#include "tap.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
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
		TAP_OK(ch.relay[2].named && strcmp(ch.relay[2].host, "localhost") == 0,
		       "hop 3 was given by name, so its loopback relay is that name");
		TAP_EQ_INT(round_trip(&ch, (struct sockaddr *)&echo_sa), 3,
		           "a datagram crosses all three and back, the named "
		           "relay's layer checked by port");
		udpc_socks_disconnect_chain(&ch);
	}

	/* ------------------------------------------------------------------ */
	TAP_GROUP("FR-CH-03: each hop authenticates with its own credentials");
	{
		const char *const two[] = { a, b };

		cfg = chain_cfg(two, 2);
		before = lowest_free_fd();
		capture_begin(&saved);
		e = 0;
		TAP_EQ_INT(udpc_socks_associate_chain(cfg, NULL, &ch, &e), -1,
		           "hop 2 without credentials fails");
		capture_end(saved);
		TAP_EQ_INT(e, EACCES, "with EACCES");
		TAP_OK(strstr(g_stderr, "UDPCHAINS_USERNAME_2") != NULL,
		       "naming hop 2's variables");
		TAP_OK(chain_is_empty(&ch), "leaving no hop");
		TAP_EQ_INT(lowest_free_fd(), before, "and nothing open");

		hop_creds(cfg, 2, "hopuser", "wrong");
		capture_begin(&saved);
		e = 0;
		TAP_EQ_INT(udpc_socks_associate_chain(cfg, NULL, &ch, &e), -1,
		           "a wrong password for hop 2 fails");
		capture_end(saved);
		TAP_EQ_INT(e, EACCES, "with EACCES");
		TAP_OK(strstr(g_stderr, "hop 2 of 2 (") != NULL,
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

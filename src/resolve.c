#include "resolve.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

#include "addr.h"
#include "assoc.h"
#include "fdtable.h"
#include "guard.h"
#include "log.h"
#include "real.h"
#include "shim.h"
#include "socks5.h"

/* DESIGN.md §11.3: a small pool of shim-owned associations, each used by one
 * lookup at a time.  Not one shared association: a proxy pins an association
 * to the first local socket that sends on it (§0.5), so concurrent lookups
 * could share one only through a reply demultiplexer. */
#define POOL_MAX 4
#define ATTEMPTS 2
#define UDP_RX_MAX 4096
#define TCP_MSG_MAX 65535

struct pool_ent {
	bool used;  /* holds a live association */
	bool busy;  /* owned by a lookup, or being established */
	bool stale; /* inherited across fork: close, never use */
	struct udpc_socks_chain chain; /* a control connection per hop */
	int udp_fd;
	long last_used; /* CLOCK_MONOTONIC seconds */
};

static struct pool_ent g_pool[POOL_MAX];
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cv;
static pthread_once_t g_once = PTHREAD_ONCE_INIT;

/* One query in flight, and where its answer goes. */
struct xfer {
	const uint8_t *query;
	size_t qlen;
	uint8_t *ans;
	size_t anscap;
	size_t anslen;
	bool done;
	bool need_tcp; /* the UDP answer was truncated */
};

/* --- time and randomness --------------------------------------------------- */

static long long now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

uint16_t udpc_resolve_random_id(void)
{
	uint16_t id;

	/* The ID is the main defence against a forged answer on the relay leg
	 * (D-22), so it comes from the kernel's CSPRNG. */
	if (getrandom(&id, sizeof(id), GRND_NONBLOCK) == (ssize_t)sizeof(id))
		return id;
	return (uint16_t)(now_ms() ^ (long long)(uintptr_t)&id);
}

/* --- the pool -------------------------------------------------------------- */

static void atfork_prepare(void)
{
	pthread_mutex_lock(&g_mu);
}

static void atfork_parent(void)
{
	pthread_mutex_unlock(&g_mu);
}

static void cond_init(void)
{
	pthread_condattr_t ca;

	pthread_condattr_init(&ca);
	pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
	pthread_cond_init(&g_cv, &ca);
	pthread_condattr_destroy(&ca);
}

/* The child is single-threaded.  Every entry belongs to the parent: its control
 * connection is the parent's association, and a lookup that held it lives on
 * only in a thread that did not survive the fork. */
static void ent_close(struct pool_ent *e);

static void atfork_child(void)
{
	int i;

	/* D-31: the child's copies are closed at once, so the parent's
	 * associations are released at the proxy when the parent is done with
	 * them rather than when the last child exits.  close() is safe here;
	 * the parent keeps its own copies. */
	for (i = 0; i < POOL_MAX; i++) {
		g_pool[i].busy = false;
		if (g_pool[i].used)
			ent_close(&g_pool[i]);
	}
	cond_init();
	pthread_mutex_unlock(&g_mu);
}

static void init_once(void)
{
	cond_init();
	(void)pthread_atfork(atfork_prepare, atfork_parent, atfork_child);
}

static void ent_close(struct pool_ent *e)
{
	unsigned k;

	udpc_fd_shim_close(e->udp_fd);
	for (k = 0; k < e->chain.n && k < UDPC_CHAIN_MAX; k++)
		udpc_fd_shim_close(e->chain.control_fd[k]);
	e->udp_fd = -1;
	e->chain.n = 0;
	e->used = e->stale = false;
}

/* Opens a UDP association through every hop of the chain, and a socket
 * connected to hop 1's relay (FR-CH-11).  The handshake is the shim's own
 * traffic, so it runs under the re-entry guard (guard.h). */
static int ent_establish(const struct udpc_config *cfg, struct pool_ent *e,
                         int *err)
{
	struct udpc_socks_chain ch;
	const struct sockaddr *relay;
	char rbuf[UDPC_SOCKS_CHAIN_PATH_MAX], dbuf[UDPC_ADDRSTRLEN];
	socklen_t rlen;
	unsigned k;
	int udp, rc;

	UDPC_GUARD_ENTER();
	rc = udpc_socks_associate_chain(cfg, NULL, &ch, err);
	UDPC_GUARD_LEAVE();
	if (rc != 0)
		return -1;

	relay = (const struct sockaddr *)&ch.relay[0].sa;
	rlen = udpc_sa_len(relay);
	udp = REAL_SOCKET(relay->sa_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (udp < 0 || rlen == 0 || REAL_CONNECT(udp, relay, rlen) != 0) {
		*err = (udp < 0 || rlen == 0) ? (udp < 0 ? errno : EAFNOSUPPORT)
		                              : errno;
		if (udp >= 0)
			REAL_CLOSE(udp);
		for (k = 0; k < ch.n; k++)
			REAL_CLOSE(ch.control_fd[k]);
		return -1;
	}

	/* All are the shim's own descriptors, kept out of the application's
	 * way and out of its close-all loops (D-26). */
	e->chain = ch;
	for (k = 0; k < ch.n; k++)
		e->chain.control_fd[k] = udpc_fd_shim_adopt(ch.control_fd[k]);
	e->udp_fd = udpc_fd_shim_adopt(udp);
	e->used = true;
	e->stale = false;
	e->last_used = (long)(now_ms() / 1000);

	/* FR-C-06: one line per association, resolver ones included, naming
	 * every hop's relay (FR-CH-12). */
	udpc_socks_chain_path(&e->chain, rbuf, sizeof(rbuf));
	udpc_info("resolver association up: dns %s via relay %s",
	          udpc_addr_str((const struct sockaddr *)&cfg->dns, dbuf,
	                        sizeof(dbuf)),
	          rbuf);
	return 0;
}

/* Takes an entry for exclusive use, establishing one if none is free and the
 * pool has room, else waiting for one until the deadline.  Returns its index,
 * or -1 with *err set. */
static int acquire(const struct udpc_config *cfg, long long deadline, int *err)
{
	pthread_mutex_lock(&g_mu);
	for (;;) {
		int i, empty = -1;
		struct timespec ts;

		for (i = 0; i < POOL_MAX; i++) {
			struct pool_ent *e = &g_pool[i];

			if (e->busy)
				continue;
			if (e->used && e->stale)
				ent_close(e);
			if (e->used) {
				e->busy = true;
				pthread_mutex_unlock(&g_mu);
				return i;
			}
			if (empty < 0)
				empty = i;
		}

		if (empty >= 0) {
			struct pool_ent *e = &g_pool[empty];

			e->busy = true;
			e->chain.n = 0;
			e->udp_fd = -1;
			pthread_mutex_unlock(&g_mu);
			if (ent_establish(cfg, e, err) == 0)
				return empty;
			pthread_mutex_lock(&g_mu);
			e->busy = false;
			pthread_cond_broadcast(&g_cv);
			pthread_mutex_unlock(&g_mu);
			return -1;
		}

		ts.tv_sec = (time_t)(deadline / 1000);
		ts.tv_nsec = (long)(deadline % 1000) * 1000000L;
		if (pthread_cond_timedwait(&g_cv, &g_mu, &ts) == ETIMEDOUT) {
			pthread_mutex_unlock(&g_mu);
			*err = ETIMEDOUT;
			return -1;
		}
	}
}

static void release(int i, bool broken)
{
	struct pool_ent *e = &g_pool[i];

	pthread_mutex_lock(&g_mu);
	if (broken && e->used)
		ent_close(e);
	else
		e->last_used = (long)(now_ms() / 1000);
	e->busy = false;
	pthread_cond_signal(&g_cv);
	pthread_mutex_unlock(&g_mu);
}

/* FR-P-08, for the pool: an entry idle long enough to have been expired by the
 * proxy is checked before use, and replaced if any hop has dropped it
 * (FR-CH-09). */
static int revalidate(const struct udpc_config *cfg, struct pool_ent *e, int *err)
{
	if ((long)(now_ms() / 1000) - e->last_used < UDPC_IDLE_PROBE_SECS)
		return 0;
	if (udpc_socks_chain_alive(&e->chain))
		return 0;

	udpc_debug("resolver association expired by the proxy; re-associating");
	ent_close(e);
	return ent_establish(cfg, e, err);
}

/* --- transport ------------------------------------------------------------- */

static bool association_gone(int e)
{
	return e == ECONNREFUSED || e == ENOTCONN || e == EPIPE ||
	       e == ECONNRESET || e == EHOSTUNREACH || e == ENETUNREACH;
}

/* True if a relayed datagram's SOCKS source is the configured resolver.  Both
 * sides are normalised to the resolver's family first: a proxy may report an
 * IPv4 origin to a client that named it v4-mapped, or the reverse (D-14). */
static bool from_resolver(const struct sockaddr *src, const struct udpc_config *cfg)
{
	struct sockaddr_storage norm;

	if (udpc_addr_for_family(src, cfg->dns.ss_family, &norm) != 0)
		return false;
	return udpc_addr_equal((const struct sockaddr *)&norm,
	                       (const struct sockaddr *)&cfg->dns);
}

static void deliver(struct xfer *x, const uint8_t *msg, size_t len)
{
	size_t take = len < x->anscap ? len : x->anscap;

	memcpy(x->ans, msg, take);
	/* Cut short to fit the caller's buffer: say so the way DNS does. */
	if (take < len && take > 2)
		x->ans[2] |= 0x02;
	x->anslen = take;
	x->done = true;
}

/* Sends every unanswered query over the entry's association and collects
 * replies, retransmitting once, until each is answered or the deadline passes.
 * Returns 0 when all are done, or -1 with *err set; *broken says the
 * association itself failed, so a fresh one may succeed. */
static int udp_exchange(const struct udpc_config *cfg, struct pool_ent *e,
                        struct xfer *x, size_t nx, long long deadline,
                        bool *broken, int *err)
{
	uint8_t hdr[UDPC_SOCKS_CHAIN_HDR_MAX];
	/* Room for an answer as a chain of one has always had it, plus a
	 * header for each later hop. */
	uint8_t rx[UDP_RX_MAX + UDPC_SOCKS_CHAIN_HDR_MAX - UDPC_SOCKS_HDR_MAX];
	size_t rxcap = UDP_RX_MAX + (e->chain.n - 1) * UDPC_SOCKS_HDR_MAX;
	ssize_t hl;
	size_t i;
	int attempt;

	hl = udpc_socks_encode_chain(hdr, sizeof(hdr), &e->chain,
	                             (const struct sockaddr *)&cfg->dns, NULL);
	if (hl < 0) {
		*err = errno;
		return -1;
	}

	for (attempt = 0; attempt < ATTEMPTS; attempt++) {
		long long now = now_ms(), adl;
		size_t pending = 0;

		if (now >= deadline)
			break;
		adl = now + (deadline - now) / (ATTEMPTS - attempt);

		for (i = 0; i < nx; i++) {
			struct iovec v[2];
			struct msghdr m;

			if (x[i].done)
				continue;
			pending++;
			v[0].iov_base = hdr;
			v[0].iov_len = (size_t)hl;
			v[1].iov_base = (void *)(uintptr_t)x[i].query;
			v[1].iov_len = x[i].qlen;
			memset(&m, 0, sizeof(m));
			m.msg_iov = v;
			m.msg_iovlen = 2;
			if (REAL_SENDMSG(e->udp_fd, &m, MSG_NOSIGNAL | MSG_DONTWAIT) < 0 &&
			    association_gone(errno)) {
				*broken = true;
				*err = errno;
				return -1;
			}
		}
		if (pending == 0)
			return 0;

		while (pending > 0 && (now = now_ms()) < adl) {
			struct pollfd pfd[1 + UDPC_CHAIN_MAX];
			struct udpc_socks_hdr sh;
			enum udpc_socks_drop why;
			unsigned k, layer;
			ssize_t n, sl;
			size_t len;
			bool clipped, gone = false;

			pfd[0].fd = e->udp_fd;
			pfd[0].events = POLLIN;
			pfd[0].revents = 0;
			for (k = 0; k < e->chain.n; k++) {
				pfd[1 + k].fd = e->chain.control_fd[k];
				pfd[1 + k].events = POLLRDHUP;
				pfd[1 + k].revents = 0;
			}
			if (poll(pfd, 1 + e->chain.n, (int)(adl - now)) < 0) {
				if (errno == EINTR)
					continue;
				*err = errno;
				return -1;
			}
			/* Each hop ties its association to its control
			 * connection (§0.5); once any closes, no reply is
			 * coming (FR-CH-09). */
			for (k = 0; k < e->chain.n; k++)
				if (pfd[1 + k].revents &
				    (POLLRDHUP | POLLHUP | POLLERR | POLLNVAL))
					gone = true;
			if (gone) {
				*broken = true;
				*err = ECONNRESET;
				return -1;
			}
			if (!(pfd[0].revents & (POLLIN | POLLERR)))
				continue;

			n = REAL_RECV(e->udp_fd, rx, rxcap, MSG_DONTWAIT | MSG_TRUNC);
			if (n < 0) {
				if (association_gone(errno)) {
					*broken = true;
					*err = errno;
					return -1;
				}
				continue;
			}
			clipped = (size_t)n > rxcap;
			len = clipped ? rxcap : (size_t)n;

			/* Everything below is untrusted: from the relay, but
			 * claiming to be from the resolver.  Every layer must
			 * come from the hop it names (D-41), the innermost must
			 * say it is from the resolver, and the answer must then
			 * match an outstanding query exactly (dns.h), or it is
			 * dropped. */
			sl = udpc_socks_decode_chain(rx, len, &e->chain, &sh, &layer,
			                             &why);
			if (sl < 0 || sh.frag != 0 || !sh.addr_valid ||
			    !from_resolver((const struct sockaddr *)&sh.addr, cfg))
				continue;

			for (i = 0; i < nx; i++) {
				const uint8_t *msg = rx + sl;
				size_t mlen = len - (size_t)sl;

				if (x[i].done ||
				    !udpc_dns_answers(x[i].query, x[i].qlen, msg, mlen))
					continue;
				if (clipped || (msg[2] & 0x02)) {
					/* D-22: a truncated answer is never used;
					 * the query is repeated over TCP. */
					x[i].need_tcp = true;
					x[i].done = true;
				} else {
					deliver(&x[i], msg, mlen);
				}
				pending--;
				break;
			}
		}
	}

	for (i = 0; i < nx; i++)
		if (!x[i].done) {
			*err = ETIMEDOUT;
			return -1;
		}
	return 0;
}

static int stream_io(int fd, uint8_t *buf, size_t len, bool writing,
                     long long deadline)
{
	size_t off = 0;

	while (off < len) {
		struct pollfd pfd;
		long long now = now_ms();
		ssize_t n;

		if (now >= deadline) {
			errno = ETIMEDOUT;
			return -1;
		}
		pfd.fd = fd;
		pfd.events = writing ? POLLOUT : POLLIN;
		pfd.revents = 0;
		if (poll(&pfd, 1, (int)(deadline - now)) < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		n = writing ? REAL_WRITE(fd, buf + off, len - off)
		            : REAL_READ(fd, buf + off, len - off);
		if (n > 0) {
			off += (size_t)n;
			continue;
		}
		if (n == 0) {
			errno = ECONNRESET;
			return -1;
		}
		if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
			return -1;
	}
	return 0;
}

/* D-22: a truncated UDP answer is repeated as DNS over TCP (RFC 1035 §4.2.2,
 * two-byte length prefix), through the proxy with SOCKS5 CONNECT.  A proxy
 * that refuses CONNECT fails the lookup; nothing is ever sent directly. */
static int tcp_exchange(const struct udpc_config *cfg, struct xfer *x,
                        long long deadline, int *err)
{
	uint8_t len2[2];
	uint8_t *buf;
	size_t want;
	int fd, rc = -1;

	if (x->qlen > TCP_MSG_MAX) {
		*err = EMSGSIZE;
		return -1;
	}

	UDPC_GUARD_ENTER();
	fd = udpc_socks_connect(cfg, (const struct sockaddr *)&cfg->dns, err);
	UDPC_GUARD_LEAVE();
	if (fd < 0) {
		udpc_debug("resolver TCP fallback: CONNECT through the proxy "
		           "failed (%s)",
		           strerror(*err));
		return -1;
	}
	fd = udpc_fd_shim_adopt(fd);

	buf = malloc(TCP_MSG_MAX);
	if (buf == NULL) {
		*err = ENOMEM;
		goto out;
	}

	udpc_dns_put16(len2, (uint16_t)x->qlen);
	memcpy(buf, x->query, x->qlen);
	if (stream_io(fd, len2, 2, true, deadline) != 0 ||
	    stream_io(fd, buf, x->qlen, true, deadline) != 0 ||
	    stream_io(fd, len2, 2, false, deadline) != 0) {
		*err = errno;
		goto out;
	}
	want = udpc_dns_get16(len2);
	if (want < UDPC_DNS_HDR_LEN || stream_io(fd, buf, want, false, deadline) != 0) {
		*err = want < UDPC_DNS_HDR_LEN ? EPROTO : errno;
		goto out;
	}
	if (!udpc_dns_answers(x->query, x->qlen, buf, want)) {
		*err = EPROTO;
		goto out;
	}
	deliver(x, buf, want);
	x->need_tcp = false;
	rc = 0;
out:
	free(buf);
	udpc_fd_shim_close(fd);
	return rc;
}

static void note_no_dns(void)
{
	static atomic_flag once = ATOMIC_FLAG_INIT;

	if (!atomic_flag_test_and_set(&once))
		udpc_err("a name lookup needs DNS, but no resolver is configured "
		         "(set 'dns = <ip>' or UDPCHAINS_DNS); refusing to "
		         "resolve names directly (D-22)");
}

/* Runs a set of queries to completion.  Returns 0 with every answer delivered,
 * or -1 with *st set.  There is no path from here to a direct query. */
static int transact(struct xfer *x, size_t nx, enum udpc_res_status *st)
{
	const struct udpc_config *cfg = udpc_shim_config();
	long long deadline;
	int err = 0, rc = -1, tries;
	size_t i;

	if (cfg == NULL) {
		/* The shim already reported why it is unconfigured. */
		*st = UDPC_RES_FAIL;
		return -1;
	}
	if (!cfg->dns_set) {
		note_no_dns();
		*st = UDPC_RES_FAIL;
		return -1;
	}

	pthread_once(&g_once, init_once);
	deadline = now_ms() + cfg->dns_timeout_ms;

	/* A second try only after the association itself broke -- the proxy
	 * expired it between our check and our send.  A plain timeout means
	 * the resolver is not answering, and trying again cannot help. */
	for (tries = 0; tries < 2; tries++) {
		bool broken = false;
		int i_ent = acquire(cfg, deadline, &err);

		if (i_ent < 0)
			break;
		if (revalidate(cfg, &g_pool[i_ent], &err) != 0) {
			release(i_ent, true);
			break;
		}
		rc = udp_exchange(cfg, &g_pool[i_ent], x, nx, deadline, &broken, &err);
		release(i_ent, broken);
		if (rc == 0 || !broken)
			break;
		udpc_debug("resolver association failed (%s); retrying on a "
		           "fresh one",
		           strerror(err));
	}
	if (rc != 0) {
		udpc_debug("name lookup through the proxy failed: %s", strerror(err));
		*st = UDPC_RES_AGAIN;
		return -1;
	}

	for (i = 0; i < nx; i++) {
		if (!x[i].need_tcp)
			continue;
		udpc_debug("resolver answer truncated; repeating over TCP");
		if (tcp_exchange(cfg, &x[i], deadline, &err) != 0) {
			*st = UDPC_RES_AGAIN;
			return -1;
		}
	}
	*st = UDPC_RES_OK;
	return 0;
}

/* --- local sources --------------------------------------------------------- */

static void strip_dot(const char *in, char *out, size_t outlen)
{
	size_t l;

	snprintf(out, outlen, "%s", in);
	l = strlen(out);
	if (l > 1 && out[l - 1] == '.')
		out[l - 1] = '\0';
}

/* RFC 6761 §6.3: localhost and every name under it are loopback, and are never
 * sent to a resolver. */
static bool is_localhost(const char *name)
{
	size_t l = strlen(name);

	if (strcasecmp(name, "localhost") == 0)
		return true;
	return l > 10 && strcasecmp(name + l - 10, ".localhost") == 0;
}

static void add_addr(struct udpc_res_result *out, int family, const void *bytes)
{
	if (out->naddr >= UDPC_RES_MAX_ADDRS)
		return;
	out->addr[out->naddr].family = family;
	memset(out->addr[out->naddr].bytes, 0, 16);
	memcpy(out->addr[out->naddr].bytes, bytes, family == AF_INET ? 4 : 16);
	out->naddr++;
}

/* Parses one hosts-file line in place: returns the address token, and leaves
 * *names pointing at the rest.  NULL for a blank or comment line. */
static char *hosts_line(char *line, char **names)
{
	char *hash = strchr(line, '#'), *addr, *save = NULL;

	if (hash != NULL)
		*hash = '\0';
	addr = strtok_r(line, " \t\r\n", &save);
	*names = save;
	return addr;
}

static bool hosts_lookup(const char *path, const char *name, unsigned want,
                         struct udpc_res_result *out)
{
	char line[1024];
	FILE *f = fopen(path, "re");

	if (f == NULL)
		return false;
	while (fgets(line, sizeof(line), f) != NULL) {
		char *names, *tok, *save = NULL, *first = NULL;
		char *addr = hosts_line(line, &names);
		uint8_t b[16];
		bool match = false;

		if (addr == NULL || names == NULL)
			continue;
		for (tok = strtok_r(names, " \t\r\n", &save); tok != NULL;
		     tok = strtok_r(NULL, " \t\r\n", &save)) {
			if (first == NULL)
				first = tok;
			if (strcasecmp(tok, name) == 0)
				match = true;
		}
		if (!match)
			continue;

		if (inet_pton(AF_INET, addr, b) == 1) {
			if (!(want & UDPC_RES_WANT_A))
				continue;
			add_addr(out, AF_INET, b);
		} else if (inet_pton(AF_INET6, addr, b) == 1) {
			if (!(want & UDPC_RES_WANT_AAAA))
				continue;
			add_addr(out, AF_INET6, b);
		} else {
			continue;
		}
		if (out->canon[0] == '\0')
			snprintf(out->canon, sizeof(out->canon), "%s", first);
	}
	fclose(f);
	return out->naddr > 0;
}

/* The address bytes to compare for a reverse lookup: IPv4 for AF_INET and for
 * a v4-mapped AF_INET6, else the sixteen IPv6 bytes. */
static int addr_bytes(const struct sockaddr *sa, uint8_t *b)
{
	if (sa->sa_family == AF_INET) {
		memcpy(b, &((const struct sockaddr_in *)sa)->sin_addr, 4);
		return AF_INET;
	}
	if (sa->sa_family == AF_INET6) {
		const struct in6_addr *a6 = &((const struct sockaddr_in6 *)sa)->sin6_addr;
		if (IN6_IS_ADDR_V4MAPPED(a6)) {
			memcpy(b, &a6->s6_addr[12], 4);
			return AF_INET;
		}
		memcpy(b, a6, 16);
		return AF_INET6;
	}
	return -1;
}

static bool hosts_reverse(const char *path, const struct sockaddr *sa, char *name)
{
	char line[1024];
	uint8_t want[16];
	int fam = addr_bytes(sa, want);
	FILE *f;

	if (fam < 0 || (f = fopen(path, "re")) == NULL)
		return false;
	while (fgets(line, sizeof(line), f) != NULL) {
		char *names, *save = NULL, *first;
		char *addr = hosts_line(line, &names);
		uint8_t b[16];

		if (addr == NULL || names == NULL ||
		    inet_pton(fam, addr, b) != 1 ||
		    memcmp(b, want, fam == AF_INET ? 4 : 16) != 0)
			continue;
		first = strtok_r(names, " \t\r\n", &save);
		if (first == NULL)
			continue;
		snprintf(name, UDPC_DNS_NAME_MAX, "%s", first);
		fclose(f);
		return true;
	}
	fclose(f);
	return false;
}

static const char *hosts_path(void)
{
	const struct udpc_config *cfg = udpc_shim_config();

	return cfg != NULL ? cfg->hosts_file : UDPC_DEFAULT_HOSTS_FILE;
}

/* --- lookups --------------------------------------------------------------- */

size_t udpc_resolve_candidates(const char *name, char (*out)[UDPC_DNS_NAME_MAX],
                               size_t max)
{
	const struct udpc_config *cfg = udpc_shim_config();
	size_t n = 0;

	if (max == 0)
		return 0;

	/* D-22: search domains apply only when opted in, and only to a single
	 * label.  A dotted name is looked up exactly as given. */
	if (cfg != NULL && cfg->dns_search[0] != '\0' && strchr(name, '.') == NULL) {
		char list[sizeof(cfg->dns_search)];
		char *save = NULL, *dom;

		snprintf(list, sizeof(list), "%s", cfg->dns_search);
		for (dom = strtok_r(list, " ,\t", &save); dom != NULL && n < max;
		     dom = strtok_r(NULL, " ,\t", &save)) {
			int w = snprintf(out[n], UDPC_DNS_NAME_MAX, "%s.%s", name, dom);
			if (w > 0 && w < UDPC_DNS_NAME_MAX)
				n++;
		}
	}
	if (n == 0) {
		snprintf(out[0], UDPC_DNS_NAME_MAX, "%s", name);
		n = 1;
	}
	return n;
}

/* One name, through the proxy: A and/or AAAA, sent together. */
static enum udpc_res_status dns_lookup(const char *name, unsigned want,
                                       struct udpc_res_result *out)
{
	uint8_t q[2][UDPC_DNS_QUERY_MAX];
	uint16_t types[2];
	struct xfer x[2];
	struct udpc_dns_result *r;
	enum udpc_res_status st;
	bool nxdomain = false, again = false;
	size_t nx = 0, i;

	memset(x, 0, sizeof(x));
	if (want & UDPC_RES_WANT_A)
		types[nx++] = UDPC_DNS_TYPE_A;
	if (want & UDPC_RES_WANT_AAAA)
		types[nx++] = UDPC_DNS_TYPE_AAAA;
	if (nx == 0)
		return UDPC_RES_NODATA;

	for (i = 0; i < nx; i++) {
		ssize_t ql = udpc_dns_build_query(q[i], sizeof(q[i]),
		                                  udpc_resolve_random_id(), name,
		                                  UDPC_DNS_CLASS_IN, types[i],
		                                  UDPC_DNS_EDNS_SIZE);
		if (ql < 0)
			return UDPC_RES_NONAME; /* not a name DNS can carry */
		x[i].query = q[i];
		x[i].qlen = (size_t)ql;
		x[i].anscap = TCP_MSG_MAX;
		x[i].ans = malloc(TCP_MSG_MAX);
		if (x[i].ans == NULL) {
			st = UDPC_RES_AGAIN;
			goto out;
		}
	}

	if (transact(x, nx, &st) != 0)
		goto out;

	r = malloc(sizeof(*r));
	if (r == NULL) {
		st = UDPC_RES_AGAIN;
		goto out;
	}
	for (i = 0; i < nx; i++) {
		size_t k;

		if (udpc_dns_parse(x[i].ans, x[i].anslen, name, types[i], r) != 0) {
			again = true;
			continue;
		}
		if (r->rcode == UDPC_DNS_RCODE_NXDOMAIN) {
			nxdomain = true;
			continue;
		}
		if (r->rcode != UDPC_DNS_RCODE_NOERROR) {
			again = true;
			continue;
		}
		for (k = 0; k < r->naddr; k++)
			add_addr(out, r->addr[k].family, r->addr[k].bytes);
		if (out->canon[0] == '\0')
			snprintf(out->canon, sizeof(out->canon), "%s", r->canon);
	}
	free(r);

	if (out->naddr > 0)
		st = UDPC_RES_OK;
	else if (nxdomain)
		st = UDPC_RES_NONAME;
	else if (again)
		st = UDPC_RES_AGAIN;
	else
		st = UDPC_RES_NODATA;
out:
	for (i = 0; i < nx; i++)
		free(x[i].ans);
	return st;
}

enum udpc_res_status udpc_resolve_name(const char *name, unsigned want,
                                       struct udpc_res_result *out)
{
	char bare[UDPC_DNS_NAME_MAX];
	char (*cand)[UDPC_DNS_NAME_MAX];
	size_t n, i;
	bool again = false, nodata = false;
	enum udpc_res_status st = UDPC_RES_NONAME;

	memset(out, 0, sizeof(*out));
	if (name == NULL || name[0] == '\0' || strlen(name) >= sizeof(bare))
		return UDPC_RES_NONAME;
	strip_dot(name, bare, sizeof(bare));

	if (is_localhost(bare)) {
		static const uint8_t lo4[4] = { 127, 0, 0, 1 };

		if (want & UDPC_RES_WANT_A)
			add_addr(out, AF_INET, lo4);
		if (want & UDPC_RES_WANT_AAAA)
			add_addr(out, AF_INET6, &in6addr_loopback);
		snprintf(out->canon, sizeof(out->canon), "%s", bare);
		return out->naddr > 0 ? UDPC_RES_OK : UDPC_RES_NODATA;
	}

	if (hosts_lookup(hosts_path(), bare, want, out))
		return UDPC_RES_OK;

	cand = malloc(8 * sizeof(*cand));
	if (cand == NULL)
		return UDPC_RES_AGAIN;
	n = udpc_resolve_candidates(name, cand, 8);
	for (i = 0; i < n; i++) {
		memset(out, 0, sizeof(*out));
		st = dns_lookup(cand[i], want, out);
		if (st == UDPC_RES_OK || st == UDPC_RES_FAIL)
			break;
		if (st == UDPC_RES_AGAIN)
			again = true;
		else if (st == UDPC_RES_NODATA)
			nodata = true;
	}
	free(cand);

	if (st == UDPC_RES_OK || st == UDPC_RES_FAIL)
		return st;
	return again ? UDPC_RES_AGAIN : nodata ? UDPC_RES_NODATA : UDPC_RES_NONAME;
}

enum udpc_res_status udpc_resolve_addr(const struct sockaddr *sa, char *name)
{
	char ptr[UDPC_DNS_NAME_MAX];
	uint8_t q[UDPC_DNS_QUERY_MAX];
	struct udpc_dns_result *r;
	struct xfer x;
	enum udpc_res_status st;
	uint8_t b[16];
	int fam;
	ssize_t ql;

	name[0] = '\0';
	fam = addr_bytes(sa, b);
	if (fam < 0)
		return UDPC_RES_NONAME;
	if (hosts_reverse(hosts_path(), sa, name))
		return UDPC_RES_OK;

	/* Loopback never goes to a resolver, the reverse of RFC 6761. */
	if ((fam == AF_INET && b[0] == 127) ||
	    (fam == AF_INET6 && memcmp(b, &in6addr_loopback, 16) == 0)) {
		snprintf(name, UDPC_DNS_NAME_MAX, "localhost");
		return UDPC_RES_OK;
	}

	if (udpc_dns_ptr_name(sa, ptr, sizeof(ptr)) != 0)
		return UDPC_RES_NONAME;
	ql = udpc_dns_build_query(q, sizeof(q), udpc_resolve_random_id(), ptr,
	                          UDPC_DNS_CLASS_IN, UDPC_DNS_TYPE_PTR,
	                          UDPC_DNS_EDNS_SIZE);
	if (ql < 0)
		return UDPC_RES_NONAME;

	memset(&x, 0, sizeof(x));
	x.query = q;
	x.qlen = (size_t)ql;
	x.anscap = TCP_MSG_MAX;
	x.ans = malloc(TCP_MSG_MAX);
	r = malloc(sizeof(*r));
	if (x.ans == NULL || r == NULL) {
		free(x.ans);
		free(r);
		return UDPC_RES_AGAIN;
	}

	if (transact(&x, 1, &st) == 0) {
		if (udpc_dns_parse(x.ans, x.anslen, ptr, UDPC_DNS_TYPE_PTR, r) != 0)
			st = UDPC_RES_AGAIN;
		else if (r->rcode == UDPC_DNS_RCODE_NXDOMAIN)
			st = UDPC_RES_NONAME;
		else if (r->rcode != UDPC_DNS_RCODE_NOERROR)
			st = UDPC_RES_AGAIN;
		else if (!r->have_ptr)
			st = UDPC_RES_NODATA;
		else
			snprintf(name, UDPC_DNS_NAME_MAX, "%s", r->ptr);
	}
	free(x.ans);
	free(r);
	return st;
}

ssize_t udpc_resolve_raw(const uint8_t *query, size_t qlen, uint8_t *answer,
                         size_t anslen, enum udpc_res_status *status)
{
	struct xfer x;

	if (query == NULL || answer == NULL || qlen < UDPC_DNS_HDR_LEN ||
	    anslen < UDPC_DNS_HDR_LEN) {
		*status = UDPC_RES_FAIL;
		return -1;
	}
	memset(&x, 0, sizeof(x));
	x.query = query;
	x.qlen = qlen;
	x.ans = answer;
	x.anscap = anslen;
	if (transact(&x, 1, status) != 0)
		return -1;
	return (ssize_t)x.anslen;
}

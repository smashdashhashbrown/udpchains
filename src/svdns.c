/* svdns.c -- which datagrams are queries to the system resolver (D-52).
 *
 * A supervised program runs its own resolver, which reads /etc/resolv.conf.
 * A query to port 53 of the system resolver -- a loopback address, or a
 * nameserver listed there -- is sent to `dns` instead (svcall.c), and its
 * reply reported as from the address the program asked.  Port 53 anywhere
 * else is proxied as addressed.
 *
 * resolv.conf is read again whenever it changes, so a nameserver a VPN or DHCP
 * puts there while the program runs is recognised too.  Wrapper-only.
 *
 * Also which Unix sockets are a resolver daemon's (D-55).
 *
 * Written from resolv.conf(5) and nsswitch.conf(5) (D-01); the daemons'
 * socket paths from what their clients were seen to connect to.
 */
#include "svint.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <sys/stat.h>

#include "addr.h"

#define DNS_PORT 53
#define NSERVERS 16 /* resolv.conf(5) honours 3; more are kept, harmlessly */

static const char *g_path = "/etc/resolv.conf";
static struct sockaddr_storage g_server[NSERVERS];
static unsigned g_nserver;
static bool g_loaded;
static struct stat g_seen; /* the file as last read: device, inode, size, time */

void svdns_set_path(const char *path)
{
	g_path = path;
	g_loaded = false;
}

static bool changed(const struct stat *st)
{
	return !g_loaded || st->st_dev != g_seen.st_dev || st->st_ino != g_seen.st_ino ||
	       st->st_size != g_seen.st_size || st->st_mtim.tv_sec != g_seen.st_mtim.tv_sec ||
	       st->st_mtim.tv_nsec != g_seen.st_mtim.tv_nsec;
}

/* One "nameserver <address>" line's address, without a zone ("%eth0"). */
static void add_server(const char *word)
{
	char addr[80], *pct;
	struct sockaddr_storage *ss = &g_server[g_nserver];

	if (g_nserver == NSERVERS)
		return;
	snprintf(addr, sizeof(addr), "%s", word);
	pct = strchr(addr, '%');
	if (pct != NULL)
		*pct = '\0';
	memset(ss, 0, sizeof(*ss));
	if (inet_pton(AF_INET, addr, &((struct sockaddr_in *)ss)->sin_addr) == 1)
		ss->ss_family = AF_INET;
	else if (inet_pton(AF_INET6, addr, &((struct sockaddr_in6 *)ss)->sin6_addr) == 1)
		ss->ss_family = AF_INET6;
	else
		return;
	udpc_sa_set_port((struct sockaddr *)ss, DNS_PORT);
	g_nserver++;
}

/* Reads the nameservers again if the file has changed since.  A file that
 * has gone lists none. */
static void refresh(void)
{
	struct stat st;
	char line[512];
	FILE *f;

	if (stat(g_path, &st) != 0) {
		memset(&st, 0, sizeof(st));
		if (g_loaded && !changed(&st))
			return;
		g_nserver = 0;
		g_seen = st;
		g_loaded = true;
		return;
	}
	if (!changed(&st))
		return;
	g_nserver = 0;
	g_seen = st;
	g_loaded = true;
	f = fopen(g_path, "re");
	if (f == NULL)
		return;
	while (fgets(line, sizeof(line), f) != NULL) {
		char word[80];

		if (sscanf(line, " nameserver %79s", word) == 1)
			add_server(word);
	}
	fclose(f);
}

bool svdns_same(const struct sockaddr *a, const struct sockaddr *b)
{
	struct sockaddr_storage x, y;

	if (udpc_addr_for_family(a, AF_INET6, &x) != 0 ||
	    udpc_addr_for_family(b, AF_INET6, &y) != 0)
		return false;
	return udpc_addr_equal((const struct sockaddr *)&x, (const struct sockaddr *)&y);
}

bool svdns_system_resolver(const struct sockaddr *dst)
{
	unsigned k;

	if (dst == NULL || (dst->sa_family != AF_INET && dst->sa_family != AF_INET6) ||
	    udpc_sa_port(dst) != DNS_PORT)
		return false;
	if (udpc_addr_is_loopback(dst))
		return true;
	refresh();
	for (k = 0; k < g_nserver; k++)
		if (svdns_same(dst, (const struct sockaddr *)&g_server[k]))
			return true;
	return false;
}

/* --- resolver daemons (D-55) ------------------------------------------------*/

/* The sockets of the daemons a lookup is handed to, by an NSS module or by
 * glibc itself, each resolving it outside the proxy. */
static const struct {
	const char *path; /* under /run, which /var/run is a link to */
	const char *name;
} g_daemons[] = {
	{ "/run/systemd/resolve/io.systemd.Resolve", "systemd-resolved (nss-resolve)" },
	{ "/run/nscd/socket", "nscd" },
	{ "/run/avahi-daemon/socket", "avahi (nss-mdns)" },
};

const char *svdns_resolver_daemon(const struct sockaddr_un *un, socklen_t len)
{
	char path[sizeof(un->sun_path) + 1];
	const char *p = path;
	size_t n;
	unsigned k;

	if (len <= offsetof(struct sockaddr_un, sun_path) || un->sun_family != AF_UNIX ||
	    un->sun_path[0] == '\0')
		return NULL;
	n = len - offsetof(struct sockaddr_un, sun_path);
	if (n > sizeof(un->sun_path))
		n = sizeof(un->sun_path);
	memcpy(path, un->sun_path, n);
	path[n] = '\0';
	if (strncmp(p, "/var/run/", 9) == 0)
		p += 4;
	for (k = 0; k < sizeof(g_daemons) / sizeof(g_daemons[0]); k++)
		if (strcmp(p, g_daemons[k].path) == 0)
			return g_daemons[k].name;
	return NULL;
}

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "addr.h"
#include "log.h"

void udpc_config_init(struct udpc_config *cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	cfg->verbosity = UDPC_NORMAL;
}

void udpc_config_defaults(struct udpc_config *cfg)
{
	udpc_config_init(cfg);
	cfg->max_datagram = UDPC_DEFAULT_MAX_DATAGRAM;
	cfg->connect_timeout_ms = UDPC_DEFAULT_CONNECT_TIMEOUT_MS;
	cfg->dns_timeout_ms = UDPC_DEFAULT_DNS_TIMEOUT_MS;
	snprintf(cfg->hosts_file, sizeof(cfg->hosts_file), "%s",
	         UDPC_DEFAULT_HOSTS_FILE);
	cfg->strict_loopback = false;
	cfg->verbosity = UDPC_NORMAL;
	/* proxy deliberately left unset: D-10. */
}

void udpc_config_merge(struct udpc_config *dst, const struct udpc_config *src)
{
	uint32_t m = src->set_mask;
	unsigned i;

	if (m & UDPC_SET_PROXY) {
		memcpy(dst->proxy_spec, src->proxy_spec, sizeof(dst->proxy_spec));
		dst->proxy_set = src->proxy_set;
		/* D-38: the chain comes whole from the layer that names it. */
		dst->nextra = src->nextra;
		for (i = 0; i < UDPC_CHAIN_MAX - 1; i++)
			memcpy(dst->hops[i].spec, src->hops[i].spec,
			       sizeof(dst->hops[i].spec));
	}
	if (m & UDPC_SET_MAX_DATAGRAM)
		dst->max_datagram = src->max_datagram;
	if (m & UDPC_SET_STRICT_LOOPBACK)
		dst->strict_loopback = src->strict_loopback;
	if (m & UDPC_SET_CONNECT_TIMEOUT)
		dst->connect_timeout_ms = src->connect_timeout_ms;
	if (m & UDPC_SET_CHAIN_TIMEOUT) {
		dst->chain_timeout_ms = src->chain_timeout_ms;
		dst->chain_timeout_set = src->chain_timeout_set;
	}
	if (m & UDPC_SET_SUPERVISE)
		dst->supervise = src->supervise;
	if (m & UDPC_SET_RESOLVER_DAEMONS)
		dst->allow_resolver_daemons = src->allow_resolver_daemons;
	if (m & UDPC_SET_USERNAME) {
		memcpy(dst->username, src->username, sizeof(dst->username));
		dst->have_credentials = true;
	}
	if (m & UDPC_SET_PASSWORD) {
		memcpy(dst->password, src->password, sizeof(dst->password));
		memcpy(dst->password_file, src->password_file,
		       sizeof(dst->password_file));
		memcpy(dst->password_config, src->password_config,
		       sizeof(dst->password_config));
		dst->have_credentials = true;
	}
	if (m & UDPC_SET_VERBOSITY)
		dst->verbosity = src->verbosity;
	if (m & UDPC_SET_CONFIG_PATH)
		memcpy(dst->config_path, src->config_path, sizeof(dst->config_path));
	if (m & UDPC_SET_DNS) {
		memcpy(dst->dns_spec, src->dns_spec, sizeof(dst->dns_spec));
		dst->dns_set = src->dns_set;
	}
	if (m & UDPC_SET_DNS_TIMEOUT)
		dst->dns_timeout_ms = src->dns_timeout_ms;
	if (m & UDPC_SET_DNS_SEARCH)
		memcpy(dst->dns_search, src->dns_search, sizeof(dst->dns_search));
	if (m & UDPC_SET_HOSTS_FILE)
		memcpy(dst->hosts_file, src->hosts_file, sizeof(dst->hosts_file));

	/* Later hops' credentials, each from the highest layer that sets it, as
	 * hop 1's are. */
	for (i = 0; i < UDPC_CHAIN_MAX - 1; i++) {
		const struct udpc_hop *sh = &src->hops[i];
		struct udpc_hop *dh = &dst->hops[i];

		if (sh->set_mask & UDPC_SET_USERNAME) {
			memcpy(dh->username, sh->username, sizeof(dh->username));
			dh->have_credentials = true;
		}
		if (sh->set_mask & UDPC_SET_PASSWORD) {
			memcpy(dh->password, sh->password, sizeof(dh->password));
			memcpy(dh->password_file, sh->password_file,
			       sizeof(dh->password_file));
			memcpy(dh->password_config, sh->password_config,
			       sizeof(dh->password_config));
			dh->have_credentials = true;
		}
		dh->set_mask |= sh->set_mask;
	}

	dst->set_mask |= m;
}

static int parse_bool(const char *v, bool *out)
{
	if (strcmp(v, "1") == 0 || strcasecmp(v, "yes") == 0 ||
	    strcasecmp(v, "true") == 0 || strcasecmp(v, "on") == 0) {
		*out = true;
		return 0;
	}
	if (strcmp(v, "0") == 0 || strcasecmp(v, "no") == 0 ||
	    strcasecmp(v, "false") == 0 || strcasecmp(v, "off") == 0) {
		*out = false;
		return 0;
	}
	return -1;
}

static int parse_long(const char *v, long min, long max, long *out)
{
	char *end = NULL;
	long n;

	errno = 0;
	n = strtol(v, &end, 10);
	if (errno != 0 || end == v || *end != '\0' || n < min || n > max)
		return -1;
	*out = n;
	return 0;
}

/* The warnings about a config file -- its permissions, and proxychains
 * directives it does not apply -- are the wrapper's to give: launched by the
 * wrapper, a shim reading the same files again would print each warning a
 * second time, once per process (D-33). */
static bool g_quiet_file_warnings;

/* SEC-03: reads a password from a file, so it never appears in argv or in
 * `ps` output.  Strips one trailing newline, CR included.
 *
 * L5: a password longer than RFC 1929's 255 bytes is an error, not a silent
 * truncation -- the truncated password would fail at the proxy with nothing
 * to say why. */
static int read_password_file(const char *path, char *out, size_t outlen,
                              const char **err)
{
	char buf[UDPC_PASSWORD_MAX + 3]; /* the maximum, a CR LF, and one over */
	size_t len = 0;
	struct stat st;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		*err = "cannot open password file";
		return -1;
	}
	if (!g_quiet_file_warnings && fstat(fd, &st) == 0 &&
	    (st.st_mode & (S_IRWXG | S_IRWXO)) != 0)
		udpc_warn("password file %s is group- or world-accessible", path);

	while (len < sizeof(buf)) {
		ssize_t n = read(fd, buf + len, sizeof(buf) - len);
		if (n == 0)
			break;
		if (n < 0) {
			if (errno == EINTR)
				continue;
			close(fd);
			explicit_bzero(buf, sizeof(buf));
			*err = "cannot read password file";
			return -1;
		}
		len += (size_t)n;
	}
	close(fd);

	if (len > 0 && buf[len - 1] == '\n')
		len--;
	if (len > 0 && buf[len - 1] == '\r')
		len--;
	if (len > UDPC_PASSWORD_MAX || len >= outlen) {
		explicit_bzero(buf, sizeof(buf));
		*err = "password file holds more than 255 bytes, the RFC 1929 "
		       "limit";
		return -1;
	}
	memcpy(out, buf, len);
	out[len] = '\0';
	explicit_bzero(buf, sizeof(buf));
	return 0;
}

/* The credential keys, for hop 1 or a later hop (D-38): each has the same
 * fields, so one setter serves both.  Returns 1 if key was a credential key and
 * was set, 0 if it is not a credential key, and -1 with *err on a bad value. */
struct creds {
	uint32_t *mask;
	char *username, *password, *password_file, *password_config;
};

static int set_credential(const struct creds *c, const char *key, const char *value,
                          const char **err)
{
	if (strcmp(key, "username") == 0) {
		if (strlen(value) >= UDPC_PASSWORD_MAX + 1) {
			*err = "username too long";
			return -1;
		}
		snprintf(c->username, UDPC_PASSWORD_MAX + 1, "%s", value);
		*c->mask |= UDPC_SET_USERNAME;
		return 1;
	}
	if (strcmp(key, "password") == 0) {
		if (strlen(value) >= UDPC_PASSWORD_MAX + 1) {
			*err = "password too long";
			return -1;
		}
		snprintf(c->password, UDPC_PASSWORD_MAX + 1, "%s", value);
		/* An inline value.  If it came from a config file,
		 * udpc_config_read_file records which one (D-25). */
		c->password_file[0] = '\0';
		c->password_config[0] = '\0';
		*c->mask |= UDPC_SET_PASSWORD;
		return 1;
	}
	if (strcmp(key, "password_file") == 0) {
		char *abs;

		if (read_password_file(value, c->password, UDPC_PASSWORD_MAX + 1,
		                       err) != 0)
			return -1;
		/* D-25: remembered as an ABSOLUTE path, so a target that changes
		 * directory -- or a descendant that starts elsewhere -- can still
		 * read it. */
		abs = realpath(value, NULL);
		snprintf(c->password_file, UDPC_PATH_MAX, "%s", abs != NULL ? abs : value);
		free(abs);
		c->password_config[0] = '\0';
		*c->mask |= UDPC_SET_PASSWORD;
		return 1;
	}
	return 0;
}

static struct creds hop1_creds(struct udpc_config *cfg)
{
	struct creds c = { &cfg->set_mask, cfg->username, cfg->password,
	                   cfg->password_file, cfg->password_config };
	return c;
}

static struct creds hop_creds(struct udpc_hop *h)
{
	struct creds c = { &h->set_mask, h->username, h->password,
	                   h->password_file, h->password_config };
	return c;
}

int udpc_config_set(struct udpc_config *cfg, const char *key, const char *value,
                    const char **err)
{
	long n;
	int rc;

	*err = NULL;

	if (strcmp(key, "proxy") == 0) {
		if (strlen(value) >= sizeof(cfg->proxy_spec)) {
			*err = "proxy address too long";
			return -1;
		}
		snprintf(cfg->proxy_spec, sizeof(cfg->proxy_spec), "%s", value);
		cfg->proxy_set = true;
		cfg->set_mask |= UDPC_SET_PROXY;
		return 0;
	}
	if (strcmp(key, "max_datagram") == 0) {
		if (parse_long(value, 1, UDPC_MAX_DATAGRAM_CEILING, &n) != 0) {
			*err = "max_datagram must be 1..65507";
			return -1;
		}
		cfg->max_datagram = (size_t)n;
		cfg->set_mask |= UDPC_SET_MAX_DATAGRAM;
		return 0;
	}
	if (strcmp(key, "strict_loopback") == 0) {
		if (parse_bool(value, &cfg->strict_loopback) != 0) {
			*err = "strict_loopback must be a boolean";
			return -1;
		}
		cfg->set_mask |= UDPC_SET_STRICT_LOOPBACK;
		return 0;
	}
	if (strcmp(key, "connect_timeout") == 0) {
		if (parse_long(value, 1, UDPC_CONNECT_TIMEOUT_MAX_MS, &n) != 0) {
			*err = "connect_timeout must be 1..600000 ms";
			return -1;
		}
		cfg->connect_timeout_ms = (int)n;
		cfg->set_mask |= UDPC_SET_CONNECT_TIMEOUT;
		return 0;
	}
	/* D-45: up to what the default can reach, connect_timeout's most for
	 * each of the most hops. */
	if (strcmp(key, "chain_timeout") == 0) {
		if (parse_long(value, 0,
		               (long)UDPC_CONNECT_TIMEOUT_MAX_MS * UDPC_CHAIN_MAX,
		               &n) != 0) {
			*err = "chain_timeout must be 0 (no limit) or 1..4800000 ms";
			return -1;
		}
		cfg->chain_timeout_ms = (int)n;
		cfg->chain_timeout_set = true;
		cfg->set_mask |= UDPC_SET_CHAIN_TIMEOUT;
		return 0;
	}
	if (strcmp(key, "supervise") == 0) {
		if (parse_bool(value, &cfg->supervise) != 0) {
			*err = "supervise must be a boolean";
			return -1;
		}
		cfg->set_mask |= UDPC_SET_SUPERVISE;
		return 0;
	}
	if (strcmp(key, "allow_resolver_daemons") == 0) {
		if (parse_bool(value, &cfg->allow_resolver_daemons) != 0) {
			*err = "allow_resolver_daemons must be a boolean";
			return -1;
		}
		cfg->set_mask |= UDPC_SET_RESOLVER_DAEMONS;
		return 0;
	}
	if (strcmp(key, "dns") == 0) {
		if (strlen(value) >= sizeof(cfg->dns_spec)) {
			*err = "dns address too long";
			return -1;
		}
		snprintf(cfg->dns_spec, sizeof(cfg->dns_spec), "%s", value);
		cfg->dns_set = true;
		cfg->set_mask |= UDPC_SET_DNS;
		return 0;
	}
	if (strcmp(key, "dns_timeout") == 0) {
		if (parse_long(value, 100, 600000, &n) != 0) {
			*err = "dns_timeout must be 100..600000 ms";
			return -1;
		}
		cfg->dns_timeout_ms = (int)n;
		cfg->set_mask |= UDPC_SET_DNS_TIMEOUT;
		return 0;
	}
	if (strcmp(key, "dns_search") == 0) {
		if (strlen(value) >= sizeof(cfg->dns_search)) {
			*err = "dns_search too long";
			return -1;
		}
		snprintf(cfg->dns_search, sizeof(cfg->dns_search), "%s", value);
		cfg->set_mask |= UDPC_SET_DNS_SEARCH;
		return 0;
	}
	if (strcmp(key, "hosts_file") == 0) {
		if (value[0] == '\0' || strlen(value) >= sizeof(cfg->hosts_file)) {
			*err = "hosts_file must be a path";
			return -1;
		}
		snprintf(cfg->hosts_file, sizeof(cfg->hosts_file), "%s", value);
		cfg->set_mask |= UDPC_SET_HOSTS_FILE;
		return 0;
	}
	{
		struct creds c = hop1_creds(cfg);

		rc = set_credential(&c, key, value, err);
		if (rc != 0)
			return rc < 0 ? -1 : 0;
	}
	if (strcmp(key, "quiet") == 0) {
		bool b;
		if (parse_bool(value, &b) != 0) {
			*err = "quiet must be a boolean";
			return -1;
		}
		if (b)
			cfg->verbosity = UDPC_QUIET;
		cfg->set_mask |= UDPC_SET_VERBOSITY;
		return 0;
	}
	if (strcmp(key, "debug") == 0) {
		bool b;
		if (parse_bool(value, &b) != 0) {
			*err = "debug must be a boolean";
			return -1;
		}
		if (b)
			cfg->verbosity = UDPC_DEBUG;
		cfg->set_mask |= UDPC_SET_VERBOSITY;
		return 0;
	}

	*err = "unknown configuration key";
	return -1;
}

int udpc_config_append_hop(struct udpc_config *cfg, const char *spec,
                           const char **err)
{
	*err = NULL;
	if (!(cfg->set_mask & UDPC_SET_PROXY)) {
		*err = "a later hop needs a first proxy before it";
		return -1;
	}
	if (cfg->nextra >= UDPC_CHAIN_MAX - 1) {
		*err = "a chain has at most 8 hops (D-42)";
		return -1;
	}
	if (spec[0] == '\0' || strlen(spec) >= sizeof(cfg->hops[0].spec)) {
		*err = "proxy address empty or too long";
		return -1;
	}
	snprintf(cfg->hops[cfg->nextra].spec, sizeof(cfg->hops[0].spec), "%s", spec);
	cfg->nextra++;
	return 0;
}

/* A key inside a [hop] section (D-38).  Only the hop's own keys belong there:
 * any other would look per-hop and is not. */
static int set_hop_key(struct udpc_hop *h, const char *key, const char *value,
                       const char **err)
{
	struct creds c = hop_creds(h);
	int rc;

	if (strcmp(key, "proxy") == 0) {
		if (value[0] == '\0' || strlen(value) >= sizeof(h->spec)) {
			*err = "proxy address empty or too long";
			return -1;
		}
		snprintf(h->spec, sizeof(h->spec), "%s", value);
		return 0;
	}
	rc = set_credential(&c, key, value, err);
	if (rc != 0)
		return rc < 0 ? -1 : 0;
	*err = "only proxy, username, password and password_file belong in a "
	       "[hop] section";
	return -1;
}

/* --- proxychains.conf (FR-CH-14, D-47) --------------------------------------
 *
 * A proxychains.conf can be given to -f as it is, for the strict chain of
 * socks5 hops that udpchains shares with it.  Written from the format as
 * proxychains documents it, never from its source (D-01). */

/* proxychains' own directives, which come before its [ProxyList], one to a
 * line as "name" or "name value" ("chain_len = 2" has an '=').  Each is
 * applied, refused, or named in a warning; none can make anything go direct.
 * Returns 1 if the line is one, 0 if it is not, and -1 with *err if it is
 * refused. */
static int proxychains_directive(struct udpc_config *cfg, const char *line,
                                 const char *path, int lineno, const char **err)
{
	static const struct {
		const char *name, *why;
	} ignored[] = {
		{ "chain_len", "chains are strict, so every hop listed is used" },
		{ "tcp_read_time_out", "there is no read timeout; connect_timeout "
		                       "bounds each step of a handshake" },
		{ "proxy_dns", "names are looked up at the resolver set by dns, "
		               "through the proxies, and fail without one" },
		{ "proxy_dns_old", "names are looked up at the resolver set by dns, "
		                   "through the proxies, and fail without one" },
		{ "proxy_dns_daemon", "names are looked up at the resolver set by "
		                      "dns, through the proxies, and fail without one" },
		{ "remote_dns_subnet", "no placeholder addresses are handed out" },
		{ "localnet", "there is no bypass, so that traffic goes through the "
		              "proxies or fails (D-05)" },
		{ "dnat", "destinations are used as given" },
	};
	char name[32];
	const char *value;
	size_t len = strcspn(line, " \t=");
	size_t i;

	if (len == 0 || len >= sizeof(name))
		return 0;
	memcpy(name, line, len);
	name[len] = '\0';
	value = line + len;
	value += strspn(value, " \t");
	if (*value == '=')
		value += 1 + strspn(value + 1, " \t");

	if (strcmp(name, "strict_chain") == 0)
		return 1;
	if (strcmp(name, "dynamic_chain") == 0 || strcmp(name, "random_chain") == 0 ||
	    strcmp(name, "round_robin_chain") == 0) {
		*err = "chains are strict: every hop, in order, or the send fails "
		       "(D-37); use strict_chain";
		return -1;
	}
	if (strcmp(name, "quiet_mode") == 0) {
		cfg->verbosity = UDPC_QUIET;
		cfg->set_mask |= UDPC_SET_VERBOSITY;
		return 1;
	}
	if (strcmp(name, "tcp_connect_time_out") == 0) {
		if (udpc_config_set(cfg, "connect_timeout", value, err) != 0) {
			*err = "tcp_connect_time_out must be 1..600000 ms";
			return -1;
		}
		return 1;
	}
	for (i = 0; i < sizeof(ignored) / sizeof(ignored[0]); i++) {
		if (strcmp(name, ignored[i].name) != 0)
			continue;
		if (!g_quiet_file_warnings)
			udpc_warn("%s:%d: proxychains' %s is not applied: %s", path,
			          lineno, name, ignored[i].why);
		return 1;
	}
	return 0;
}

/* One [ProxyList] line, "type host port [user pass]", separated by spaces or
 * tabs, as the next hop.  Only socks5 can carry UDP. */
static int proxylist_entry(struct udpc_config *cfg, char *line, const char **err)
{
	char *field[5], *save = NULL, *tok;
	char spec[sizeof(cfg->proxy_spec)];
	struct creds c;
	unsigned n = 0;
	long port;

	for (tok = strtok_r(line, " \t", &save); tok != NULL;
	     tok = strtok_r(NULL, " \t", &save)) {
		/* D4, as for key = value lines. */
		if (tok[0] == '#') {
			*err = "'#' after a proxy is not a comment; comments must be on "
			       "their own line";
			return -1;
		}
		if (n == sizeof(field) / sizeof(field[0])) {
			*err = "too many fields; a [ProxyList] line is 'socks5 host port "
			       "[username password]'";
			return -1;
		}
		field[n++] = tok;
	}

	if (strcasecmp(field[0], "socks4") == 0 || strcasecmp(field[0], "http") == 0 ||
	    strcasecmp(field[0], "raw") == 0) {
		*err = "only socks5 can carry UDP; socks4, http and raw proxies "
		       "cannot";
		return -1;
	}
	if (strcasecmp(field[0], "socks5") != 0) {
		*err = "unknown proxy type; a [ProxyList] line is 'socks5 host port "
		       "[username password]'";
		return -1;
	}
	if (n < 3) {
		*err = "a [ProxyList] line is 'socks5 host port [username password]'";
		return -1;
	}
	if (n == 4) {
		*err = "a username needs a password after it";
		return -1;
	}
	if (parse_long(field[2], 1, 65535, &port) != 0) {
		*err = "the port must be 1..65535";
		return -1;
	}
	/* A bare IPv6 address takes the brackets the rest of the configuration
	 * writes it with. */
	if (strchr(field[1], ':') != NULL && field[1][0] != '[')
		snprintf(spec, sizeof(spec), "[%.200s]:%ld", field[1], port);
	else
		snprintf(spec, sizeof(spec), "%.240s:%ld", field[1], port);

	if (!(cfg->set_mask & UDPC_SET_PROXY)) {
		if (udpc_config_set(cfg, "proxy", spec, err) != 0)
			return -1;
		c = hop1_creds(cfg);
	} else {
		if (udpc_config_append_hop(cfg, spec, err) != 0)
			return -1;
		c = hop_creds(&cfg->hops[cfg->nextra - 1]);
	}
	if (n == 5 && (set_credential(&c, "username", field[3], err) < 0 ||
	               set_credential(&c, "password", field[4], err) < 0))
		return -1;
	return 0;
}

int udpc_config_read_file(struct udpc_config *cfg, const char *path,
                          const char **err, int *errline)
{
	/* D-38: 0 at the top level, which is hop 1; k inside the k-th [hop]
	 * section, which is hop k + 1. */
	unsigned section = 0;
	int section_line = 0;
	/* FR-CH-14: inside a proxychains [ProxyList], every line is a hop. */
	bool proxylist = false;
	int proxylist_line = 0;
	FILE *f;
	char line[1024];
	int lineno = 0;
	struct stat st;
	bool have_st;

	*err = NULL;
	*errline = 0;

	f = fopen(path, "re");
	if (f == NULL) {
		*err = (errno == ENOENT) ? "no such file" : strerror(errno);
		return -1;
	}

	/* SEC-04: this file directs where traffic goes.  If anyone else can
	 * write it, they can redirect the traffic. */
	have_st = fstat(fileno(f), &st) == 0;
	if (!g_quiet_file_warnings && have_st && (st.st_mode & (S_IWGRP | S_IWOTH)) != 0)
		udpc_warn("config file %s is group- or world-writable; "
		          "it controls where your traffic goes",
		          path);

	while (fgets(line, sizeof(line), f) != NULL) {
		char *p = line, *key, *value, *eq, *end;
		lineno++;

		/* L5: a line that filled the buffer without a newline is too
		 * long -- unless the file ends exactly there.  Measured before
		 * leading whitespace is skipped, which once hid it. */
		end = strchr(line, '\n');
		if (end != NULL) {
			*end = '\0';
		} else if (strlen(line) == sizeof(line) - 1) {
			int c = fgetc(f);

			if (c != EOF) {
				*err = "line too long";
				*errline = lineno;
				fclose(f);
				return -1;
			}
		}
		p += strspn(p, " \t");

		if (*p == '\0' || *p == '#' || *p == ';')
			continue;

		if (*p == '[') {
			end = p + strlen(p);
			while (end > p && (end[-1] == ' ' || end[-1] == '\t'))
				*--end = '\0';
			if (strcasecmp(p, "[proxylist]") == 0) {
				/* One way to write a chain to a file (D-47). */
				*err = proxylist ? "a second [ProxyList]"
				       : (cfg->set_mask & UDPC_SET_PROXY)
				               ? "[ProxyList] cannot follow 'proxy =' or "
				                 "[hop] sections; use one or the other"
				               : NULL;
				if (*err != NULL) {
					*errline = lineno;
					fclose(f);
					return -1;
				}
				proxylist = true;
				proxylist_line = lineno;
				continue;
			}
			if (strcasecmp(p, "[hop]") != 0) {
				*err = "unknown section; the sections are [hop] and "
				       "[ProxyList]";
				*errline = lineno;
				fclose(f);
				return -1;
			}
			if (proxylist) {
				*err = "[hop] sections cannot follow [ProxyList]; use one "
				       "or the other";
				*errline = lineno;
				fclose(f);
				return -1;
			}
			if (!(cfg->set_mask & UDPC_SET_PROXY)) {
				*err = "a [hop] section needs a top-level proxy before "
				       "it, which is hop 1";
				*errline = lineno;
				fclose(f);
				return -1;
			}
			if (section > 0 && cfg->hops[section - 1].spec[0] == '\0') {
				*err = "[hop] section without a proxy";
				*errline = section_line;
				fclose(f);
				return -1;
			}
			if (cfg->nextra >= UDPC_CHAIN_MAX - 1) {
				*err = "a chain has at most 8 hops (D-42)";
				*errline = lineno;
				fclose(f);
				return -1;
			}
			section = ++cfg->nextra;
			section_line = lineno;
			continue;
		}

		if (proxylist) {
			/* "key = value": an '=' after the first word.  One
			 * inside a password further on is the password's. */
			const char *after = p + strcspn(p, " \t=");

			if (after[strspn(after, " \t")] == '=') {
				*err = "only proxies belong after [ProxyList]; put "
				       "settings before it";
			} else if (proxylist_entry(cfg, p, err) == 0) {
				continue;
			}
			*errline = lineno;
			fclose(f);
			return -1;
		}
		if (section == 0) {
			int rc = proxychains_directive(cfg, p, path, lineno, err);

			if (rc > 0)
				continue;
			if (rc < 0) {
				*errline = lineno;
				fclose(f);
				return -1;
			}
		}

		eq = strchr(p, '=');
		if (eq == NULL) {
			*err = "expected 'key = value'";
			*errline = lineno;
			fclose(f);
			return -1;
		}
		*eq = '\0';
		key = p;
		value = eq + 1;

		/* trim key */
		end = key + strlen(key);
		while (end > key && (end[-1] == ' ' || end[-1] == '\t'))
			*--end = '\0';
		/* trim value */
		value += strspn(value, " \t");
		end = value + strlen(value);
		while (end > value && (end[-1] == ' ' || end[-1] == '\t'))
			*--end = '\0';

		if (*key == '\0') {
			*err = "empty key";
			*errline = lineno;
			fclose(f);
			return -1;
		}

		/* D4: comments are whole lines only.  "key = value # note" would
		 * otherwise make the note part of the value -- silently, for a
		 * password.  A '#' inside a value ("abc#def") is fine; one after
		 * whitespace, or opening the value, looks like a comment. */
		if (*value == '#' || strstr(value, " #") != NULL ||
		    strstr(value, "\t#") != NULL) {
			*err = "'#' after a value is not a comment; comments must be "
			       "on their own line (a password containing \" #\" "
			       "belongs in password_file)";
			*errline = lineno;
			fclose(f);
			return -1;
		}

		if ((section == 0 ? udpc_config_set(cfg, key, value, err)
		                  : set_hop_key(&cfg->hops[section - 1], key, value,
		                                err)) != 0) {
			*errline = lineno;
			fclose(f);
			return -1;
		}
	}

	if (section > 0 && cfg->hops[section - 1].spec[0] == '\0') {
		*err = "[hop] section without a proxy";
		*errline = section_line;
		fclose(f);
		return -1;
	}
	if (proxylist && !(cfg->set_mask & UDPC_SET_PROXY)) {
		*err = "[ProxyList] lists no proxy";
		*errline = proxylist_line;
		fclose(f);
		return -1;
	}

	if (ferror(f)) {
		*err = "read error";
		fclose(f);
		return -1;
	}

	fclose(f);
	snprintf(cfg->config_path, sizeof(cfg->config_path), "%s", path);
	cfg->set_mask |= UDPC_SET_CONFIG_PATH;

	/* D-25: a password written inline in this file is passed on by naming
	 * the file, never by copying the value into the environment.  So is a
	 * later hop's (D-38). */
	{
		bool inline_pw = (cfg->set_mask & UDPC_SET_PASSWORD) &&
		                 cfg->password_file[0] == '\0';
		char *abs;
		unsigned i;

		for (i = 0; i < cfg->nextra; i++)
			if ((cfg->hops[i].set_mask & UDPC_SET_PASSWORD) &&
			    cfg->hops[i].password_file[0] == '\0')
				inline_pw = true;
		if (!inline_pw)
			return 0;

		/* L5: SEC-04 warns about a writable config file because it
		 * directs traffic; one holding a password also matters when
		 * others can merely READ it. */
		if (!g_quiet_file_warnings && have_st &&
		    (st.st_mode & (S_IRGRP | S_IROTH)) != 0)
			udpc_warn("config file %s holds a password and is readable "
			          "by other users",
			          path);

		abs = realpath(path, NULL);
		if ((cfg->set_mask & UDPC_SET_PASSWORD) && cfg->password_file[0] == '\0')
			snprintf(cfg->password_config, sizeof(cfg->password_config),
			         "%s", abs != NULL ? abs : path);
		for (i = 0; i < cfg->nextra; i++)
			if ((cfg->hops[i].set_mask & UDPC_SET_PASSWORD) &&
			    cfg->hops[i].password_file[0] == '\0')
				snprintf(cfg->hops[i].password_config,
				         sizeof(cfg->hops[i].password_config), "%s",
				         abs != NULL ? abs : path);
		free(abs);
	}
	return 0;
}

struct env_key {
	const char *env;
	const char *key;
};

static const struct env_key g_env_keys[] = {
	{ "UDPCHAINS_MAX_DATAGRAM", "max_datagram" },
	{ "UDPCHAINS_STRICT_LOOPBACK", "strict_loopback" },
	{ "UDPCHAINS_CONNECT_TIMEOUT", "connect_timeout" },
	{ "UDPCHAINS_CHAIN_TIMEOUT", "chain_timeout" },
	{ "UDPCHAINS_SUPERVISE", "supervise" },
	{ "UDPCHAINS_ALLOW_RESOLVER_DAEMONS", "allow_resolver_daemons" },
	{ "UDPCHAINS_USERNAME", "username" },
	{ "UDPCHAINS_PASSWORD_FILE", "password_file" },
	{ "UDPCHAINS_DNS", "dns" },
	{ "UDPCHAINS_DNS_TIMEOUT", "dns_timeout" },
	{ "UDPCHAINS_DNS_SEARCH", "dns_search" },
	{ "UDPCHAINS_HOSTS_FILE", "hosts_file" },
};

/* D-38: UDPCHAINS_PROXY is a comma-separated list; the first entry is hop 1. */
static int proxy_list_from_env(struct udpc_config *cfg, const char *v, const char **err)
{
	char spec[256];
	const char *p = v;

	for (;;) {
		size_t len = strcspn(p, ",");

		if (len == 0) {
			*err = "UDPCHAINS_PROXY has an empty entry";
			return -1;
		}
		if (len >= sizeof(spec)) {
			*err = "proxy address too long";
			return -1;
		}
		memcpy(spec, p, len);
		spec[len] = '\0';
		if ((p == v ? udpc_config_set(cfg, "proxy", spec, err)
		            : udpc_config_append_hop(cfg, spec, err)) != 0)
			return -1;
		if (p[len] == '\0')
			return 0;
		p += len + 1;
	}
}

/* The password inline in the n-th hop (from 1) of a config file, which the
 * wrapper names rather than exporting the password (D-25, D-38).  Read into a
 * static layer: this runs once, at start-up, and a config with every hop is
 * too large for a small thread stack. */
static int password_from_config(const char *path, unsigned hop, char *out,
                                size_t outlen)
{
	static struct udpc_config tmp;
	const char *ferr = NULL;
	int fline = 0, rc = -1, read_rc;
	bool quiet = g_quiet_file_warnings;

	/* Only the password is wanted.  Whoever named this file has already
	 * read it, and said what there was to say about it. */
	udpc_config_init(&tmp);
	g_quiet_file_warnings = true;
	read_rc = udpc_config_read_file(&tmp, path, &ferr, &fline);
	g_quiet_file_warnings = quiet;
	if (read_rc == 0) {
		const uint32_t mask = hop == 1 ? tmp.set_mask : tmp.hops[hop - 2].set_mask;
		const char *pw = hop == 1 ? tmp.password : tmp.hops[hop - 2].password;

		if ((mask & UDPC_SET_PASSWORD) && (hop == 1 || hop - 2 < tmp.nextra)) {
			snprintf(out, outlen, "%s", pw);
			rc = 0;
		}
	}
	explicit_bzero(&tmp, sizeof(tmp));
	return rc;
}

/* Hop n's credentials, for n from 2: UDPCHAINS_USERNAME_<n> and the rest. */
static int hop_creds_from_env(struct udpc_config *cfg, unsigned n, const char **err)
{
	struct udpc_hop *h = &cfg->hops[n - 2];
	struct creds c = hop_creds(h);
	char name[64];
	const char *v;

	snprintf(name, sizeof(name), "UDPCHAINS_USERNAME_%u", n);
	if ((v = getenv(name)) != NULL && *v != '\0' &&
	    set_credential(&c, "username", v, err) < 0)
		return -1;
	snprintf(name, sizeof(name), "UDPCHAINS_PASSWORD_FILE_%u", n);
	if ((v = getenv(name)) != NULL && *v != '\0' &&
	    set_credential(&c, "password_file", v, err) < 0)
		return -1;
	snprintf(name, sizeof(name), "UDPCHAINS_PASSWORD_CONFIG_%u", n);
	if ((v = getenv(name)) != NULL && *v != '\0') {
		if (password_from_config(v, n, h->password, sizeof(h->password)) != 0) {
			*err = "cannot read a hop's password from the file named by "
			       "UDPCHAINS_PASSWORD_CONFIG_<n>";
			return -1;
		}
		snprintf(h->password_config, sizeof(h->password_config), "%s", v);
		h->password_file[0] = '\0';
		h->set_mask |= UDPC_SET_PASSWORD;
	}
	snprintf(name, sizeof(name), "UDPCHAINS_PASSWORD_%u", n);
	if ((v = getenv(name)) != NULL && *v != '\0' &&
	    set_credential(&c, "password", v, err) < 0)
		return -1;
	return 0;
}

int udpc_config_from_env(struct udpc_config *cfg, const char **err)
{
	size_t i;
	unsigned n;
	const char *v;

	*err = NULL;

	v = getenv("UDPCHAINS_PROXY");
	if (v != NULL && *v != '\0' && proxy_list_from_env(cfg, v, err) != 0)
		return -1;
	for (n = 2; n <= UDPC_CHAIN_MAX; n++)
		if (hop_creds_from_env(cfg, n, err) != 0)
			return -1;

	for (i = 0; i < sizeof(g_env_keys) / sizeof(g_env_keys[0]); i++) {
		v = getenv(g_env_keys[i].env);
		if (v == NULL || *v == '\0')
			continue;
		if (udpc_config_set(cfg, g_env_keys[i].key, v, err) != 0)
			return -1;
	}

	/* D-25: the wrapper names the config file holding an inline password,
	 * rather than exporting the password.  Only the password is taken from
	 * it; everything else arrived resolved, in the variables above. */
	v = getenv("UDPCHAINS_PASSWORD_CONFIG");
	if (v != NULL && *v != '\0') {
		if (password_from_config(v, 1, cfg->password, sizeof(cfg->password)) != 0) {
			*err = "cannot read the password from the file named by "
			       "UDPCHAINS_PASSWORD_CONFIG";
			return -1;
		}
		snprintf(cfg->password_config, sizeof(cfg->password_config), "%s", v);
		cfg->password_file[0] = '\0';
		cfg->set_mask |= UDPC_SET_PASSWORD;
	}

	/* SEC-03 note: UDPCHAINS_PASSWORD (the value itself, rather than a path
	 * to it) is accepted because the environment of a process is not
	 * visible in `ps` the way argv is.  It is also inherited by every
	 * descendant and shows up in anything that dumps the environment, so a
	 * file is preferable -- and the wrapper never creates this variable
	 * itself (D-25). */
	v = getenv("UDPCHAINS_PASSWORD");
	if (v != NULL && *v != '\0') {
		if (udpc_config_set(cfg, "password", v, err) != 0)
			return -1;
	}

	/* L5: booleans, like every other switch -- UDPCHAINS_QUIET=0 used to
	 * turn quiet mode ON, because only presence was tested.  An empty
	 * value counts as unset, as it does for the other variables. */
	{
		static const struct {
			const char *env;
			int level;
			const char *err;
		} sw[] = {
			{ "UDPCHAINS_QUIET", UDPC_QUIET,
			  "UDPCHAINS_QUIET must be a boolean (1/0, yes/no, "
			  "true/false, on/off)" },
			{ "UDPCHAINS_DEBUG", UDPC_DEBUG,
			  "UDPCHAINS_DEBUG must be a boolean (1/0, yes/no, "
			  "true/false, on/off)" },
		};

		for (i = 0; i < sizeof(sw) / sizeof(sw[0]); i++) {
			bool on;

			v = getenv(sw[i].env);
			if (v == NULL || *v == '\0')
				continue;
			if (parse_bool(v, &on) != 0) {
				*err = sw[i].err;
				return -1;
			}
			if (on) {
				cfg->verbosity = sw[i].level;
				cfg->set_mask |= UDPC_SET_VERBOSITY;
			}
		}
	}

	return 0;
}

int udpc_config_finalize(struct udpc_config *cfg, const char **err)
{
	const char *perr = NULL;

	*err = NULL;

	/* D-10 / FR-C-03: there is no built-in default proxy.  Without one the
	 * only fail-closed answer is to refuse. */
	if (!cfg->proxy_set || cfg->proxy_spec[0] == '\0') {
		*err = "no proxy configured (set UDPCHAINS_PROXY, use -p, or put "
		       "'proxy = host:port' in a config file)";
		return -1;
	}

	if (udpc_addr_parse(cfg->proxy_spec, UDPC_DEFAULT_PROXY_PORT, &cfg->proxy,
	                    &perr) != 0) {
		*err = perr ? perr : "cannot parse proxy address";
		return -1;
	}

	/* D-05 R2: whether the proxy is on this host decides how a loopback
	 * destination is treated.  Computed once here, never on the datagram
	 * path -- udpc_addr_is_local walks getifaddrs and allocates. */
	cfg->proxy_is_local =
		udpc_addr_is_local((const struct sockaddr *)&cfg->proxy);

	if (cfg->max_datagram == 0)
		cfg->max_datagram = UDPC_DEFAULT_MAX_DATAGRAM;

	/* D-39: a later hop is reached through the hop before it, which
	 * resolves it.  Here only its form is checked. */
	{
		unsigned i;

		for (i = 0; i < cfg->nextra; i++) {
			static char buf[160];
			char host[256];
			uint16_t port;

			if (udpc_addr_split(cfg->hops[i].spec, UDPC_DEFAULT_PROXY_PORT,
			                    host, sizeof(host), &port, &perr) != 0) {
				snprintf(buf, sizeof(buf), "hop %u: %s", i + 2,
				         perr ? perr : "cannot parse proxy address");
				*err = buf;
				return -1;
			}
		}
	}

	/* D-22: a resolver named by hostname would need a lookup before
	 * lookups work, and that lookup could only go direct.  Refused here,
	 * so the wrapper reports it before exec (FR-C-03). */
	if (cfg->dns_set && cfg->dns_spec[0] != '\0') {
		if (udpc_addr_parse_numeric(cfg->dns_spec, UDPC_DEFAULT_DNS_PORT,
		                            &cfg->dns, &perr) != 0) {
			*err = "dns must be a numeric address, as ip or ip:port "
			       "or [v6]:port";
			return -1;
		}
	} else {
		cfg->dns_set = false;
	}

	return 0;
}

int udpc_config_load_layers(struct udpc_config *cfg, const char *cli_path,
                            const char **err)
{
	/* Static: with a chain's hops, a layer is too large for a small thread
	 * stack, and this runs once, during single-threaded start-up -- the
	 * wrapper before exec, or the shim under pthread_once. */
	static struct udpc_config filecfg, envcfg;
	const char *path = NULL;
	const char *ferr = NULL;
	int fline = 0;
	char home_path[4096];

	*err = NULL;
	udpc_config_defaults(cfg);

	/* Which file?  Command line beats the environment beats the default
	 * locations.  The path is needed before any file layer can be read, so
	 * it is resolved out of band. */
	if (cli_path != NULL && *cli_path != '\0') {
		path = cli_path;
	} else {
		const char *envpath = getenv("UDPCHAINS_CONFIG");
		if (envpath != NULL && *envpath != '\0') {
			path = envpath;
		} else {
			const char *home = getenv("HOME");
			if (home != NULL && *home != '\0') {
				snprintf(home_path, sizeof(home_path),
				         "%s/.udpchains.conf", home);
				if (access(home_path, R_OK) == 0)
					path = home_path;
			}
			if (path == NULL && access("/etc/udpchains.conf", R_OK) == 0)
				path = "/etc/udpchains.conf";
		}
	}

	if (path != NULL) {
		udpc_config_init(&filecfg);
		if (udpc_config_read_file(&filecfg, path, &ferr, &fline) != 0) {
			bool explicit_path =
				(cli_path != NULL && *cli_path != '\0') ||
				getenv("UDPCHAINS_CONFIG") != NULL;

			/* An explicitly named file that is missing or broken is
			 * fatal (FR-C-03).  A default-location file that simply
			 * does not exist is not an error. */
			if (explicit_path || strcmp(ferr, "no such file") != 0) {
				/* Written once during single-threaded start-up:
				 * the wrapper before exec, or the shim under
				 * pthread_once. */
				static char buf[4608];
				if (fline > 0)
					snprintf(buf, sizeof(buf), "%.4095s:%d: %.400s",
					         path, fline, ferr);
				else
					snprintf(buf, sizeof(buf), "%.4095s: %.400s", path,
					         ferr);
				*err = buf;
				return -1;
			}
		} else {
			udpc_config_merge(cfg, &filecfg);
		}
	}

	udpc_config_init(&envcfg);
	if (udpc_config_from_env(&envcfg, err) != 0)
		return -1;
	udpc_config_merge(cfg, &envcfg);

	return 0;
}

/* The proxy as a numeric "host:port" or "[v6]:port" -- a v6 scope kept, as
 * getnameinfo writes it (fe80::1%eth0). */
static int numeric_proxy(const struct udpc_config *cfg, char *out, size_t outlen)
{
	char host[NI_MAXHOST], serv[NI_MAXSERV];
	int n;

	if (getnameinfo((const struct sockaddr *)&cfg->proxy,
	                udpc_sa_len((const struct sockaddr *)&cfg->proxy), host,
	                sizeof(host), serv, sizeof(serv),
	                NI_NUMERICHOST | NI_NUMERICSERV) != 0)
		return -1;
	n = snprintf(out, outlen, cfg->proxy.ss_family == AF_INET6 ? "[%s]:%s" : "%s:%s",
	             host, serv);
	return (n < 0 || (size_t)n >= outlen) ? -1 : 0;
}

/* D-38: hop n's credentials, for n from 2, exported as hop 1's are below: the
 * username, and where the password is, never the password.  A hop past the end
 * of the chain, or one without credentials, leaves nothing behind. */
static int export_hop_creds(const struct udpc_config *cfg, unsigned n)
{
	const struct udpc_hop *h = &cfg->hops[n - 2];
	char user[64], file[64], conf[64], pw[64];
	bool in_chain = n - 2 < cfg->nextra;

	snprintf(user, sizeof(user), "UDPCHAINS_USERNAME_%u", n);
	snprintf(file, sizeof(file), "UDPCHAINS_PASSWORD_FILE_%u", n);
	snprintf(conf, sizeof(conf), "UDPCHAINS_PASSWORD_CONFIG_%u", n);
	snprintf(pw, sizeof(pw), "UDPCHAINS_PASSWORD_%u", n);

	if (!in_chain || !h->have_credentials) {
		unsetenv(user);
		unsetenv(file);
		unsetenv(conf);
		unsetenv(pw);
		return 0;
	}
	if (h->username[0] != '\0' ? setenv(user, h->username, 1) != 0
	                           : unsetenv(user) != 0)
		return -1;
	unsetenv(conf);
	if (h->password_file[0] != '\0') {
		if (setenv(file, h->password_file, 1) != 0)
			return -1;
		unsetenv(pw);
	} else if (h->password_config[0] != '\0') {
		if (setenv(conf, h->password_config, 1) != 0)
			return -1;
		unsetenv(pw);
		unsetenv(file);
	}
	return 0;
}

int udpc_config_export(const struct udpc_config *cfg)
{
	char buf[64], proxy[NI_MAXHOST + NI_MAXSERV + 4];
	char list[sizeof(proxy) + (UDPC_CHAIN_MAX - 1) * 257];
	size_t off;
	unsigned i, n;

	/* D-27: the ADDRESS the wrapper resolved and checked, not the name.
	 * Exported by name, every process started under the shim looked the
	 * proxy up again -- directly, since that lookup must bypass the proxy
	 * it is trying to find -- and could reach a different address.  Later
	 * hops are exported as written: only the hop before each may resolve
	 * it (D-39). */
	if (numeric_proxy(cfg, proxy, sizeof(proxy)) != 0)
		snprintf(proxy, sizeof(proxy), "%s", cfg->proxy_spec);
	off = (size_t)snprintf(list, sizeof(list), "%s", proxy);
	for (i = 0; i < cfg->nextra && off < sizeof(list); i++)
		off += (size_t)snprintf(list + off, sizeof(list) - off, ",%s",
		                        cfg->hops[i].spec);
	if (setenv("UDPCHAINS_PROXY", list, 1) != 0)
		return -1;
	for (n = 2; n <= UDPC_CHAIN_MAX; n++)
		if (export_hop_creds(cfg, n) != 0)
			return -1;

	snprintf(buf, sizeof(buf), "%zu", cfg->max_datagram);
	if (setenv("UDPCHAINS_MAX_DATAGRAM", buf, 1) != 0)
		return -1;

	snprintf(buf, sizeof(buf), "%d", cfg->connect_timeout_ms);
	if (setenv("UDPCHAINS_CONNECT_TIMEOUT", buf, 1) != 0)
		return -1;

	/* D-45: unset is exported as unset, so the shim works the default out
	 * from the chain it is given. */
	if (cfg->chain_timeout_set) {
		snprintf(buf, sizeof(buf), "%d", cfg->chain_timeout_ms);
		if (setenv("UDPCHAINS_CHAIN_TIMEOUT", buf, 1) != 0)
			return -1;
	} else {
		unsetenv("UDPCHAINS_CHAIN_TIMEOUT");
	}

	if (setenv("UDPCHAINS_STRICT_LOOPBACK", cfg->strict_loopback ? "1" : "0",
	           1) != 0)
		return -1;
	/* D-49, D-55: the wrapper's settings alone; the program is not told. */
	unsetenv("UDPCHAINS_SUPERVISE");
	unsetenv("UDPCHAINS_ALLOW_RESOLVER_DAEMONS");

	/* D-22 resolver settings.  An unset dns is exported as unset, never as
	 * a default: the shim must fail lookups rather than pick a resolver. */
	if (cfg->dns_set) {
		if (setenv("UDPCHAINS_DNS", cfg->dns_spec, 1) != 0)
			return -1;
	} else {
		unsetenv("UDPCHAINS_DNS");
	}
	snprintf(buf, sizeof(buf), "%d", cfg->dns_timeout_ms);
	if (setenv("UDPCHAINS_DNS_TIMEOUT", buf, 1) != 0)
		return -1;
	if (cfg->dns_search[0] != '\0') {
		if (setenv("UDPCHAINS_DNS_SEARCH", cfg->dns_search, 1) != 0)
			return -1;
	} else {
		unsetenv("UDPCHAINS_DNS_SEARCH");
	}
	if (setenv("UDPCHAINS_HOSTS_FILE", cfg->hosts_file, 1) != 0)
		return -1;

	/* Verbosity is exported as the resolved level so the shim does not have
	 * to re-derive it from the -q/-v pair. */
	if (cfg->verbosity == UDPC_QUIET) {
		if (setenv("UDPCHAINS_QUIET", "1", 1) != 0)
			return -1;
		unsetenv("UDPCHAINS_DEBUG");
	} else if (cfg->verbosity == UDPC_DEBUG) {
		if (setenv("UDPCHAINS_DEBUG", "1", 1) != 0)
			return -1;
		unsetenv("UDPCHAINS_QUIET");
	} else {
		unsetenv("UDPCHAINS_QUIET");
		unsetenv("UDPCHAINS_DEBUG");
	}

	/* Credentials for the shim's RFC 1929 exchange (FR-P-09, D-20).  Never
	 * via argv (SEC-03), and -- D-25 -- never the password itself via the
	 * environment either.  The target and every process it starts inherit
	 * the environment, and anything that dumps it (a crash reporter, a CI
	 * log, a stray `env`) would print the secret.  So the wrapper exports
	 * WHERE the password is -- the password file, or the config file
	 * holding it inline -- and each shim reads it from there.  A password
	 * the user supplied as UDPCHAINS_PASSWORD is already in the environment
	 * by their choice, and is left as it is. */
	if (cfg->have_credentials) {
		if (cfg->username[0] != '\0' &&
		    setenv("UDPCHAINS_USERNAME", cfg->username, 1) != 0)
			return -1;
		unsetenv("UDPCHAINS_PASSWORD_CONFIG");
		if (cfg->password_file[0] != '\0') {
			if (setenv("UDPCHAINS_PASSWORD_FILE", cfg->password_file, 1) != 0)
				return -1;
			unsetenv("UDPCHAINS_PASSWORD");
		} else if (cfg->password_config[0] != '\0') {
			if (setenv("UDPCHAINS_PASSWORD_CONFIG", cfg->password_config,
			           1) != 0)
				return -1;
			unsetenv("UDPCHAINS_PASSWORD");
			unsetenv("UDPCHAINS_PASSWORD_FILE");
		}
	}

	/* The shim must not re-read any file: the wrapper already resolved
	 * everything, and re-reading could pick up a file that changed between
	 * exec and first use -- or a different one entirely (D-27). */
	unsetenv("UDPCHAINS_CONFIG");
	if (setenv("UDPCHAINS_RESOLVED", "1", 1) != 0)
		return -1;
	return 0;
}

int udpc_config_load_shim(struct udpc_config *cfg, const char **err)
{
	/* Static, for the reason given in udpc_config_load_layers. */
	static struct udpc_config envcfg;

	udpc_config_defaults(cfg);

	if (getenv("UDPCHAINS_RESOLVED") != NULL) {
		/* The wrapper has already warned about any file's permissions;
		 * each process under it saying so again is noise (D-33). */
		g_quiet_file_warnings = true;
		/* D-27: the wrapper exported a complete, resolved configuration,
		 * and it is the whole of it.  Consulting the default config files
		 * as well, as this once did, let ~/.udpchains.conf supply
		 * credentials to a run whose -f named a different file, and let a
		 * broken home file break the program after the wrapper had
		 * reported success. */
		udpc_config_init(&envcfg);
		if (udpc_config_from_env(&envcfg, err) != 0)
			return -1;
		udpc_config_merge(cfg, &envcfg);
	} else {
		/* A bare LD_PRELOAD, without the wrapper: the files are the only
		 * configuration there is, with the environment above them. */
		if (udpc_config_load_layers(cfg, NULL, err) != 0)
			return -1;
	}

	return udpc_config_finalize(cfg, err);
}

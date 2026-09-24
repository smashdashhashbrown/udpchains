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

	if (m & UDPC_SET_PROXY) {
		memcpy(dst->proxy_spec, src->proxy_spec, sizeof(dst->proxy_spec));
		dst->proxy_set = src->proxy_set;
	}
	if (m & UDPC_SET_MAX_DATAGRAM)
		dst->max_datagram = src->max_datagram;
	if (m & UDPC_SET_STRICT_LOOPBACK)
		dst->strict_loopback = src->strict_loopback;
	if (m & UDPC_SET_CONNECT_TIMEOUT)
		dst->connect_timeout_ms = src->connect_timeout_ms;
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

/* SEC-03: reads a password from a file, so it never appears in argv or in
 * `ps` output.  Strips exactly one trailing newline. */
static int read_password_file(const char *path, char *out, size_t outlen,
                              const char **err)
{
	int fd;
	ssize_t n;
	struct stat st;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		*err = "cannot open password file";
		return -1;
	}
	if (fstat(fd, &st) == 0 && (st.st_mode & (S_IRWXG | S_IRWXO)) != 0)
		udpc_warn("password file %s is group- or world-accessible", path);

	n = read(fd, out, outlen - 1);
	close(fd);
	if (n < 0) {
		*err = "cannot read password file";
		return -1;
	}
	out[n] = '\0';
	if (n > 0 && out[n - 1] == '\n')
		out[n - 1] = '\0';
	return 0;
}

int udpc_config_set(struct udpc_config *cfg, const char *key, const char *value,
                    const char **err)
{
	long n;

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
		if (parse_long(value, 1, 600000, &n) != 0) {
			*err = "connect_timeout must be 1..600000 ms";
			return -1;
		}
		cfg->connect_timeout_ms = (int)n;
		cfg->set_mask |= UDPC_SET_CONNECT_TIMEOUT;
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
	if (strcmp(key, "username") == 0) {
		if (strlen(value) >= sizeof(cfg->username)) {
			*err = "username too long";
			return -1;
		}
		snprintf(cfg->username, sizeof(cfg->username), "%s", value);
		cfg->set_mask |= UDPC_SET_USERNAME;
		return 0;
	}
	if (strcmp(key, "password") == 0) {
		if (strlen(value) >= sizeof(cfg->password)) {
			*err = "password too long";
			return -1;
		}
		snprintf(cfg->password, sizeof(cfg->password), "%s", value);
		/* An inline value.  If it came from a config file,
		 * udpc_config_read_file records which one (D-25). */
		cfg->password_file[0] = '\0';
		cfg->password_config[0] = '\0';
		cfg->set_mask |= UDPC_SET_PASSWORD;
		return 0;
	}
	if (strcmp(key, "password_file") == 0) {
		char *abs;

		if (read_password_file(value, cfg->password, sizeof(cfg->password),
		                       err) != 0)
			return -1;
		/* D-25: remembered as an ABSOLUTE path, so a target that changes
		 * directory -- or a descendant that starts elsewhere -- can still
		 * read it. */
		abs = realpath(value, NULL);
		snprintf(cfg->password_file, sizeof(cfg->password_file), "%s",
		         abs != NULL ? abs : value);
		free(abs);
		cfg->password_config[0] = '\0';
		cfg->set_mask |= UDPC_SET_PASSWORD;
		return 0;
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

	/* FR-C-04 ([ProxyList] stanzas) is deferred (D-08).  Recognise the
	 * header specifically so a user who brings a proxychains.conf gets a
	 * useful message instead of "unknown key". */
	if (strcasecmp(key, "[proxylist]") == 0) {
		*err = "proxychains-style [ProxyList] is not supported in v1 "
		       "(FR-C-04, deferred); use 'proxy = host:port'";
		return -1;
	}

	*err = "unknown configuration key";
	return -1;
}

int udpc_config_read_file(struct udpc_config *cfg, const char *path,
                          const char **err, int *errline)
{
	FILE *f;
	char line[1024];
	int lineno = 0;
	struct stat st;

	*err = NULL;
	*errline = 0;

	f = fopen(path, "re");
	if (f == NULL) {
		*err = (errno == ENOENT) ? "no such file" : strerror(errno);
		return -1;
	}

	/* SEC-04: this file directs where traffic goes.  If anyone else can
	 * write it, they can redirect the traffic. */
	if (fstat(fileno(f), &st) == 0 && (st.st_mode & (S_IWGRP | S_IWOTH)) != 0)
		udpc_warn("config file %s is group- or world-writable; "
		          "it controls where your traffic goes",
		          path);

	while (fgets(line, sizeof(line), f) != NULL) {
		char *p = line, *key, *value, *eq, *end;
		lineno++;

		p += strspn(p, " \t");
		end = strchr(p, '\n');
		if (end != NULL)
			*end = '\0';
		else if (strlen(p) == sizeof(line) - 1) {
			*err = "line too long";
			*errline = lineno;
			fclose(f);
			return -1;
		}

		if (*p == '\0' || *p == '#' || *p == ';')
			continue;

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

		if (udpc_config_set(cfg, key, value, err) != 0) {
			*errline = lineno;
			fclose(f);
			return -1;
		}
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
	 * the file, never by copying the value into the environment. */
	if ((cfg->set_mask & UDPC_SET_PASSWORD) && cfg->password_file[0] == '\0') {
		char *abs = realpath(path, NULL);

		snprintf(cfg->password_config, sizeof(cfg->password_config), "%s",
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
	{ "UDPCHAINS_PROXY", "proxy" },
	{ "UDPCHAINS_MAX_DATAGRAM", "max_datagram" },
	{ "UDPCHAINS_STRICT_LOOPBACK", "strict_loopback" },
	{ "UDPCHAINS_CONNECT_TIMEOUT", "connect_timeout" },
	{ "UDPCHAINS_USERNAME", "username" },
	{ "UDPCHAINS_PASSWORD_FILE", "password_file" },
	{ "UDPCHAINS_DNS", "dns" },
	{ "UDPCHAINS_DNS_TIMEOUT", "dns_timeout" },
	{ "UDPCHAINS_DNS_SEARCH", "dns_search" },
	{ "UDPCHAINS_HOSTS_FILE", "hosts_file" },
};

int udpc_config_from_env(struct udpc_config *cfg, const char **err)
{
	size_t i;
	const char *v;

	*err = NULL;

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
		struct udpc_config tmp;
		const char *ferr = NULL;
		int fline = 0;
		int rc;

		udpc_config_init(&tmp);
		rc = udpc_config_read_file(&tmp, v, &ferr, &fline);
		if (rc == 0 && (tmp.set_mask & UDPC_SET_PASSWORD)) {
			memcpy(cfg->password, tmp.password, sizeof(cfg->password));
			snprintf(cfg->password_config, sizeof(cfg->password_config),
			         "%s", v);
			cfg->password_file[0] = '\0';
			cfg->set_mask |= UDPC_SET_PASSWORD;
		}
		explicit_bzero(tmp.password, sizeof(tmp.password));
		if (rc != 0 || !(cfg->set_mask & UDPC_SET_PASSWORD)) {
			*err = "cannot read the password from the file named by "
			       "UDPCHAINS_PASSWORD_CONFIG";
			return -1;
		}
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

	if (getenv("UDPCHAINS_QUIET") != NULL) {
		cfg->verbosity = UDPC_QUIET;
		cfg->set_mask |= UDPC_SET_VERBOSITY;
	}
	if (getenv("UDPCHAINS_DEBUG") != NULL) {
		cfg->verbosity = UDPC_DEBUG;
		cfg->set_mask |= UDPC_SET_VERBOSITY;
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
	struct udpc_config filecfg, envcfg;
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

int udpc_config_export(const struct udpc_config *cfg)
{
	char buf[64], proxy[NI_MAXHOST + NI_MAXSERV + 4];

	/* D-27: the ADDRESS the wrapper resolved and checked, not the name.
	 * Exported by name, every process started under the shim looked the
	 * proxy up again -- directly, since that lookup must bypass the proxy
	 * it is trying to find -- and could reach a different address. */
	if (numeric_proxy(cfg, proxy, sizeof(proxy)) != 0)
		snprintf(proxy, sizeof(proxy), "%s", cfg->proxy_spec);
	if (setenv("UDPCHAINS_PROXY", proxy, 1) != 0)
		return -1;

	snprintf(buf, sizeof(buf), "%zu", cfg->max_datagram);
	if (setenv("UDPCHAINS_MAX_DATAGRAM", buf, 1) != 0)
		return -1;

	snprintf(buf, sizeof(buf), "%d", cfg->connect_timeout_ms);
	if (setenv("UDPCHAINS_CONNECT_TIMEOUT", buf, 1) != 0)
		return -1;

	if (setenv("UDPCHAINS_STRICT_LOOPBACK", cfg->strict_loopback ? "1" : "0",
	           1) != 0)
		return -1;

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
	struct udpc_config envcfg;

	udpc_config_defaults(cfg);

	if (getenv("UDPCHAINS_RESOLVED") != NULL) {
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

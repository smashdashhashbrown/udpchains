/* wrapper.c -- the `udpchains` executable (FR-C-01, FR-C-03, SEC-06, D-10).
 *
 * Resolves configuration, refuses to run if it cannot, sets LD_PRELOAD, and
 * execs the target.  Configuration is resolved BEFORE exec so that a failure is
 * attributable to the wrapper rather than being emitted from inside the
 * target's address space.
 */
#include "compat.h"

#include <errno.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "addr.h"
#include "config.h"
#include "log.h"

#ifndef UDPCHAINS_LIBDIR
#define UDPCHAINS_LIBDIR "/usr/local/lib"
#endif

#ifndef UDPCHAINS_VERSION
#define UDPCHAINS_VERSION "0.1.0"
#endif

static void usage(FILE *out)
{
	fprintf(out,
	        "usage: udpchains [options] <program> [args...]\n"
	        "\n"
	        "Routes a dynamically-linked program's UDP traffic through a\n"
	        "SOCKS5 proxy that supports UDP ASSOCIATE.\n"
	        "\n"
	        "options:\n"
	        "  -f <file>    config file (default: $UDPCHAINS_CONFIG,\n"
	        "               ~/.udpchains.conf, /etc/udpchains.conf)\n"
	        "  -p <addr>    proxy address as host:port or [v6]:port\n"
	        "  -q           quiet: errors only\n"
	        "  -v           verbose: log protocol steps (never payload)\n"
	        "  -V           print version and exit\n"
	        "  -h           this help\n"
	        "\n"
	        "environment:\n"
	        "  UDPCHAINS_PROXY, UDPCHAINS_CONFIG, UDPCHAINS_MAX_DATAGRAM,\n"
	        "  UDPCHAINS_STRICT_LOOPBACK, UDPCHAINS_CONNECT_TIMEOUT,\n"
	        "  UDPCHAINS_USERNAME, UDPCHAINS_PASSWORD_FILE\n"
	        "\n"
	        "Credentials are never accepted on the command line, because argv\n"
	        "is visible in ps(1).  Use a file or the environment.\n"
	        "\n"
	        "Does not work for: statically-linked binaries, Go binaries,\n"
	        "setuid/setgid binaries, or programs issuing raw syscalls.\n"
	        "Local UDP services and service discovery do not work under the\n"
	        "shim -- see the README.\n");
}

/* Resolves what execvp() would actually run, so the SEC-06 check inspects the
 * real file rather than a name. */
static int resolve_program(const char *name, char *out, size_t outlen)
{
	const char *path, *p;

	if (strchr(name, '/') != NULL) {
		if (snprintf(out, outlen, "%s", name) >= (int)outlen)
			return -1;
		return access(out, X_OK) == 0 ? 0 : -1;
	}

	path = getenv("PATH");
	if (path == NULL || *path == '\0')
		path = "/usr/local/bin:/usr/bin:/bin";

	for (p = path; *p != '\0';) {
		const char *end = strchr(p, ':');
		size_t len = (end != NULL) ? (size_t)(end - p) : strlen(p);

		if (len == 0) {
			/* An empty PATH element means the current directory. */
			if (snprintf(out, outlen, "./%s", name) < (int)outlen &&
			    access(out, X_OK) == 0)
				return 0;
		} else if (len < outlen) {
			if (snprintf(out, outlen, "%.*s/%s", (int)len, p, name) <
			        (int)outlen &&
			    access(out, X_OK) == 0)
				return 0;
		}

		if (end == NULL)
			break;
		p = end + 1;
	}
	return -1;
}

/* SEC-06.  The loader ignores LD_PRELOAD for AT_SECURE binaries, so such a
 * program would run completely unproxied with no indication.  That is exactly
 * the silent-leak failure this project exists to prevent (baseline 0.3.1), so
 * the wrapper refuses rather than running it.
 *
 * AT_SECURE is set for setuid and setgid binaries, and also for binaries
 * carrying file capabilities -- which is why the xattr is checked too. */
static int refuse_if_privileged(const char *program)
{
	struct stat st;
	ssize_t caplen;

	if (stat(program, &st) != 0) {
		fprintf(stderr, "udpchains: cannot stat %s: %s\n", program,
		        strerror(errno));
		return -1;
	}

	if (st.st_mode & S_ISUID) {
		fprintf(stderr,
		        "udpchains: refusing to run %s: it is setuid, and the "
		        "loader ignores LD_PRELOAD for setuid binaries.\n"
		        "udpchains: running it would proxy nothing and warn about "
		        "nothing (SEC-06).\n",
		        program);
		return -1;
	}
	if (st.st_mode & S_ISGID) {
		fprintf(stderr,
		        "udpchains: refusing to run %s: it is setgid, and the "
		        "loader ignores LD_PRELOAD for setgid binaries.\n"
		        "udpchains: running it would proxy nothing and warn about "
		        "nothing (SEC-06).\n",
		        program);
		return -1;
	}

	caplen = getxattr(program, "security.capability", NULL, 0);
	if (caplen > 0) {
		fprintf(stderr,
		        "udpchains: refusing to run %s: it carries file "
		        "capabilities, and the loader ignores LD_PRELOAD for "
		        "such binaries (SEC-06).\n",
		        program);
		return -1;
	}

	return 0;
}

/* Locates libudpchains.so: an explicit override, then next to the wrapper (the
 * build tree and a self-contained install), then the configured libdir. */
static int find_shim(char *out, size_t outlen)
{
	const char *override = getenv("UDPCHAINS_LIB");
	char exe[4096];
	ssize_t n;

	if (override != NULL && *override != '\0') {
		if (access(override, R_OK) != 0) {
			fprintf(stderr, "udpchains: UDPCHAINS_LIB=%s is not readable\n",
			        override);
			return -1;
		}
		snprintf(out, outlen, "%s", override);
		return 0;
	}

	n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
	if (n > 0) {
		char dir[4096];
		exe[n] = '\0';
		snprintf(dir, sizeof(dir), "%s", exe);
		snprintf(out, outlen, "%s/libudpchains.so", dirname(dir));
		if (access(out, R_OK) == 0)
			return 0;

		snprintf(dir, sizeof(dir), "%s", exe);
		snprintf(out, outlen, "%s/../lib/libudpchains.so", dirname(dir));
		if (access(out, R_OK) == 0)
			return 0;
	}

	snprintf(out, outlen, "%s/libudpchains.so", UDPCHAINS_LIBDIR);
	if (access(out, R_OK) == 0)
		return 0;

	fprintf(stderr,
	        "udpchains: cannot find libudpchains.so (looked next to the "
	        "wrapper and in %s).\n"
	        "udpchains: set UDPCHAINS_LIB to its path.\n",
	        UDPCHAINS_LIBDIR);
	return -1;
}

static int set_preload(const char *shim)
{
	const char *existing = getenv("LD_PRELOAD");
	char buf[8192];

	if (existing != NULL && *existing != '\0') {
		if (snprintf(buf, sizeof(buf), "%s:%s", shim, existing) >=
		    (int)sizeof(buf)) {
			fprintf(stderr, "udpchains: LD_PRELOAD too long\n");
			return -1;
		}
	} else {
		snprintf(buf, sizeof(buf), "%s", shim);
	}
	return setenv("LD_PRELOAD", buf, 1);
}

int main(int argc, char **argv)
{
	struct udpc_config cfg, cli;
	const char *err = NULL;
	const char *cli_path = NULL;
	char program[4096];
	char shim[4096];
	char addrbuf[UDPC_ADDRSTRLEN];
	int i;

	udpc_config_init(&cli);

	for (i = 1; i < argc; i++) {
		const char *a = argv[i];

		if (strcmp(a, "--") == 0) {
			i++;
			break;
		}
		if (a[0] != '-' || a[1] == '\0')
			break;

		if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
			usage(stdout);
			return 0;
		}
		if (strcmp(a, "-V") == 0 || strcmp(a, "--version") == 0) {
			printf("udpchains %s\n", UDPCHAINS_VERSION);
			return 0;
		}
		if (strcmp(a, "-q") == 0) {
			cli.verbosity = UDPC_QUIET;
			cli.set_mask |= UDPC_SET_VERBOSITY;
			continue;
		}
		if (strcmp(a, "-v") == 0) {
			cli.verbosity = UDPC_DEBUG;
			cli.set_mask |= UDPC_SET_VERBOSITY;
			continue;
		}
		if (strcmp(a, "-f") == 0) {
			if (++i >= argc) {
				fprintf(stderr, "udpchains: -f needs a file\n");
				return 1;
			}
			cli_path = argv[i];
			continue;
		}
		if (strcmp(a, "-p") == 0) {
			if (++i >= argc) {
				fprintf(stderr, "udpchains: -p needs an address\n");
				return 1;
			}
			if (udpc_config_set(&cli, "proxy", argv[i], &err) != 0) {
				fprintf(stderr, "udpchains: -p: %s\n", err);
				return 1;
			}
			continue;
		}

		/* SEC-03: refuse credentials on the command line explicitly,
		 * rather than letting them fall through to "unknown option".
		 * argv is world-readable via ps(1). */
		if (strncmp(a, "--password", 10) == 0 ||
		    strcmp(a, "-w") == 0) {
			fprintf(stderr,
			        "udpchains: passwords are not accepted on the "
			        "command line (visible in ps).\n"
			        "udpchains: use UDPCHAINS_PASSWORD_FILE or "
			        "'password_file =' in the config file (SEC-03).\n");
			return 1;
		}

		fprintf(stderr, "udpchains: unknown option '%s'\n", a);
		usage(stderr);
		return 1;
	}

	if (i >= argc) {
		fprintf(stderr, "udpchains: no program given\n");
		usage(stderr);
		return 1;
	}

	/* Layers below the command line, then the command line on top. */
	if (udpc_config_load_layers(&cfg, cli_path, &err) != 0) {
		fprintf(stderr, "udpchains: %s\n", err);
		return 1;
	}
	udpc_config_merge(&cfg, &cli);
	udpc_log_set_level(cfg.verbosity);

	/* FR-C-03 / D-10: refuse to run rather than run unproxied. */
	if (udpc_config_finalize(&cfg, &err) != 0) {
		fprintf(stderr, "udpchains: %s\n", err);
		fprintf(stderr,
		        "udpchains: refusing to run '%s' unproxied.\n", argv[i]);
		return 1;
	}

	if (resolve_program(argv[i], program, sizeof(program)) != 0) {
		fprintf(stderr, "udpchains: %s: not found or not executable\n",
		        argv[i]);
		return 127;
	}

	if (refuse_if_privileged(program) != 0)
		return 1;

	if (find_shim(shim, sizeof(shim)) != 0)
		return 1;

	if (udpc_config_export(&cfg) != 0 || set_preload(shim) != 0) {
		fprintf(stderr, "udpchains: cannot set up the environment: %s\n",
		        strerror(errno));
		return 1;
	}

	udpc_debug("proxy %s -> %s%s, max_datagram %zu", cfg.proxy_spec,
	           udpc_addr_str((const struct sockaddr *)&cfg.proxy, addrbuf,
	                         sizeof(addrbuf)),
	           cfg.proxy_is_local ? " (local)" : "", cfg.max_datagram);

	execvp(argv[i], &argv[i]);

	fprintf(stderr, "udpchains: cannot exec %s: %s\n", argv[i],
	        strerror(errno));
	return 126;
}

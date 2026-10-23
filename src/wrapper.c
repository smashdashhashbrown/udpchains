/* wrapper.c -- the `udpchains` executable (FR-C-01, FR-C-03, SEC-06, D-10).
 *
 * Resolves configuration, refuses to run if it cannot, sets LD_PRELOAD, and
 * execs the target.  Configuration is resolved BEFORE exec so that a failure is
 * attributable to the wrapper rather than being emitted from inside the
 * target's address space.  With --supervise it runs the target under the
 * supervisor instead (supervise.c, D-49).
 */
#include "compat.h"

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "addr.h"
#include "config.h"
#include "log.h"
#include "supervise.h"

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
	        "SOCKS5 proxy that supports UDP ASSOCIATE, or a chain of them.\n"
	        "\n"
	        "options:\n"
	        "  -f <file>    config file, or a proxychains.conf (default:\n"
	        "               $UDPCHAINS_CONFIG, ~/.udpchains.conf,\n"
	        "               /etc/udpchains.conf)\n"
	        "  -p <addr>    proxy address as host:port or [v6]:port; repeat\n"
	        "               it for a chain, hop 1 first\n"
	        "  -q           quiet: errors only\n"
	        "  -v           verbose: log protocol steps (never payload)\n"
	        "  -V           print version and exit\n"
	        "  -h           this help\n"
	        "\n"
	        "environment:\n"
	        "  UDPCHAINS_PROXY, UDPCHAINS_CONFIG, UDPCHAINS_MAX_DATAGRAM,\n"
	        "  UDPCHAINS_STRICT_LOOPBACK, UDPCHAINS_CONNECT_TIMEOUT,\n"
	        "  UDPCHAINS_CHAIN_TIMEOUT,\n"
	        "  UDPCHAINS_USERNAME, UDPCHAINS_PASSWORD_FILE, and for hop n\n"
	        "  of a chain UDPCHAINS_USERNAME_<n>, UDPCHAINS_PASSWORD_FILE_<n>,\n"
	        "  UDPCHAINS_DNS, UDPCHAINS_DNS_TIMEOUT, UDPCHAINS_DNS_SEARCH,\n"
	        "  UDPCHAINS_HOSTS_FILE\n"
	        "\n"
	        "Name lookups are answered through the proxy, never by this host's\n"
	        "resolver.  Set UDPCHAINS_DNS (or 'dns =' in the config file) to a\n"
	        "numeric resolver address; without one, lookups needing DNS fail.\n"
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


/* Reads the ELF class and machine of an object, so the shim can be compared
 * against this wrapper rather than against a compile-time #ifdef ladder. */
static int elf_ident(const char *path, unsigned char *cls, uint16_t *machine)
{
	ElfW(Ehdr) eh;
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	ssize_t n;

	if (fd < 0)
		return -1;
	n = read(fd, &eh, sizeof(eh));
	close(fd);

	if (n != (ssize_t)sizeof(eh) || memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0)
		return -1;

	*cls = eh.e_ident[EI_CLASS];
	*machine = eh.e_machine;
	return 0;
}

/* SEC-06, second half.  find_shim() proves the file is READABLE; this proves it
 * is LOADABLE, which is not the same thing and fails in ways that are hard to
 * attribute after the fact.
 *
 * If the loader cannot map the shim it prints a warning and RUNS THE PROGRAM
 * ANYWAY, unproxied.  That is the exact outcome SEC-06 refuses to allow for
 * setuid binaries -- LD_PRELOAD ignored, traffic going direct -- reached by a
 * different route, and for a tool whose distinguishing claim is that it fails
 * closed it is the worst possible failure mode: silent, and visible only as one
 * line on stderr that a scripted run will not notice.
 *
 * Three causes, all seen in practice and each with its own diagnostic:
 *
 *   - the filesystem is mounted noexec, or a security policy (SELinux,
 *     AppArmor) denies mapping the file executable.  The PROT_EXEC probe is
 *     what catches this; it is the same mapping the loader will attempt.
 *   - the object is for another architecture, from copying a build between
 *     hosts rather than rebuilding.
 *   - the file is truncated or otherwise not an ELF object, from an interrupted
 *     transfer.
 */
static int check_shim_loadable(const char *shim)
{
	unsigned char self_cls = 0, shim_cls = 0;
	uint16_t self_machine = 0, shim_machine = 0;
	long pagesize;
	void *p;
	int fd;

	if (elf_ident(shim, &shim_cls, &shim_machine) != 0) {
		fprintf(stderr,
		        "udpchains: %s is not a valid ELF shared object.\n"
		        "udpchains: it may be truncated or incompletely copied; "
		        "rebuild it with make.\n"
		        "udpchains: refusing to run unproxied (SEC-06).\n",
		        shim);
		return -1;
	}

	/* A mismatch here means the object was built elsewhere.  Compared
	 * against this wrapper, which is by definition the right answer. */
	if (elf_ident("/proc/self/exe", &self_cls, &self_machine) == 0 &&
	    (shim_cls != self_cls || shim_machine != self_machine)) {
		fprintf(stderr,
		        "udpchains: %s was built for a different architecture "
		        "(ELF class %u machine %u; this wrapper is class %u "
		        "machine %u).\n"
		        "udpchains: rebuild it on this host rather than copying "
		        "the binary.\n"
		        "udpchains: refusing to run unproxied (SEC-06).\n",
		        shim, shim_cls, shim_machine, self_cls, self_machine);
		return -1;
	}

	pagesize = sysconf(_SC_PAGESIZE);
	if (pagesize <= 0)
		pagesize = 4096;

	fd = open(shim, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "udpchains: cannot open %s: %s\n", shim,
		        strerror(errno));
		return -1;
	}

	/* The same mapping ld.so will make for the text segment.  If this is
	 * refused, the preload will be refused. */
	p = mmap(NULL, (size_t)pagesize, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd,
	         0);
	if (p == MAP_FAILED) {
		int err = errno;

		close(fd);
		fprintf(stderr,
		        "udpchains: %s cannot be mapped executable: %s\n",
		        shim, strerror(err));
		if (err == EACCES || err == EPERM)
			fprintf(stderr,
			        "udpchains: the filesystem is probably mounted "
			        "noexec, or a security policy (SELinux, "
			        "AppArmor) forbids it.\n"
			        "udpchains: check with: findmnt -no OPTIONS -T "
			        "%s\n"
			        "udpchains: then move the shim to a filesystem "
			        "that permits execution.\n",
			        shim);
		fprintf(stderr,
		        "udpchains: refusing to run unproxied -- the loader "
		        "would ignore LD_PRELOAD and the program would send "
		        "directly (SEC-06).\n");
		return -1;
	}

	munmap(p, (size_t)pagesize);
	close(fd);
	return 0;
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

/* D-49: a supervised program is not also given the shim.  Removes
 * libudpchains.so from an LD_PRELOAD the program would inherit, keeping
 * whatever else is there.  Returns 1 if it was there, 0 if not, -1 on
 * failure. */
static int strip_preload(void)
{
	const char *existing = getenv("LD_PRELOAD");
	char in[8192], out[8192];
	char *tok, *save = NULL;
	size_t off = 0;
	int found = 0;

	if (existing == NULL)
		return 0;
	if (snprintf(in, sizeof(in), "%s", existing) >= (int)sizeof(in))
		return -1;
	out[0] = '\0';
	/* ld.so(8): entries are separated by colons or spaces. */
	for (tok = strtok_r(in, ": ", &save); tok != NULL; tok = strtok_r(NULL, ": ", &save)) {
		const char *base = strrchr(tok, '/');

		if (strcmp(base != NULL ? base + 1 : tok, "libudpchains.so") == 0) {
			found = 1;
			continue;
		}
		off += (size_t)snprintf(out + off, sizeof(out) - off, "%s%s",
		                        off ? ":" : "", tok);
	}
	if ((out[0] != '\0' ? setenv("LD_PRELOAD", out, 1) : unsetenv("LD_PRELOAD")) != 0)
		return -1;
	return found;
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
		if (strcmp(a, "--supervise") == 0) {
			cli.supervise = true;
			cli.set_mask |= UDPC_SET_SUPERVISE;
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
			/* D-38: the first -p is hop 1; each further one is
			 * the next hop. */
			if (((cli.set_mask & UDPC_SET_PROXY)
			         ? udpc_config_append_hop(&cli, argv[i], &err)
			         : udpc_config_set(&cli, "proxy", argv[i], &err)) != 0) {
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

	if (cfg.supervise) {
		int stripped = strip_preload();

		if (stripped < 0) {
			fprintf(stderr, "udpchains: cannot set up the environment: %s\n",
			        strerror(errno));
			return 1;
		}
		/* The same LD_PRELOAD loaded the shim into udpchains itself,
		 * where it would wrap the supervisor's own datagrams to the
		 * relay a second time.  Run again without it, before the
		 * environment is changed in any other way. */
		if (stripped > 0) {
			execv("/proc/self/exe", argv);
			fprintf(stderr, "udpchains: libudpchains.so is preloaded into "
			        "udpchains itself, and it cannot run again without it "
			        "(%s); refusing to supervise '%s' (D-49)\n",
			        strerror(errno), argv[i]);
			return 1;
		}
		if (udpc_config_export(&cfg) != 0) {
			fprintf(stderr, "udpchains: cannot set up the environment: %s\n",
			        strerror(errno));
			return 1;
		}
		/* The supervisor keeps the password: it, not the program,
		 * speaks to the proxy. */
		explicit_bzero(cli.password, sizeof(cli.password));
		return udpc_supervise(&cfg, program, &argv[i]);
	}

	if (find_shim(shim, sizeof(shim)) != 0)
		return 1;

	if (check_shim_loadable(shim) != 0)
		return 1;

	if (udpc_config_export(&cfg) != 0 || set_preload(shim) != 0) {
		fprintf(stderr, "udpchains: cannot set up the environment: %s\n",
		        strerror(errno));
		return 1;
	}
	/* The wrapper needs the password no longer: the target reads it from
	 * wherever it came from (D-25). */
	explicit_bzero(cfg.password, sizeof(cfg.password));
	explicit_bzero(cli.password, sizeof(cli.password));

	udpc_debug("proxy %s -> %s%s, max_datagram %zu", cfg.proxy_spec,
	           udpc_addr_str((const struct sockaddr *)&cfg.proxy, addrbuf,
	                         sizeof(addrbuf)),
	           cfg.proxy_is_local ? " (local)" : "", cfg.max_datagram);
	{
		unsigned k;

		/* Later hops as written: they are never resolved here (D-39). */
		for (k = 0; k < cfg.nextra; k++)
			udpc_debug("then hop %u: %s", k + 2, cfg.hops[k].spec);
	}

	/* D-28: exec the file that was checked, not a name.  execvp() would
	 * search PATH a second time, and the setuid/capability check above
	 * could then have inspected a different file from the one run -- a
	 * swapped binary, or a PATH entry that changed in between.  argv[0]
	 * stays as the user typed it. */
	execv(program, &argv[i]);

	/* execvp's one extra: a file with no #! line and no ELF header is run
	 * by /bin/sh.  Kept, still naming the checked file. */
	if (errno == ENOEXEC) {
		int n = argc - i;
		char **shargv = calloc((size_t)n + 2, sizeof(*shargv));

		if (shargv != NULL) {
			int k;

			shargv[0] = (char *)(uintptr_t)"sh";
			shargv[1] = program;
			for (k = 1; k < n; k++)
				shargv[k + 1] = argv[i + k];
			execv("/bin/sh", shargv);
			free(shargv);
		}
	}

	fprintf(stderr, "udpchains: cannot exec %s: %s\n", argv[i],
	        strerror(errno));
	return 126;
}

/* config.h -- configuration (FR-C-02, FR-C-03, SEC-03, SEC-04, D-10, D-12).
 *
 * Precedence, highest first (FR-C-02):
 *   1. command line          (wrapper only; it exports the result to the shim)
 *   2. environment           UDPCHAINS_PROXY, UDPCHAINS_CONFIG, ...
 *   3. config file           UDPCHAINS_CONFIG, or ~/.udpchains.conf, or
 *                            /etc/udpchains.conf
 *   4. built-in default
 *
 * Precedence is implemented by layering: each layer is parsed into its own
 * struct, recording which keys it set explicitly, and merged over the one below
 * it.  A layer never clobbers a higher one with a value it did not actually
 * specify.
 *
 * D-10: built-in defaults exist only for OPTIONAL settings.  There is no
 * built-in default proxy address.  If no proxy is resolved, the wrapper refuses
 * to exec the target (FR-C-03) rather than running it unproxied.
 */
#ifndef UDPCHAINS_CONFIG_H
#define UDPCHAINS_CONFIG_H

#include "compat.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#define UDPC_DEFAULT_MAX_DATAGRAM 8192  /* D-12: matches the reference proxy */
#define UDPC_DEFAULT_PROXY_PORT 1080
#define UDPC_DEFAULT_CONNECT_TIMEOUT_MS 5000
#define UDPC_DEFAULT_DNS_PORT 53
#define UDPC_DEFAULT_DNS_TIMEOUT_MS 5000 /* D-22: the whole lookup, all attempts */
#define UDPC_DEFAULT_HOSTS_FILE "/etc/hosts"
#define UDPC_MAX_DATAGRAM_CEILING 65507 /* largest a UDP payload can ever be */
#define UDPC_PASSWORD_MAX 255 /* RFC 1929: PLEN is one byte */

/* Which keys a layer set explicitly. */
#define UDPC_SET_PROXY (1u << 0)
#define UDPC_SET_MAX_DATAGRAM (1u << 1)
#define UDPC_SET_STRICT_LOOPBACK (1u << 2)
#define UDPC_SET_CONNECT_TIMEOUT (1u << 3)
#define UDPC_SET_USERNAME (1u << 4)
#define UDPC_SET_PASSWORD (1u << 5)
#define UDPC_SET_VERBOSITY (1u << 6)
#define UDPC_SET_CONFIG_PATH (1u << 7)
#define UDPC_SET_DNS (1u << 8)
#define UDPC_SET_DNS_TIMEOUT (1u << 9)
#define UDPC_SET_DNS_SEARCH (1u << 10)
#define UDPC_SET_HOSTS_FILE (1u << 11)

struct udpc_config {
	uint32_t set_mask; /* UDPC_SET_* explicitly set in this layer */

	bool proxy_set;
	char proxy_spec[256];           /* as written, for diagnostics */
	struct sockaddr_storage proxy;  /* resolved by udpc_config_finalize */
	bool proxy_is_local;            /* D-05 R2 loopback guard */

	size_t max_datagram;            /* D-12: configured, never discovered */
	int verbosity;                  /* enum udpc_verbosity */
	bool strict_loopback;           /* D-05 R2: promote warning to error */
	int connect_timeout_ms;

	/* D-22: the resolver the shim queries through the proxy.  Numeric
	 * only, since a named resolver would need resolving first.  There is
	 * no default: with dns_set false, a lookup that needs DNS fails. */
	bool dns_set;
	char dns_spec[128];
	struct sockaddr_storage dns;    /* resolved by udpc_config_finalize */
	int dns_timeout_ms;
	char dns_search[512];           /* space- or comma-separated; opt-in */
	char hosts_file[1024];

	/* SEC-03: credentials come from a file or the environment, never from
	 * the command line (FR-P-09, D-20). */
	bool have_credentials;
	char username[256];
	char password[256];

	/* D-25: where the password came from, so the wrapper can pass THAT to
	 * the target rather than the secret itself.  At most one is set: the
	 * absolute path of a password file, or of a config file holding
	 * `password =` inline.  Neither means UDPCHAINS_PASSWORD, which the
	 * user put in the environment themselves. */
	char password_file[4096];
	char password_config[4096];

	char config_path[4096];
};

/* Zeroes the layer.  set_mask ends up 0: nothing is explicitly set. */
void udpc_config_init(struct udpc_config *cfg);

/* Built-in defaults for the OPTIONAL settings only.  Leaves proxy unset --
 * there is no default proxy (D-10). */
void udpc_config_defaults(struct udpc_config *cfg);

/* Copies from src into dst every field src set explicitly. */
void udpc_config_merge(struct udpc_config *dst, const struct udpc_config *src);

/* Applies a "key = value" pair to one layer.  Returns 0, or -1 with a static
 * reason in *err.
 *
 * Unknown keys are an error, not a warning: a typo in the file that directs
 * where traffic goes should stop the program, not be silently ignored
 * (FR-C-03). */
int udpc_config_set(struct udpc_config *cfg, const char *key, const char *value,
                    const char **err);

/* Reads a config file into its own layer.  Returns 0 on success, -1 on failure
 * (including a file that exists but does not parse), with a static reason in
 * *err and the offending line in *errline.  A missing file is reported via
 * *err = "no such file" so the caller can decide whether that is fatal.
 *
 * SEC-04: warns if the file is group- or world-writable. */
int udpc_config_read_file(struct udpc_config *cfg, const char *path,
                          const char **err, int *errline);

/* Parses the environment into its own layer. */
int udpc_config_from_env(struct udpc_config *cfg, const char **err);

/* Resolves proxy_spec to an address, computes proxy_is_local, and enforces
 * D-10: fails if no proxy was configured.  Returns 0, or -1 with *err.
 *
 * Calls getaddrinfo when the spec is a name; callers inside the shim must hold
 * the re-entry guard (guard.h). */
int udpc_config_finalize(struct udpc_config *cfg, const char **err);

/* Convenience: layer defaults, file and environment in precedence order,
 * without the command line.  The caller merges its command-line layer on top
 * and then calls udpc_config_finalize. */
int udpc_config_load_layers(struct udpc_config *cfg, const char *cli_path,
                            const char **err);

/* Exports the resolved configuration as canonical UDPCHAINS_* variables so the
 * shim inherits it without re-parsing.  Used by the wrapper before exec. */
int udpc_config_export(const struct udpc_config *cfg);

/* Loads configuration inside the shim.  Launched by the wrapper -- which sets
 * UDPCHAINS_RESOLVED -- only the environment is read; under a bare LD_PRELOAD
 * the config files are read too (D-27).  Returns 0 on success. */
int udpc_config_load_shim(struct udpc_config *cfg, const char **err);

#endif /* UDPCHAINS_CONFIG_H */

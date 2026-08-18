/* log.h -- diagnostics (FR-C-05, FR-C-06, NFR-05).
 *
 * NFR-05 is absolute: payload bytes are never written to any log at any
 * verbosity.  Lengths, addresses and header fields only.  There is deliberately
 * no hex-dump helper in this file, and none should be added.
 */
#ifndef UDPCHAINS_LOG_H
#define UDPCHAINS_LOG_H

#include "compat.h"

enum udpc_verbosity {
	UDPC_QUIET = 0,  /* errors only */
	UDPC_NORMAL = 1, /* + one line per association (FR-C-06) */
	UDPC_DEBUG = 2   /* + protocol steps; still never payload */
};

void udpc_log_set_level(int level);
int udpc_log_level(void);

/* All output goes to stderr with the "udpchains: " prefix (FR-C-05). */
void udpc_err(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void udpc_warn(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void udpc_info(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void udpc_debug(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

#endif /* UDPCHAINS_LOG_H */

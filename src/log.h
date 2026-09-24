/* log.h -- diagnostics (FR-C-05, FR-C-06, NFR-05).
 *
 * NFR-05 is absolute: payload bytes are never written to any log at any
 * verbosity.  Lengths, addresses and header fields only.  There is deliberately
 * no hex-dump helper in this file, and none should be added.
 */
#ifndef UDPCHAINS_LOG_H
#define UDPCHAINS_LOG_H

#include "compat.h"

#include <stdatomic.h>
#include <stddef.h>

enum udpc_verbosity {
	UDPC_QUIET = 0,  /* errors only */
	UDPC_NORMAL = 1, /* + one line per association (FR-C-06) */
	UDPC_DEBUG = 2   /* + protocol steps; still never payload */
};

void udpc_log_set_level(int level);
int udpc_log_level(void);

/* Records what the process's stderr is, so that a program which later closes it
 * and reuses descriptor 2 for a file or socket does not find the shim's
 * diagnostics written into that (D-33).  Called once by the shim at start-up;
 * the wrapper, which never touches its own fd 2, does not. */
void udpc_log_bind_stderr(void);

/* At most one report per second for a warning that could otherwise fire on
 * every datagram (D-33).  udpc_ratelimit() returns 0 to drop this occurrence,
 * or how many occurred since the last report (this one included).  The note
 * renders that count for the message: "" for 1. */
struct udpc_ratelimit {
	_Atomic long window;
	_Atomic unsigned suppressed;
};
unsigned udpc_ratelimit(struct udpc_ratelimit *rl);
const char *udpc_ratelimit_note(unsigned n, char *buf, size_t buflen);

/* All output goes to stderr with the "udpchains: " prefix (FR-C-05).  Errors
 * always print; warnings are suppressed by -q, which means "errors only". */
void udpc_err(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void udpc_warn(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void udpc_info(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void udpc_debug(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

#endif /* UDPCHAINS_LOG_H */

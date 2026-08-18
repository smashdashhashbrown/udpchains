/* shim.h -- shim-wide initialisation and state.
 *
 * The shim cannot refuse to run the program the way the wrapper can (FR-C-03):
 * by the time it loads, the target is already running.  So a configuration
 * failure inside the shim is recorded, and every intercepted datagram then
 * fails closed (SEC-01) with a one-time diagnostic.  It never falls through to
 * an unproxied send.
 */
#ifndef UDPCHAINS_SHIM_H
#define UDPCHAINS_SHIM_H

#include "compat.h"

#include <stdbool.h>

#include "config.h"

/* Returns the resolved configuration, initialising on first use.  Returns NULL
 * if configuration failed, in which case the caller must fail closed. */
const struct udpc_config *udpc_shim_config(void);

/* True when the shim is configured and may intercept.  False means every
 * intercepted call fails closed. */
bool udpc_shim_ready(void);

/* errno to report when the shim is unusable.  Kept in one place so the failure
 * is consistent across every hooked entry point. */
int udpc_shim_failure_errno(void);

#endif /* UDPCHAINS_SHIM_H */

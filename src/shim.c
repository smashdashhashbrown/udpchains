#include "shim.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>

#include "addr.h"
#include "guard.h"
#include "log.h"

/* guard.h: definition of the thread-local re-entry depth. */
__thread int udpc_reentry_depth = 0;

static struct udpc_config g_cfg;
static _Atomic bool g_ready = false;
static pthread_once_t g_once = PTHREAD_ONCE_INIT;

static void shim_init(void)
{
	const char *err = NULL;
	char addrbuf[UDPC_ADDRSTRLEN];

	/* Configuration resolution may call getaddrinfo, which sends over UDP
	 * through libc and would otherwise be intercepted by this very shim.
	 * The guard makes the shim transparent to its own traffic (guard.h). */
	UDPC_GUARD_ENTER();

	if (udpc_config_load_shim(&g_cfg, &err) != 0) {
		udpc_log_set_level(UDPC_NORMAL);
		udpc_err("not configured: %s", err ? err : "unknown error");
		udpc_err("every UDP send from this program will fail rather than "
		         "go direct (SEC-01)");
		UDPC_GUARD_LEAVE();
		return;
	}

	udpc_log_set_level(g_cfg.verbosity);

	/* D-38: until chains are carried on the wire, a longer chain fails
	 * closed rather than running through its first hop alone. */
	if (g_cfg.nextra > 0) {
		udpc_err("a chain of %u proxies is configured, but this version "
		         "carries only one",
		         g_cfg.nextra + 1);
		udpc_err("every UDP send from this program will fail rather than "
		         "go through the first proxy alone");
		UDPC_GUARD_LEAVE();
		return;
	}
	atomic_store_explicit(&g_ready, true, memory_order_release);

	udpc_debug("shim ready: proxy %s, max_datagram %zu, strict_loopback %s",
	           udpc_addr_str((const struct sockaddr *)&g_cfg.proxy, addrbuf,
	                         sizeof(addrbuf)),
	           g_cfg.max_datagram, g_cfg.strict_loopback ? "yes" : "no");

	UDPC_GUARD_LEAVE();
}

const struct udpc_config *udpc_shim_config(void)
{
	pthread_once(&g_once, shim_init);
	if (!atomic_load_explicit(&g_ready, memory_order_acquire))
		return NULL;
	return &g_cfg;
}

bool udpc_shim_ready(void)
{
	return udpc_shim_config() != NULL;
}

int udpc_shim_failure_errno(void)
{
	/* The shim is loaded but cannot reach a proxy configuration.  The
	 * network is, from the application's point of view, unusable. */
	return ENETUNREACH;
}

#include "real.h"

#include <dlfcn.h>
#include <stdatomic.h>
#include <stdlib.h>

#include "log.h"

static _Atomic(void *) g_slots[R_SLOT_COUNT];

void *udpc_real(enum udpc_real_slot slot, const char *name)
{
	/* Hot path: one relaxed-acquire load.  No locks, no allocation, no
	 * syscall (NFR-02, NFR-03). */
	void *fn = atomic_load_explicit(&g_slots[slot], memory_order_acquire);
	if (__builtin_expect(fn != NULL, 1))
		return fn;

	/* Cold path, at most once per symbol per process.  A race here is
	 * harmless: both threads resolve the same address. */
	dlerror();
	fn = dlsym(RTLD_NEXT, name);
	if (fn == NULL) {
		/* No safe fallback exists.  A shim that cannot find the real
		 * symbol cannot proxy and must not guess -- callers fail closed
		 * (SEC-01).  This is fatal rather than degraded on purpose. */
		udpc_err("cannot resolve real '%s' via dlsym(RTLD_NEXT): %s",
		         name, dlerror() ? dlerror() : "not found");
		abort();
	}
	atomic_store_explicit(&g_slots[slot], fn, memory_order_release);
	return fn;
}

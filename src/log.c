#include "log.h"

#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Verbosity is read on paths that may run concurrently with nothing that
 * writes it after startup, but keep it atomic so the read is well-defined. */
static _Atomic int g_level = UDPC_NORMAL;

void udpc_log_set_level(int level)
{
	atomic_store_explicit(&g_level, level, memory_order_relaxed);
}

int udpc_log_level(void)
{
	return atomic_load_explicit(&g_level, memory_order_relaxed);
}

/* Write directly with the raw syscall rather than through libc.
 *
 * Two reasons.  First, the shim hooks write(); routing diagnostics through the
 * hooked symbol would recurse (harmlessly, since fd 2 is never in the table --
 * but relying on that is fragile).  Second, stdio buffers and allocates, and a
 * diagnostic emitted from an error path should not depend on the allocator
 * being in a sane state. */
static void emit(const char *buf, size_t len)
{
	size_t off = 0;
	while (off < len) {
		long n = syscall(SYS_write, 2, buf + off, len - off);
		if (n <= 0)
			return; /* nothing useful to do about a failed diagnostic */
		off += (size_t)n;
	}
}

static void vlogf(const char *level, const char *fmt, va_list ap)
{
	/* Fixed stack buffer: no allocation on any logging path.  A truncated
	 * diagnostic is better than a malloc in an error handler. */
	char buf[1024];
	int n = snprintf(buf, sizeof(buf), "udpchains: %s", level);
	if (n < 0 || (size_t)n >= sizeof(buf))
		return;

	int m = vsnprintf(buf + n, sizeof(buf) - (size_t)n, fmt, ap);
	if (m < 0)
		return;

	size_t len = (size_t)n + (size_t)m;
	if (len >= sizeof(buf) - 1)
		len = sizeof(buf) - 2;
	buf[len++] = '\n';
	emit(buf, len);
}

void udpc_err(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vlogf("", fmt, ap);
	va_end(ap);
}

void udpc_warn(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vlogf("warning: ", fmt, ap);
	va_end(ap);
}

void udpc_info(const char *fmt, ...)
{
	if (udpc_log_level() < UDPC_NORMAL)
		return;
	va_list ap;
	va_start(ap, fmt);
	vlogf("", fmt, ap);
	va_end(ap);
}

void udpc_debug(const char *fmt, ...)
{
	if (udpc_log_level() < UDPC_DEBUG)
		return;
	va_list ap;
	va_start(ap, fmt);
	vlogf("debug: ", fmt, ap);
	va_end(ap);
}

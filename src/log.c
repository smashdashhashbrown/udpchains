#include "log.h"

#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
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

/* D-33: the identity of fd 2 when the shim started.  Written once, before the
 * program runs, and read afterwards; g_stderr_bound publishes it. */
static _Atomic bool g_stderr_bound;
static bool g_stderr_open;
static dev_t g_stderr_dev;
static ino_t g_stderr_ino;

void udpc_log_bind_stderr(void)
{
	struct stat st;

	g_stderr_open = fstat(2, &st) == 0;
	if (g_stderr_open) {
		g_stderr_dev = st.st_dev;
		g_stderr_ino = st.st_ino;
	}
	atomic_store_explicit(&g_stderr_bound, true, memory_order_release);
}

/* True unless fd 2 is no longer the stderr the program started with: closed,
 * or reused for something else -- a daemon's log file, a socket.  Writing there
 * would put the shim's text into the program's data. */
static bool stderr_is_ours(void)
{
	struct stat st;

	if (!atomic_load_explicit(&g_stderr_bound, memory_order_acquire))
		return true;
	if (!g_stderr_open || fstat(2, &st) != 0)
		return false;
	return st.st_dev == g_stderr_dev && st.st_ino == g_stderr_ino;
}

unsigned udpc_ratelimit(struct udpc_ratelimit *rl)
{
	struct timespec ts;
	long now, w;

	if (clock_gettime(CLOCK_MONOTONIC_COARSE, &ts) != 0)
		return 1;
	now = (long)ts.tv_sec;
	w = atomic_load_explicit(&rl->window, memory_order_relaxed);
	if (w == now ||
	    !atomic_compare_exchange_strong_explicit(&rl->window, &w, now,
	                                             memory_order_relaxed,
	                                             memory_order_relaxed)) {
		atomic_fetch_add_explicit(&rl->suppressed, 1u, memory_order_relaxed);
		return 0;
	}
	return atomic_exchange_explicit(&rl->suppressed, 0u, memory_order_relaxed) + 1;
}

const char *udpc_ratelimit_note(unsigned n, char *buf, size_t buflen)
{
	if (n <= 1)
		return "";
	snprintf(buf, buflen, " (and %u more like it since the last report)", n - 1);
	return buf;
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

	if (!stderr_is_ours())
		return;
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

	/* -q is documented as "errors only" (FR-C-05). */
	if (udpc_log_level() < UDPC_NORMAL)
		return;
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

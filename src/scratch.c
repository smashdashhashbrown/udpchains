#include "scratch.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

/* Fast access is via the thread-local pointer.  The pthread key exists only so
 * a destructor runs at thread exit -- __thread variables have no destructors,
 * and without one a program that creates and joins many threads would leak a
 * buffer per thread (which TST-07 would show up under ASan). */
static __thread struct udpc_tls *t_tls;
static pthread_key_t g_key;
static pthread_once_t g_key_once = PTHREAD_ONCE_INIT;

static void tls_free(void *p)
{
	struct udpc_tls *tls = p;

	if (tls == NULL)
		return;
	free(tls->buf);
	free(tls->iov);
	free(tls);
	t_tls = NULL;
}

static void key_init(void)
{
	(void)pthread_key_create(&g_key, tls_free);
}

struct udpc_tls *udpc_tls_get(size_t bufneed)
{
	struct udpc_tls *tls = t_tls;

	if (__builtin_expect(tls != NULL, 1)) {
		if (__builtin_expect(tls->buflen >= bufneed, 1))
			return tls;
		/* max_datagram is fixed at start-up, so this only happens if a
		 * caller asks for more than the configured maximum. */
		{
			uint8_t *nb = realloc(tls->buf, bufneed);
			if (nb == NULL)
				return NULL;
			tls->buf = nb;
			tls->buflen = bufneed;
		}
		return tls;
	}

	pthread_once(&g_key_once, key_init);

	tls = calloc(1, sizeof(*tls));
	if (tls == NULL)
		return NULL;
	tls->buf = malloc(bufneed);
	tls->iov = malloc(sizeof(struct iovec) * (IOV_MAX + 1));
	if (tls->buf == NULL || tls->iov == NULL) {
		free(tls->buf);
		free(tls->iov);
		free(tls);
		return NULL;
	}
	tls->buflen = bufneed;

	t_tls = tls;
	(void)pthread_setspecific(g_key, tls);
	return tls;
}

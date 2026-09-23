/* resolve.h -- the shim's own resolver (D-22, DESIGN.md §11).
 *
 * glibc's resolver cannot be intercepted: since 2.34 it lives inside libc and
 * makes its socket calls through internal aliases.  So the shim answers name
 * lookups itself, before NSS runs.  Every answer comes from a local source
 * (numeric, localhost, the hosts file) or from a DNS query sent through the
 * proxy.  The host's resolver is never consulted, and if the proxy route fails
 * the lookup fails -- there is no path from here to a direct query.
 *
 * This path may lock and allocate.  getaddrinfo is not async-signal-safe in
 * POSIX either, so NFR-03 does not reach it.
 */
#ifndef UDPCHAINS_RESOLVE_H
#define UDPCHAINS_RESOLVE_H

#include "compat.h"

#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "dns.h"

enum udpc_res_status {
	UDPC_RES_OK = 0,
	UDPC_RES_NONAME, /* the name does not exist */
	UDPC_RES_NODATA, /* it exists, with no address of the wanted family */
	UDPC_RES_AGAIN,  /* transient: proxy or resolver unreachable, timeout */
	UDPC_RES_FAIL    /* permanent: no resolver configured, or no shim config */
};

#define UDPC_RES_WANT_A 1u
#define UDPC_RES_WANT_AAAA 2u
#define UDPC_RES_MAX_ADDRS (2 * UDPC_DNS_MAX_ADDRS) /* A and AAAA */

struct udpc_res_result {
	size_t naddr;
	struct udpc_dns_addr addr[UDPC_RES_MAX_ADDRS];
	char canon[UDPC_DNS_NAME_MAX]; /* canonical name: end of the CNAME chain */
};

/* Forward lookup of a NAME -- numeric strings are the caller's business, since
 * glibc handles them without a network.  want is a mask of UDPC_RES_WANT_*.
 * Addresses come back A-first; the caller orders them. */
enum udpc_res_status udpc_resolve_name(const char *name, unsigned want,
                                       struct udpc_res_result *out);

/* Reverse lookup.  name must hold UDPC_DNS_NAME_MAX bytes. */
enum udpc_res_status udpc_resolve_addr(const struct sockaddr *sa, char *name);

/* Sends a caller-built DNS message through the proxy and returns the reply's
 * length, or -1 with *status set.  For res_send and the res_query family.  A
 * reply longer than anslen is cut to anslen with TC set. */
ssize_t udpc_resolve_raw(const uint8_t *query, size_t qlen, uint8_t *answer,
                         size_t anslen, enum udpc_res_status *status);

/* The names to try for `name`, in order: `name` itself, unless it is a single
 * label and dns_search is set, in which case each search domain appended to
 * it.  Returns how many were written to out (at most max). */
size_t udpc_resolve_candidates(const char *name, char (*out)[UDPC_DNS_NAME_MAX],
                               size_t max);

/* A fresh random 16-bit DNS query ID. */
uint16_t udpc_resolve_random_id(void);

#endif /* UDPCHAINS_RESOLVE_H */

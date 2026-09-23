/* dnshooks.c -- the exported name-resolution symbols (D-22, DESIGN.md §11).
 *
 * glibc's resolver makes its socket calls through internal aliases that no
 * preload can see, and the NSS modules ahead of it hand names to local daemons.
 * Either way a lookup made through libc left the host directly, even with every
 * datagram hook failing closed.  These hooks answer lookups before NSS runs:
 * locally, or by a query through the proxy (resolve.c).  None of them can fall
 * through to the host's resolver.
 *
 * Every hook here is a thin wrapper, in the spirit of hooks.c.  Results for
 * getaddrinfo are built by glibc itself, from numeric addresses, so its own
 * freeaddrinfo frees them -- which is why freeaddrinfo is not hooked.
 */
#include "compat.h"

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "dns.h"
#include "guard.h"
#include "log.h"
#include "real.h"
#include "resolve.h"

/* --- helpers --------------------------------------------------------------- */

/* D-22: IDN conversion is glibc-internal, so a non-ASCII name cannot be
 * carried faithfully.  Refused rather than sent as raw bytes. */
static bool is_ascii(const char *s)
{
	for (; *s != '\0'; s++)
		if ((unsigned char)*s >= 0x80)
			return false;
	return true;
}

/* Which families this host has a usable address in: non-loopback IPv4, and
 * IPv6 that is neither loopback nor link-local.  For AI_ADDRCONFIG, and for
 * ordering results in place of glibc's RFC 6724 sort (D-22). */
static void configured_families(bool *v4, bool *v6)
{
	struct ifaddrs *ifa = NULL, *p;

	*v4 = *v6 = false;
	if (getifaddrs(&ifa) != 0)
		return;
	for (p = ifa; p != NULL; p = p->ifa_next) {
		if (p->ifa_addr == NULL)
			continue;
		if (p->ifa_addr->sa_family == AF_INET) {
			const struct sockaddr_in *a = (const struct sockaddr_in *)p->ifa_addr;
			if ((ntohl(a->sin_addr.s_addr) >> 24) != 127)
				*v4 = true;
		} else if (p->ifa_addr->sa_family == AF_INET6) {
			const struct in6_addr *a =
				&((const struct sockaddr_in6 *)p->ifa_addr)->sin6_addr;
			if (!IN6_IS_ADDR_LOOPBACK(a) && !IN6_IS_ADDR_LINKLOCAL(a))
				*v6 = true;
		}
	}
	freeifaddrs(ifa);
}

static int status_to_eai(enum udpc_res_status st)
{
	switch (st) {
	case UDPC_RES_OK: return 0;
	case UDPC_RES_NONAME: return EAI_NONAME;
	case UDPC_RES_NODATA: return EAI_NODATA;
	case UDPC_RES_AGAIN: return EAI_AGAIN;
	default: return EAI_FAIL;
	}
}

static int status_to_herrno(enum udpc_res_status st)
{
	switch (st) {
	case UDPC_RES_NONAME: return HOST_NOT_FOUND;
	case UDPC_RES_NODATA: return NO_DATA;
	case UDPC_RES_AGAIN: return TRY_AGAIN;
	default: return NO_RECOVERY;
	}
}

/* --- getaddrinfo ----------------------------------------------------------- */

/* Appends glibc's own result for one numeric address.  Returns 0, or the EAI
 * code glibc gave -- a bad service or socket type surfaces here, as it would
 * have from the real call. */
static int append_numeric(const struct udpc_dns_addr *a, const char *service,
                          const struct addrinfo *hints, int family,
                          struct addrinfo **head, struct addrinfo **tail)
{
	char ip[INET6_ADDRSTRLEN];
	struct addrinfo h = *hints, *part = NULL;
	int rc;

	if (inet_ntop(a->family, a->bytes, ip, sizeof(ip)) == NULL)
		return EAI_SYSTEM;
	h.ai_family = family;
	h.ai_flags = (hints->ai_flags | AI_NUMERICHOST) & ~(AI_CANONNAME | AI_ADDRCONFIG);
	rc = REAL_GETADDRINFO(ip, service, &h, &part);
	if (rc != 0)
		return rc;

	if (*tail == NULL)
		*head = part;
	else
		(*tail)->ai_next = part;
	for (*tail = part; (*tail)->ai_next != NULL; *tail = (*tail)->ai_next)
		;
	return 0;
}

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res)
{
	struct addrinfo h, nh;
	struct udpc_res_result *r;
	struct addrinfo *head = NULL, *tail = NULL;
	enum udpc_res_status st;
	bool have4 = true, have6 = true, v6first;
	unsigned want = 0;
	size_t i, pass;
	int rc;

	/* The shim's own lookups (a named proxy) and service-only lookups
	 * (no host, so no network) belong to libc. */
	if (UDPC_IN_SHIM() || node == NULL)
		return REAL_GETADDRINFO(node, service, hints, res);

	if (hints != NULL) {
		h = *hints;
	} else {
		/* glibc's defaults for a NULL hints argument. */
		memset(&h, 0, sizeof(h));
		h.ai_family = AF_UNSPEC;
		h.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG;
	}

	/* A numeric host is glibc's to handle: with AI_NUMERICHOST forced it
	 * cannot touch the network, and it validates the hints and service the
	 * same way either way.  Only EAI_NONAME means "this is a name". */
	nh = h;
	nh.ai_flags |= AI_NUMERICHOST;
	rc = REAL_GETADDRINFO(node, service, &nh, res);
	if (rc != EAI_NONAME || (h.ai_flags & AI_NUMERICHOST))
		return rc;

	if (!is_ascii(node))
		return EAI_IDN_ENCODE;

	switch (h.ai_family) {
	case AF_INET:
		want = UDPC_RES_WANT_A;
		break;
	case AF_INET6:
		want = UDPC_RES_WANT_AAAA;
		if (h.ai_flags & AI_V4MAPPED)
			want |= UDPC_RES_WANT_A;
		break;
	case AF_UNSPEC:
		want = UDPC_RES_WANT_A | UDPC_RES_WANT_AAAA;
		break;
	default:
		return EAI_FAMILY;
	}

	if ((h.ai_flags & AI_ADDRCONFIG) || h.ai_family == AF_UNSPEC)
		configured_families(&have4, &have6);
	if ((h.ai_flags & AI_ADDRCONFIG) && h.ai_family == AF_UNSPEC &&
	    (have4 || have6)) {
		if (!have4)
			want &= ~UDPC_RES_WANT_A;
		if (!have6)
			want &= ~UDPC_RES_WANT_AAAA;
	}

	r = malloc(sizeof(*r));
	if (r == NULL)
		return EAI_MEMORY;
	st = udpc_resolve_name(node, want, r);
	if (st != UDPC_RES_OK) {
		free(r);
		return status_to_eai(st);
	}

	/* AF_INET6 + AI_V4MAPPED: IPv4 answers are used, mapped, only when
	 * there is no IPv6 answer -- or with AI_ALL, as well. */
	if (h.ai_family == AF_INET6 && !(h.ai_flags & AI_ALL)) {
		bool any6 = false;

		for (i = 0; i < r->naddr; i++)
			if (r->addr[i].family == AF_INET6)
				any6 = true;
		if (any6) {
			size_t k = 0;
			for (i = 0; i < r->naddr; i++)
				if (r->addr[i].family == AF_INET6)
					r->addr[k++] = r->addr[i];
			r->naddr = k;
		}
	}

	/* In place of glibc's RFC 6724 sort: IPv6 first only when this host
	 * can use it. */
	v6first = (h.ai_family == AF_UNSPEC) && have6;
	for (pass = 0; pass < 2; pass++) {
		int fam = (pass == 0) == v6first ? AF_INET6 : AF_INET;

		for (i = 0; i < r->naddr; i++) {
			int target;

			if (r->addr[i].family != fam)
				continue;
			target = h.ai_family == AF_INET6 ? AF_INET6 : fam;
			rc = append_numeric(&r->addr[i], service, &h, target, &head,
			                    &tail);
			if (rc != 0) {
				if (head != NULL)
					freeaddrinfo(head);
				free(r);
				return rc;
			}
		}
	}

	if (head == NULL) {
		free(r);
		return EAI_NODATA;
	}
	if (h.ai_flags & AI_CANONNAME) {
		/* glibc's freeaddrinfo frees ai_canonname with free(). */
		head->ai_canonname = strdup(r->canon[0] != '\0' ? r->canon : node);
		if (head->ai_canonname == NULL) {
			freeaddrinfo(head);
			free(r);
			return EAI_MEMORY;
		}
	}

	udpc_debug("resolved a name: %zu address(es), without the host resolver",
	           r->naddr);
	free(r);
	*res = head;
	return 0;
}

/* The asynchronous interface runs its lookups on glibc-internal threads that
 * call glibc's internal getaddrinfo, which no hook can reach.  Until it is
 * implemented here it fails closed (D-22), rather than resolving directly. */
int getaddrinfo_a(int mode, struct gaicb *list[], int nitems,
                  struct sigevent *sevp)
{
	static atomic_flag once = ATOMIC_FLAG_INIT;

	(void)mode;
	(void)list;
	(void)nitems;
	(void)sevp;
	if (!atomic_flag_test_and_set(&once))
		udpc_err("getaddrinfo_a is not supported: its lookups would "
		         "bypass the proxy, so they are refused (D-22)");
	errno = ENOSYS;
	return EAI_SYSTEM;
}

/* --- getnameinfo ----------------------------------------------------------- */

int getnameinfo(const struct sockaddr *sa, socklen_t salen, char *host,
                socklen_t hostlen, char *serv, socklen_t servlen, int flags)
{
	char name[UDPC_DNS_NAME_MAX];
	enum udpc_res_status st;
	int rc;

	/* No host wanted, a numeric host wanted, or not an internet address:
	 * nothing here needs DNS. */
	if (UDPC_IN_SHIM() || host == NULL || hostlen == 0 ||
	    (flags & NI_NUMERICHOST) || sa == NULL ||
	    (sa->sa_family != AF_INET && sa->sa_family != AF_INET6))
		return REAL_GETNAMEINFO(sa, salen, host, hostlen, serv, servlen, flags);

	if ((sa->sa_family == AF_INET && salen < sizeof(struct sockaddr_in)) ||
	    (sa->sa_family == AF_INET6 && salen < sizeof(struct sockaddr_in6)))
		return EAI_FAMILY;

	/* The service part, from /etc/services -- never the network. */
	if (serv != NULL && servlen > 0) {
		rc = REAL_GETNAMEINFO(sa, salen, NULL, 0, serv, servlen, flags);
		if (rc != 0)
			return rc;
	}

	st = udpc_resolve_addr(sa, name);
	if (st == UDPC_RES_OK) {
		if (strlen(name) >= hostlen)
			return EAI_OVERFLOW;
		memcpy(host, name, strlen(name) + 1);
		return 0;
	}

	/* No name: a numeric answer, unless the caller insists on a name. */
	if (flags & NI_NAMEREQD)
		return st == UDPC_RES_NODATA ? EAI_NONAME : status_to_eai(st);
	return REAL_GETNAMEINFO(sa, salen, host, hostlen, NULL, 0,
	                        flags | NI_NUMERICHOST);
}

/* --- gethostby* ------------------------------------------------------------ */

/* Lays out a hostent in the caller's buffer: the address bytes, the NULL-ended
 * address and alias vectors, and the name.  Returns 0, or ERANGE if it does not
 * fit -- glibc's contract for the _r functions. */
static int fill_hostent(struct hostent *ret, char *buf, size_t buflen,
                        const char *name, int af,
                        const struct udpc_dns_addr *addrs, size_t naddr)
{
	size_t alen = af == AF_INET ? 4 : 16;
	size_t n = 0, i, off, need;
	uintptr_t align = sizeof(char *);
	char **vec;

	for (i = 0; i < naddr; i++)
		if (addrs[i].family == af)
			n++;

	off = ((uintptr_t)buf % align) ? align - (uintptr_t)buf % align : 0;
	need = off + (n + 1) * sizeof(char *) + sizeof(char *) + n * alen +
	       strlen(name) + 1;
	if (need > buflen)
		return ERANGE;

	vec = (char **)(void *)(buf + off);
	{
		char **aliases = vec + n + 1;
		char *data = (char *)(aliases + 1);
		size_t k = 0;

		for (i = 0; i < naddr; i++) {
			if (addrs[i].family != af)
				continue;
			memcpy(data + k * alen, addrs[i].bytes, alen);
			vec[k] = data + k * alen;
			k++;
		}
		vec[n] = NULL;
		aliases[0] = NULL;
		ret->h_name = data + n * alen;
		memcpy(ret->h_name, name, strlen(name) + 1);
		ret->h_aliases = aliases;
	}
	ret->h_addrtype = af;
	ret->h_length = (int)alen;
	ret->h_addr_list = vec;
	return 0;
}

int gethostbyname2_r(const char *name, int af, struct hostent *ret, char *buf,
                     size_t buflen, struct hostent **result, int *h_errnop)
{
	struct udpc_res_result *r;
	struct udpc_dns_addr one;
	enum udpc_res_status st;
	int rc;

	*result = NULL;
	if (af != AF_INET && af != AF_INET6) {
		*h_errnop = NETDB_INTERNAL;
		errno = EAFNOSUPPORT;
		return EAFNOSUPPORT;
	}
	if (name == NULL || !is_ascii(name)) {
		*h_errnop = HOST_NOT_FOUND;
		return 0;
	}

	/* A numeric address answers itself, as in glibc. */
	one.family = af;
	if (inet_pton(af, name, one.bytes) == 1) {
		rc = fill_hostent(ret, buf, buflen, name, af, &one, 1);
		if (rc != 0) {
			*h_errnop = NETDB_INTERNAL;
			errno = rc;
			return rc;
		}
		*result = ret;
		return 0;
	}

	r = malloc(sizeof(*r));
	if (r == NULL) {
		*h_errnop = NETDB_INTERNAL;
		return ENOMEM;
	}
	st = udpc_resolve_name(name, af == AF_INET ? UDPC_RES_WANT_A
	                                           : UDPC_RES_WANT_AAAA, r);
	if (st != UDPC_RES_OK) {
		free(r);
		*h_errnop = status_to_herrno(st);
		return st == UDPC_RES_AGAIN ? EAGAIN : 0;
	}
	rc = fill_hostent(ret, buf, buflen, r->canon[0] != '\0' ? r->canon : name,
	                  af, r->addr, r->naddr);
	free(r);
	if (rc != 0) {
		*h_errnop = NETDB_INTERNAL;
		errno = rc;
		return rc;
	}
	*result = ret;
	return 0;
}

int gethostbyname_r(const char *name, struct hostent *ret, char *buf,
                    size_t buflen, struct hostent **result, int *h_errnop)
{
	return gethostbyname2_r(name, AF_INET, ret, buf, buflen, result, h_errnop);
}

int gethostbyaddr_r(const void *addr, socklen_t len, int type,
                    struct hostent *ret, char *buf, size_t buflen,
                    struct hostent **result, int *h_errnop)
{
	struct sockaddr_storage ss;
	struct udpc_dns_addr one;
	char name[UDPC_DNS_NAME_MAX];
	enum udpc_res_status st;
	int rc;

	*result = NULL;
	memset(&ss, 0, sizeof(ss));
	if (type == AF_INET && len == 4) {
		((struct sockaddr_in *)&ss)->sin_family = AF_INET;
		memcpy(&((struct sockaddr_in *)&ss)->sin_addr, addr, 4);
	} else if (type == AF_INET6 && len == 16) {
		((struct sockaddr_in6 *)&ss)->sin6_family = AF_INET6;
		memcpy(&((struct sockaddr_in6 *)&ss)->sin6_addr, addr, 16);
	} else {
		*h_errnop = NETDB_INTERNAL;
		errno = EAFNOSUPPORT;
		return EAFNOSUPPORT;
	}

	st = udpc_resolve_addr((const struct sockaddr *)&ss, name);
	if (st != UDPC_RES_OK) {
		*h_errnop = status_to_herrno(st);
		return st == UDPC_RES_AGAIN ? EAGAIN : 0;
	}

	one.family = type;
	memcpy(one.bytes, addr, len);
	rc = fill_hostent(ret, buf, buflen, name, type, &one, 1);
	if (rc != 0) {
		*h_errnop = NETDB_INTERNAL;
		errno = rc;
		return rc;
	}
	*result = ret;
	return 0;
}

/* The non-reentrant forms return per-thread storage.  glibc's is shared by the
 * whole process; per-thread is strictly safer and otherwise identical. */
static __thread struct hostent t_he;
static __thread char t_hebuf[2048];

struct hostent *gethostbyname2(const char *name, int af)
{
	struct hostent *res = NULL;
	int herr = 0;

	if (gethostbyname2_r(name, af, &t_he, t_hebuf, sizeof(t_hebuf), &res,
	                     &herr) != 0 || res == NULL) {
		h_errno = herr;
		return NULL;
	}
	return res;
}

struct hostent *gethostbyname(const char *name)
{
	return gethostbyname2(name, AF_INET);
}

struct hostent *gethostbyaddr(const void *addr, socklen_t len, int type)
{
	struct hostent *res = NULL;
	int herr = 0;

	if (gethostbyaddr_r(addr, len, type, &t_he, t_hebuf, sizeof(t_hebuf), &res,
	                    &herr) != 0 || res == NULL) {
		h_errno = herr;
		return NULL;
	}
	return res;
}

/* --- the res_* query API --------------------------------------------------- */

/* glibc exports each of these under a plain name, which programs built since
 * 2.34 link, and a __res_ name, which older ones do; both are hooked.  The
 * _res options (RES_USEVC and friends) are ignored (D-22). */

static void set_herrno(res_state statp, int v)
{
	if (statp != NULL)
		statp->res_h_errno = v;
	h_errno = v;
}

/* glibc's interpretation of a reply: a -1 return, with h_errno saying why,
 * unless the reply is NOERROR with at least one answer. */
static int judge(res_state statp, const unsigned char *answer, int n)
{
	int rcode, ancount;

	if (n < UDPC_DNS_HDR_LEN) {
		set_herrno(statp, NO_RECOVERY);
		return -1;
	}
	rcode = answer[3] & 0x0f;
	ancount = udpc_dns_get16(answer + 6);
	if (rcode == UDPC_DNS_RCODE_NOERROR && ancount > 0)
		return n;
	switch (rcode) {
	case UDPC_DNS_RCODE_NXDOMAIN: set_herrno(statp, HOST_NOT_FOUND); break;
	case UDPC_DNS_RCODE_SERVFAIL: set_herrno(statp, TRY_AGAIN); break;
	case UDPC_DNS_RCODE_NOERROR: set_herrno(statp, NO_DATA); break;
	default: set_herrno(statp, NO_RECOVERY); break;
	}
	return -1;
}

static int do_send(res_state statp, const unsigned char *msg, int msglen,
                   unsigned char *answer, int anslen)
{
	enum udpc_res_status st;
	ssize_t n;

	if (msg == NULL || answer == NULL || msglen < 0 || anslen < 0) {
		errno = EINVAL;
		return -1;
	}
	n = udpc_resolve_raw(msg, (size_t)msglen, answer, (size_t)anslen, &st);
	if (n < 0) {
		set_herrno(statp, st == UDPC_RES_AGAIN ? TRY_AGAIN : NO_RECOVERY);
		errno = st == UDPC_RES_AGAIN ? ETIMEDOUT : ECONNREFUSED;
		return -1;
	}
	return (int)n;
}

static int do_query(res_state statp, const char *dname, int class, int type,
                    unsigned char *answer, int anslen)
{
	uint8_t q[UDPC_DNS_QUERY_MAX];
	ssize_t ql;
	int n;

	if (dname == NULL || !is_ascii(dname)) {
		set_herrno(statp, NO_RECOVERY);
		return -1;
	}
	ql = udpc_dns_build_query(q, sizeof(q), udpc_resolve_random_id(), dname,
	                          (uint16_t)class, (uint16_t)type,
	                          anslen > 512 ? UDPC_DNS_EDNS_SIZE : 0);
	if (ql < 0) {
		set_herrno(statp, NO_RECOVERY);
		return -1;
	}
	n = do_send(statp, q, (int)ql, answer, anslen);
	return n < 0 ? -1 : judge(statp, answer, n);
}

static int do_search(res_state statp, const char *dname, int class, int type,
                     unsigned char *answer, int anslen)
{
	char cand[8][UDPC_DNS_NAME_MAX];
	size_t n, i;
	int rc = -1;

	if (dname == NULL) {
		set_herrno(statp, NO_RECOVERY);
		return -1;
	}
	n = udpc_resolve_candidates(dname, cand, 8);
	for (i = 0; i < n; i++) {
		rc = do_query(statp, cand[i], class, type, answer, anslen);
		if (rc >= 0)
			break;
	}
	return rc;
}

static int do_querydomain(res_state statp, const char *name, const char *domain,
                          int class, int type, unsigned char *answer, int anslen)
{
	char full[UDPC_DNS_NAME_MAX];
	int w;

	if (name == NULL) {
		set_herrno(statp, NO_RECOVERY);
		return -1;
	}
	w = domain != NULL ? snprintf(full, sizeof(full), "%s.%s", name, domain)
	                   : snprintf(full, sizeof(full), "%s", name);
	if (w < 0 || (size_t)w >= sizeof(full)) {
		set_herrno(statp, NO_RECOVERY);
		return -1;
	}
	return do_query(statp, full, class, type, answer, anslen);
}

int res_query(const char *dname, int class, int type, unsigned char *answer,
              int anslen)
{
	return do_query(NULL, dname, class, type, answer, anslen);
}

int res_search(const char *dname, int class, int type, unsigned char *answer,
               int anslen)
{
	return do_search(NULL, dname, class, type, answer, anslen);
}

int res_querydomain(const char *name, const char *domain, int class, int type,
                    unsigned char *answer, int anslen)
{
	return do_querydomain(NULL, name, domain, class, type, answer, anslen);
}

int res_send(const unsigned char *msg, int msglen, unsigned char *answer,
             int anslen)
{
	return do_send(NULL, msg, msglen, answer, anslen);
}

int res_nquery(res_state statp, const char *dname, int class, int type,
               unsigned char *answer, int anslen)
{
	return do_query(statp, dname, class, type, answer, anslen);
}

int res_nsearch(res_state statp, const char *dname, int class, int type,
                unsigned char *answer, int anslen)
{
	return do_search(statp, dname, class, type, answer, anslen);
}

int res_nquerydomain(res_state statp, const char *name, const char *domain,
                     int class, int type, unsigned char *answer, int anslen)
{
	return do_querydomain(statp, name, domain, class, type, answer, anslen);
}

int res_nsend(res_state statp, const unsigned char *msg, int msglen,
              unsigned char *answer, int anslen)
{
	return do_send(statp, msg, msglen, answer, anslen);
}

/* The __res_ names, for binaries linked before glibc 2.34.  Wrappers rather
 * than aliases: the headers declare the plain names nothrow and leaf, which an
 * alias would have to repeat, and GCC's copy attribute is not portable. */
int __res_query(const char *, int, int, unsigned char *, int);
int __res_search(const char *, int, int, unsigned char *, int);
int __res_querydomain(const char *, const char *, int, int, unsigned char *, int);
int __res_send(const unsigned char *, int, unsigned char *, int);
int __res_nquery(res_state, const char *, int, int, unsigned char *, int);
int __res_nsearch(res_state, const char *, int, int, unsigned char *, int);
int __res_nquerydomain(res_state, const char *, const char *, int, int,
                       unsigned char *, int);
int __res_nsend(res_state, const unsigned char *, int, unsigned char *, int);

int __res_query(const char *dname, int class, int type, unsigned char *answer,
                int anslen)
{
	return do_query(NULL, dname, class, type, answer, anslen);
}

int __res_search(const char *dname, int class, int type, unsigned char *answer,
                 int anslen)
{
	return do_search(NULL, dname, class, type, answer, anslen);
}

int __res_querydomain(const char *name, const char *domain, int class, int type,
                      unsigned char *answer, int anslen)
{
	return do_querydomain(NULL, name, domain, class, type, answer, anslen);
}

int __res_send(const unsigned char *msg, int msglen, unsigned char *answer,
               int anslen)
{
	return do_send(NULL, msg, msglen, answer, anslen);
}

int __res_nquery(res_state statp, const char *dname, int class, int type,
                 unsigned char *answer, int anslen)
{
	return do_query(statp, dname, class, type, answer, anslen);
}

int __res_nsearch(res_state statp, const char *dname, int class, int type,
                  unsigned char *answer, int anslen)
{
	return do_search(statp, dname, class, type, answer, anslen);
}

int __res_nquerydomain(res_state statp, const char *name, const char *domain,
                       int class, int type, unsigned char *answer, int anslen)
{
	return do_querydomain(statp, name, domain, class, type, answer, anslen);
}

int __res_nsend(res_state statp, const unsigned char *msg, int msglen,
                unsigned char *answer, int anslen)
{
	return do_send(statp, msg, msglen, answer, anslen);
}

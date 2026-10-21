/* real.h -- resolution of the real libc symbols (FR-I-01).
 *
 * DESIGN.md 2.1: each hooked function resolves its real implementation with
 * dlsym(RTLD_NEXT, name), cached in an atomic slot.  Resolution is lazy --
 * performed on first call, not in a library constructor -- to avoid ordering
 * hazards with other preloaded libraries and with the loader's own use of these
 * symbols during startup.
 *
 * dlsym may allocate.  That is acceptable: it happens once per symbol, off the
 * per-datagram path (NFR-02), and a double resolution under a race is harmless
 * because both threads compute the same pointer.
 */
#ifndef UDPCHAINS_REAL_H
#define UDPCHAINS_REAL_H

#include "compat.h"

#include <stdarg.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

enum udpc_real_slot {
	/* send path */
	R_SENDTO = 0,
	R_SENDMSG,
	R_SENDMMSG,
	R_SEND,
	R_WRITE,
	R_WRITEV,
	/* receive path */
	R_RECVFROM,
	R_RECVMSG,
	R_RECVMMSG,
	R_RECV,
	R_READ,
	R_READV,
	/* lifecycle */
	R_SOCKET,
	R_CONNECT,
	R_BIND,
	R_CLOSE,
	R_CLOSE_RANGE,
	R_DUP,
	R_DUP2,
	R_DUP3,
	R_FCNTL,
	R_FCNTL64,
	R_SYSCALL,
	/* introspection */
	R_GETPEERNAME,
	R_GETSOCKNAME,
	/* name resolution (D-22) */
	R_GETADDRINFO,
	R_GETNAMEINFO,
	/* routes around the send and receive hooks (D-36) */
	R_PWRITEV2,
	R_PWRITEV64V2,
	R_PREADV2,
	R_PREADV64V2,
	R_SENDFILE,
	R_SENDFILE64,
	R_SPLICE,
	R_FDOPEN,
	R_VDPRINTF,
	R_VDPRINTF_CHK,
	R_SLOT_COUNT
};

/* Returns the real symbol, resolving it on first use.  Never returns NULL for
 * a symbol that exists in libc; if resolution genuinely fails the caller has no
 * safe fallback and must fail closed. */
void *udpc_real(enum udpc_real_slot slot, const char *name);

typedef ssize_t (*udpc_sendto_fn)(int, const void *, size_t, int,
                                  const struct sockaddr *, socklen_t);
typedef ssize_t (*udpc_sendmsg_fn)(int, const struct msghdr *, int);
typedef int (*udpc_sendmmsg_fn)(int, struct mmsghdr *, unsigned, int);
typedef ssize_t (*udpc_send_fn)(int, const void *, size_t, int);
typedef ssize_t (*udpc_write_fn)(int, const void *, size_t);
typedef ssize_t (*udpc_writev_fn)(int, const struct iovec *, int);

typedef ssize_t (*udpc_recvfrom_fn)(int, void *, size_t, int, struct sockaddr *,
                                    socklen_t *);
typedef ssize_t (*udpc_recvmsg_fn)(int, struct msghdr *, int);
typedef int (*udpc_recvmmsg_fn)(int, struct mmsghdr *, unsigned, int,
                                struct timespec *);
typedef ssize_t (*udpc_recv_fn)(int, void *, size_t, int);
typedef ssize_t (*udpc_read_fn)(int, void *, size_t);
typedef ssize_t (*udpc_readv_fn)(int, const struct iovec *, int);

typedef int (*udpc_socket_fn)(int, int, int);
typedef int (*udpc_connect_fn)(int, const struct sockaddr *, socklen_t);
typedef int (*udpc_bind_fn)(int, const struct sockaddr *, socklen_t);
typedef int (*udpc_close_fn)(int);
typedef int (*udpc_close_range_fn)(unsigned, unsigned, int);
typedef int (*udpc_dup_fn)(int);
typedef int (*udpc_dup2_fn)(int, int);
typedef int (*udpc_dup3_fn)(int, int, int);
typedef int (*udpc_fcntl_fn)(int, int, ...);
typedef long (*udpc_syscall_fn)(long, ...);

typedef int (*udpc_getpeername_fn)(int, struct sockaddr *, socklen_t *);
typedef int (*udpc_getsockname_fn)(int, struct sockaddr *, socklen_t *);

typedef ssize_t (*udpc_pwritev2_fn)(int, const struct iovec *, int, off_t, int);
typedef ssize_t (*udpc_preadv2_fn)(int, const struct iovec *, int, off_t, int);
typedef ssize_t (*udpc_sendfile_fn)(int, int, off_t *, size_t);
typedef ssize_t (*udpc_splice_fn)(int, loff_t *, int, loff_t *, size_t, unsigned);
typedef FILE *(*udpc_fdopen_fn)(int, const char *);
typedef int (*udpc_vdprintf_fn)(int, const char *, va_list);
typedef int (*udpc_vdprintf_chk_fn)(int, int, const char *, va_list);

struct addrinfo;
typedef int (*udpc_getaddrinfo_fn)(const char *, const char *,
                                   const struct addrinfo *, struct addrinfo **);
typedef int (*udpc_getnameinfo_fn)(const struct sockaddr *, socklen_t, char *,
                                   socklen_t, char *, socklen_t, int);

#define REAL_SENDTO ((udpc_sendto_fn)udpc_real(R_SENDTO, "sendto"))
#define REAL_SENDMSG ((udpc_sendmsg_fn)udpc_real(R_SENDMSG, "sendmsg"))
#define REAL_SENDMMSG ((udpc_sendmmsg_fn)udpc_real(R_SENDMMSG, "sendmmsg"))
#define REAL_SEND ((udpc_send_fn)udpc_real(R_SEND, "send"))
#define REAL_WRITE ((udpc_write_fn)udpc_real(R_WRITE, "write"))
#define REAL_WRITEV ((udpc_writev_fn)udpc_real(R_WRITEV, "writev"))

#define REAL_RECVFROM ((udpc_recvfrom_fn)udpc_real(R_RECVFROM, "recvfrom"))
#define REAL_RECVMSG ((udpc_recvmsg_fn)udpc_real(R_RECVMSG, "recvmsg"))
#define REAL_RECVMMSG ((udpc_recvmmsg_fn)udpc_real(R_RECVMMSG, "recvmmsg"))
#define REAL_RECV ((udpc_recv_fn)udpc_real(R_RECV, "recv"))
#define REAL_READ ((udpc_read_fn)udpc_real(R_READ, "read"))
#define REAL_READV ((udpc_readv_fn)udpc_real(R_READV, "readv"))

#define REAL_SOCKET ((udpc_socket_fn)udpc_real(R_SOCKET, "socket"))
#define REAL_CONNECT ((udpc_connect_fn)udpc_real(R_CONNECT, "connect"))
#define REAL_BIND ((udpc_bind_fn)udpc_real(R_BIND, "bind"))
#define REAL_CLOSE ((udpc_close_fn)udpc_real(R_CLOSE, "close"))
#define REAL_CLOSE_RANGE \
	((udpc_close_range_fn)udpc_real(R_CLOSE_RANGE, "close_range"))
#define REAL_DUP ((udpc_dup_fn)udpc_real(R_DUP, "dup"))
#define REAL_DUP2 ((udpc_dup2_fn)udpc_real(R_DUP2, "dup2"))
#define REAL_DUP3 ((udpc_dup3_fn)udpc_real(R_DUP3, "dup3"))
#define REAL_FCNTL ((udpc_fcntl_fn)udpc_real(R_FCNTL, "fcntl"))
#define REAL_FCNTL64 ((udpc_fcntl_fn)udpc_real(R_FCNTL64, "fcntl64"))
#define REAL_SYSCALL ((udpc_syscall_fn)udpc_real(R_SYSCALL, "syscall"))

#define REAL_GETPEERNAME \
	((udpc_getpeername_fn)udpc_real(R_GETPEERNAME, "getpeername"))
#define REAL_GETSOCKNAME \
	((udpc_getsockname_fn)udpc_real(R_GETSOCKNAME, "getsockname"))

#define REAL_GETADDRINFO \
	((udpc_getaddrinfo_fn)udpc_real(R_GETADDRINFO, "getaddrinfo"))
#define REAL_GETNAMEINFO \
	((udpc_getnameinfo_fn)udpc_real(R_GETNAMEINFO, "getnameinfo"))

#define REAL_PWRITEV2 ((udpc_pwritev2_fn)udpc_real(R_PWRITEV2, "pwritev2"))
#define REAL_PWRITEV64V2 \
	((udpc_pwritev2_fn)udpc_real(R_PWRITEV64V2, "pwritev64v2"))
#define REAL_PREADV2 ((udpc_preadv2_fn)udpc_real(R_PREADV2, "preadv2"))
#define REAL_PREADV64V2 \
	((udpc_preadv2_fn)udpc_real(R_PREADV64V2, "preadv64v2"))
#define REAL_SENDFILE ((udpc_sendfile_fn)udpc_real(R_SENDFILE, "sendfile"))
#define REAL_SENDFILE64 \
	((udpc_sendfile_fn)udpc_real(R_SENDFILE64, "sendfile64"))
#define REAL_SPLICE ((udpc_splice_fn)udpc_real(R_SPLICE, "splice"))
#define REAL_FDOPEN ((udpc_fdopen_fn)udpc_real(R_FDOPEN, "fdopen"))
#define REAL_VDPRINTF ((udpc_vdprintf_fn)udpc_real(R_VDPRINTF, "vdprintf"))
#define REAL_VDPRINTF_CHK \
	((udpc_vdprintf_chk_fn)udpc_real(R_VDPRINTF_CHK, "__vdprintf_chk"))

#endif /* UDPCHAINS_REAL_H */

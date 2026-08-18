/* test_matrix.c -- TST-01, the hook matrix.
 *
 * {sendto, send, write, writev, sendmsg, sendmmsg}
 *   x {recvfrom, recv, read, readv, recvmsg, recvmmsg}
 *
 * against an echo server, asserting byte-identical round-trips.  This matrix is
 * what distinguishes tier 2 from the existing tools (baseline §0.2) and is the
 * primary regression gate.
 *
 * Both existing tools fail cells here.  proxychains-ng hooks no receive
 * function at all, so every cell fails.  Proxando hooks only recvfrom, so the
 * whole recv/read/readv/recvmsg/recvmmsg column returns the payload with the
 * 10-byte SOCKS header still attached -- silent corruption rather than an
 * error, which is precisely what a byte-identical assertion catches.
 *
 * Run under the shim:  udpchains ./test_matrix <v4port> <v6port>
 *
 * send/write/writev carry no destination, so they are exercised on connected
 * sockets; sendto/sendmsg/sendmmsg are exercised both connected and not.
 */
#include "tap.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>

enum sender {
	S_SENDTO = 0,
	S_SEND,
	S_WRITE,
	S_WRITEV,
	S_SENDMSG,
	S_SENDMMSG,
	S_COUNT
};

enum receiver {
	R_RECVFROM = 0,
	R_RECV,
	R_READ,
	R_READV,
	R_RECVMSG,
	R_RECVMMSG,
	R_COUNT
};

static const char *sender_name[S_COUNT] = { "sendto",  "send",	  "write",
	                                    "writev",  "sendmsg", "sendmmsg" };
static const char *receiver_name[R_COUNT] = { "recvfrom", "recv",    "read",
	                                      "readv",	  "recvmsg", "recvmmsg" };

/* send/write/writev have no destination argument. */
static int sender_needs_connect(enum sender s)
{
	return s == S_SEND || s == S_WRITE || s == S_WRITEV;
}

static ssize_t do_send(enum sender s, int fd, const void *buf, size_t len,
                       const struct sockaddr *dst, socklen_t dstlen)
{
	switch (s) {
	case S_SENDTO:
		return sendto(fd, buf, len, 0, dst, dstlen);
	case S_SEND:
		return send(fd, buf, len, 0);
	case S_WRITE:
		return write(fd, buf, len);
	case S_WRITEV: {
		/* Split across two iovecs so scatter/gather is exercised in
		 * every cell, not only in the fidelity tests (FR-F-10). */
		struct iovec iov[2];
		size_t first = len / 2;
		iov[0].iov_base = (void *)(uintptr_t)buf;
		iov[0].iov_len = first;
		iov[1].iov_base = (void *)((uintptr_t)buf + first);
		iov[1].iov_len = len - first;
		return writev(fd, iov, 2);
	}
	case S_SENDMSG: {
		struct msghdr msg;
		struct iovec iov;
		iov.iov_base = (void *)(uintptr_t)buf;
		iov.iov_len = len;
		memset(&msg, 0, sizeof(msg));
		msg.msg_name = (void *)(uintptr_t)dst;
		msg.msg_namelen = dst ? dstlen : 0;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		return sendmsg(fd, &msg, 0);
	}
	case S_SENDMMSG: {
		struct mmsghdr mm[1];
		struct iovec iov;
		int rc;
		iov.iov_base = (void *)(uintptr_t)buf;
		iov.iov_len = len;
		memset(mm, 0, sizeof(mm));
		mm[0].msg_hdr.msg_name = (void *)(uintptr_t)dst;
		mm[0].msg_hdr.msg_namelen = dst ? dstlen : 0;
		mm[0].msg_hdr.msg_iov = &iov;
		mm[0].msg_hdr.msg_iovlen = 1;
		rc = sendmmsg(fd, mm, 1, 0);
		if (rc < 0)
			return -1;
		return (ssize_t)mm[0].msg_len;
	}
	default:
		return -1;
	}
}

static ssize_t do_recv(enum receiver r, int fd, void *buf, size_t len)
{
	switch (r) {
	case R_RECVFROM: {
		struct sockaddr_storage from;
		socklen_t flen = sizeof(from);
		return recvfrom(fd, buf, len, 0, (struct sockaddr *)&from, &flen);
	}
	case R_RECV:
		return recv(fd, buf, len, 0);
	case R_READ:
		return read(fd, buf, len);
	case R_READV: {
		/* Two iovecs, so a header that the shim failed to strip would
		 * land visibly across the boundary (FR-F-10). */
		struct iovec iov[2];
		size_t first = len / 2;
		iov[0].iov_base = buf;
		iov[0].iov_len = first;
		iov[1].iov_base = (char *)buf + first;
		iov[1].iov_len = len - first;
		return readv(fd, iov, 2);
	}
	case R_RECVMSG: {
		struct msghdr msg;
		struct iovec iov;
		iov.iov_base = buf;
		iov.iov_len = len;
		memset(&msg, 0, sizeof(msg));
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		return recvmsg(fd, &msg, 0);
	}
	case R_RECVMMSG: {
		struct mmsghdr mm[1];
		struct iovec iov;
		int rc;
		iov.iov_base = buf;
		iov.iov_len = len;
		memset(mm, 0, sizeof(mm));
		mm[0].msg_hdr.msg_iov = &iov;
		mm[0].msg_hdr.msg_iovlen = 1;
		rc = recvmmsg(fd, mm, 1, 0, NULL);
		if (rc < 0)
			return -1;
		return (ssize_t)mm[0].msg_len;
	}
	default:
		return -1;
	}
}

static int make_socket(int family, const struct sockaddr *dst, socklen_t dstlen,
                       int do_connect)
{
	struct timeval tv = { 5, 0 };
	int fd = socket(family, SOCK_DGRAM, 0);

	if (fd < 0)
		return -1;

	/* setsockopt is deliberately not hooked (FR-I-07); this both sets a
	 * timeout so a broken cell fails instead of hanging, and demonstrates
	 * that socket options still work on a redirected fd. */
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) {
		close(fd);
		return -1;
	}
	if (do_connect && connect(fd, dst, dstlen) != 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static void run_matrix(const char *label, int family, const struct sockaddr *dst,
                       socklen_t dstlen, int connected)
{
	enum sender s;
	enum receiver r;

	for (s = 0; s < S_COUNT; s++) {
		if (!connected && sender_needs_connect(s))
			continue;

		for (r = 0; r < R_COUNT; r++) {
			char payload[128];
			char got[512];
			int fd;
			ssize_t sent, rcvd;
			size_t len;

			/* A distinct payload per cell, so a cross-delivery or a
			 * stale datagram is visible rather than passing by
			 * accident. */
			snprintf(payload, sizeof(payload), "%s|%s->%s|%s", label,
			         sender_name[s], receiver_name[r], "payload");
			len = strlen(payload);

			fd = make_socket(family, dst, dstlen, connected);
			if (fd < 0) {
				TAP_OK(0, "%s: %s -> %s (socket setup failed: %s)",
				       label, sender_name[s], receiver_name[r],
				       strerror(errno));
				continue;
			}

			sent = do_send(s, fd, payload, len,
			               connected ? NULL : dst,
			               connected ? 0 : dstlen);
			if (sent != (ssize_t)len) {
				TAP_OK(0,
				       "%s: %s -> %s (send returned %zd, want %zu: %s)",
				       label, sender_name[s], receiver_name[r], sent,
				       len, strerror(errno));
				close(fd);
				continue;
			}

			memset(got, 0, sizeof(got));
			rcvd = do_recv(r, fd, got, sizeof(got));
			if (rcvd < 0) {
				TAP_OK(0, "%s: %s -> %s (receive failed: %s)", label,
				       sender_name[s], receiver_name[r],
				       strerror(errno));
				close(fd);
				continue;
			}

			/* The assertion that catches the Proxando defect: a
			 * receive hook that failed to strip the header returns
			 * len + 10 bytes beginning with the SOCKS header. */
			TAP_OK((size_t)rcvd == len && memcmp(got, payload, len) == 0,
			       "%s: %s -> %s round-trips byte-identically (%zd/%zu)",
			       label, sender_name[s], receiver_name[r], rcvd, len);

			close(fd);
		}
	}
}

int main(int argc, char **argv)
{
	struct sockaddr_in v4;
	struct sockaddr_in6 v6;
	int v4port, v6port;

	if (argc < 3) {
		fprintf(stderr, "usage: test_matrix <v4echoport> <v6echoport>\n");
		return 2;
	}
	v4port = atoi(argv[1]);
	v6port = atoi(argv[2]);

	memset(&v4, 0, sizeof(v4));
	v4.sin_family = AF_INET;
	v4.sin_port = htons((uint16_t)v4port);
	inet_pton(AF_INET, "127.0.0.1", &v4.sin_addr);

	memset(&v6, 0, sizeof(v6));
	v6.sin6_family = AF_INET6;
	v6.sin6_port = htons((uint16_t)v6port);
	inet_pton(AF_INET6, "::1", &v6.sin6_addr);

	TAP_GROUP("TST-01: hook matrix, IPv4 connected");
	run_matrix("v4-conn", AF_INET, (struct sockaddr *)&v4, sizeof(v4), 1);

	TAP_GROUP("TST-01: hook matrix, IPv4 unconnected");
	run_matrix("v4-unconn", AF_INET, (struct sockaddr *)&v4, sizeof(v4), 0);

	if (v6port > 0) {
		TAP_GROUP("TST-01: hook matrix, IPv6 connected");
		run_matrix("v6-conn", AF_INET6, (struct sockaddr *)&v6,
		           sizeof(v6), 1);

		TAP_GROUP("TST-01: hook matrix, IPv6 unconnected");
		run_matrix("v6-unconn", AF_INET6, (struct sockaddr *)&v6,
		           sizeof(v6), 0);
	}

	TAP_DONE();
}

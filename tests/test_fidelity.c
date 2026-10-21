/* test_fidelity.c -- TST-05, syscall fidelity (FR-F-01…FR-F-11, FR-I-05).
 *
 * §3 of the requirements is where the project succeeds or fails: every
 * assertion here is about being indistinguishable from an unhooked socket.
 *
 * Run under the shim:
 *   udpchains ./test_fidelity <echo1_v4> <echo2_v4> <echo_v6>
 */
#include "tap.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#ifndef SOL_UDP
#define SOL_UDP 17
#endif
#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif

static struct sockaddr_in g_echo1, g_echo2;
static struct sockaddr_in6 g_echo6;

static int udp4(void)
{
	struct timeval tv = { 3, 0 };
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (fd >= 0)
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return fd;
}

static void t_send_return_value(void)
{
	int fd = udp4();
	char buf[64];
	ssize_t n;

	TAP_GROUP("FR-F-01: a send returns the byte count the application supplied");

	memset(buf, 'x', sizeof(buf));
	n = sendto(fd, buf, 40, 0, (struct sockaddr *)&g_echo1, sizeof(g_echo1));

	/* The wrapped datagram is 40 + 10 bytes on the wire.  Reporting 50
	 * would be the classic leak of an implementation detail. */
	TAP_EQ_INT(n, 40, "sendto returns 40, not the wrapped 50");
	close(fd);
}

static void t_source_address(void)
{
	int fd = udp4();
	struct sockaddr_in from;
	socklen_t flen = sizeof(from);
	char buf[64];
	ssize_t n;

	TAP_GROUP("FR-F-02: the source is the true origin, not the relay");

	sendto(fd, "src", 3, 0, (struct sockaddr *)&g_echo1, sizeof(g_echo1));
	memset(&from, 0, sizeof(from));
	n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &flen);

	TAP_EQ_INT(n, 3, "payload arrives");
	TAP_EQ_INT(from.sin_family, AF_INET, "source family is AF_INET");
	TAP_EQ_INT(ntohs(from.sin_port), ntohs(g_echo1.sin_port),
	           "source port is the echo server's, not the relay's");
	TAP_EQ_INT(flen, sizeof(struct sockaddr_in), "source length is set");
	close(fd);
}

static void t_datagram_boundaries(void)
{
	int fd = udp4();
	char buf[64];
	int i;

	TAP_GROUP("FR-F-03: datagram boundaries are preserved exactly");

	for (i = 0; i < 3; i++) {
		char msg[32];
		snprintf(msg, sizeof(msg), "dgram-%d", i);
		sendto(fd, msg, strlen(msg), 0, (struct sockaddr *)&g_echo1,
		       sizeof(g_echo1));
	}
	for (i = 0; i < 3; i++) {
		char want[32];
		ssize_t n;

		snprintf(want, sizeof(want), "dgram-%d", i);
		memset(buf, 0, sizeof(buf));
		n = recv(fd, buf, sizeof(buf), 0);
		TAP_OK(n == (ssize_t)strlen(want) && memcmp(buf, want, n) == 0,
		       "datagram %d arrives whole and separate (%zd bytes)", i, n);
	}
	close(fd);
}

static void t_truncation(void)
{
	int fd = udp4();
	char payload[100];
	char small[10];
	struct msghdr msg;
	struct iovec iov;
	ssize_t n;

	TAP_GROUP("FR-F-04: MSG_TRUNC semantics match the kernel");

	memset(payload, 'T', sizeof(payload));

	/* recv into a short buffer: the excess is discarded. */
	sendto(fd, payload, sizeof(payload), 0, (struct sockaddr *)&g_echo1,
	       sizeof(g_echo1));
	n = recv(fd, small, sizeof(small), 0);
	TAP_EQ_INT(n, 10, "a short recv returns what fit");

	/* recvmsg into a short buffer sets MSG_TRUNC in msg_flags. */
	sendto(fd, payload, sizeof(payload), 0, (struct sockaddr *)&g_echo1,
	       sizeof(g_echo1));
	iov.iov_base = small;
	iov.iov_len = sizeof(small);
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	n = recvmsg(fd, &msg, 0);
	TAP_EQ_INT(n, 10, "recvmsg returns what fit");
	TAP_OK((msg.msg_flags & MSG_TRUNC) != 0,
	       "recvmsg sets MSG_TRUNC in msg_flags when it truncated");

	/* recvmsg WITH MSG_TRUNC requested returns the true payload length. */
	sendto(fd, payload, sizeof(payload), 0, (struct sockaddr *)&g_echo1,
	       sizeof(g_echo1));
	iov.iov_base = small;
	iov.iov_len = sizeof(small);
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	n = recvmsg(fd, &msg, MSG_TRUNC);
	TAP_EQ_INT(n, 100, "recvmsg with MSG_TRUNC returns the TRUE length");

	/* A datagram that fits must not be flagged. */
	sendto(fd, payload, 8, 0, (struct sockaddr *)&g_echo1, sizeof(g_echo1));
	iov.iov_base = payload;
	iov.iov_len = sizeof(payload);
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	n = recvmsg(fd, &msg, 0);
	TAP_EQ_INT(n, 8, "a datagram that fits returns its length");
	TAP_OK((msg.msg_flags & MSG_TRUNC) == 0,
	       "and does not set MSG_TRUNC");
	close(fd);
}

static void t_peek(void)
{
	int fd = udp4();
	char buf[64], buf2[64];
	ssize_t n1, n2;

	TAP_GROUP("FR-F-05: MSG_PEEK does not consume the datagram");

	sendto(fd, "peekable", 8, 0, (struct sockaddr *)&g_echo1, sizeof(g_echo1));

	memset(buf, 0, sizeof(buf));
	n1 = recv(fd, buf, sizeof(buf), MSG_PEEK);
	TAP_EQ_INT(n1, 8, "peek returns the unwrapped payload length");
	TAP_OK(memcmp(buf, "peekable", 8) == 0,
	       "peek returns unwrapped payload, with no SOCKS header");

	memset(buf2, 0, sizeof(buf2));
	n2 = recv(fd, buf2, sizeof(buf2), 0);
	TAP_EQ_INT(n2, 8, "the following real receive still gets the datagram");
	TAP_OK(memcmp(buf2, "peekable", 8) == 0,
	       "and returns the identical payload");

	/* Peeking twice must be idempotent. */
	sendto(fd, "twice", 5, 0, (struct sockaddr *)&g_echo1, sizeof(g_echo1));
	memset(buf, 0, sizeof(buf));
	memset(buf2, 0, sizeof(buf2));
	recv(fd, buf, sizeof(buf), MSG_PEEK);
	recv(fd, buf2, sizeof(buf2), MSG_PEEK);
	TAP_OK(memcmp(buf, buf2, 5) == 0, "two peeks return the same bytes");
	recv(fd, buf, sizeof(buf), 0);
	close(fd);
}

static void t_zero_length(void)
{
	int fd = udp4();
	char buf[64];
	ssize_t n;

	TAP_GROUP("FR-F-06: a zero-length datagram is distinct from no datagram");

	n = sendto(fd, "", 0, 0, (struct sockaddr *)&g_echo1, sizeof(g_echo1));
	TAP_EQ_INT(n, 0, "sending zero bytes returns 0, not an error");

	n = recv(fd, buf, sizeof(buf), 0);
	TAP_EQ_INT(n, 0, "receiving it returns 0, a real zero-length datagram");

	/* With nothing queued, a non-blocking receive reports EAGAIN -- which is
	 * how "no datagram" differs from "a zero-length datagram". */
	errno = 0;
	n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
	TAP_EQ_INT(n, -1, "with nothing queued the receive fails");
	TAP_OK(errno == EAGAIN || errno == EWOULDBLOCK,
	       "and reports EAGAIN, not a zero-length read (errno=%d)", errno);
	close(fd);
}

static void t_emsgsize(void)
{
	int fd = udp4();
	static char big[20000];
	ssize_t n;

	TAP_GROUP("FR-F-07: an oversized payload is EMSGSIZE, never a silent drop");

	memset(big, 'B', sizeof(big));
	errno = 0;
	n = sendto(fd, big, sizeof(big), 0, (struct sockaddr *)&g_echo1,
	           sizeof(g_echo1));
	TAP_EQ_INT(n, -1, "a payload beyond max_datagram fails");
	TAP_EQ_INT(errno, EMSGSIZE, "with EMSGSIZE");

	/* Exactly at the limit must still work. */
	errno = 0;
	n = sendto(fd, big, 8192, 0, (struct sockaddr *)&g_echo1, sizeof(g_echo1));
	TAP_EQ_INT(n, 8192, "a payload exactly at max_datagram is accepted");
	close(fd);
}

static void t_connect_semantics(void)
{
	int fd = udp4();
	char buf[64];
	struct sockaddr_in peer;
	socklen_t plen = sizeof(peer);
	ssize_t n;

	TAP_GROUP("FR-F-08: connect, re-connect, and AF_UNSPEC");

	TAP_EQ_INT(connect(fd, (struct sockaddr *)&g_echo1, sizeof(g_echo1)), 0,
	           "connect to the first echo server succeeds");

	/* FR-I-05: getpeername reports the destination the application named,
	 * never the relay the fd is really connected to. */
	TAP_EQ_INT(getpeername(fd, (struct sockaddr *)&peer, &plen), 0,
	           "getpeername succeeds on a connected socket");
	TAP_EQ_INT(ntohs(peer.sin_port), ntohs(g_echo1.sin_port),
	           "getpeername reports the echo server, NOT the relay");

	send(fd, "one", 3, 0);
	memset(buf, 0, sizeof(buf));
	n = recv(fd, buf, sizeof(buf), 0);
	TAP_OK(n == 3 && memcmp(buf, "one", 3) == 0,
	       "a connected send/recv round-trips");

	/* Re-connect re-targets. */
	TAP_EQ_INT(connect(fd, (struct sockaddr *)&g_echo2, sizeof(g_echo2)), 0,
	           "a second connect succeeds");
	plen = sizeof(peer);
	getpeername(fd, (struct sockaddr *)&peer, &plen);
	TAP_EQ_INT(ntohs(peer.sin_port), ntohs(g_echo2.sin_port),
	           "getpeername now reports the second echo server");

	send(fd, "two", 3, 0);
	memset(buf, 0, sizeof(buf));
	n = recv(fd, buf, sizeof(buf), 0);
	TAP_OK(n == 3 && memcmp(buf, "two", 3) == 0,
	       "traffic now reaches the re-targeted destination");

	/* AF_UNSPEC dissolves the association, per POSIX. */
	{
		struct sockaddr sa;
		memset(&sa, 0, sizeof(sa));
		sa.sa_family = AF_UNSPEC;
		TAP_EQ_INT(connect(fd, &sa, sizeof(sa)), 0,
		           "connect(AF_UNSPEC) succeeds");
	}
	plen = sizeof(peer);
	errno = 0;
	TAP_EQ_INT(getpeername(fd, (struct sockaddr *)&peer, &plen), -1,
	           "getpeername now fails");
	TAP_EQ_INT(errno, ENOTCONN, "with ENOTCONN, the socket being unconnected");

	errno = 0;
	n = send(fd, "three", 5, 0);
	TAP_EQ_INT(n, -1, "a destination-less send now fails");
	TAP_EQ_INT(errno, EDESTADDRREQ, "with EDESTADDRREQ");

	/* But an explicit destination still works. */
	n = sendto(fd, "four", 4, 0, (struct sockaddr *)&g_echo1, sizeof(g_echo1));
	TAP_EQ_INT(n, 4, "sendto with an explicit destination still works");
	memset(buf, 0, sizeof(buf));
	n = recv(fd, buf, sizeof(buf), 0);
	TAP_OK(n == 4 && memcmp(buf, "four", 4) == 0, "and round-trips");
	close(fd);
}

static void t_mmsg(void)
{
	int fd = udp4();
	struct mmsghdr smsgs[3], rmsgs[3];
	struct iovec siov[3], riov[3];
	char sbuf[3][32], rbuf[3][64];
	int rc, i;

	TAP_GROUP("FR-F-09: sendmmsg/recvmmsg handle each message independently");

	memset(smsgs, 0, sizeof(smsgs));
	for (i = 0; i < 3; i++) {
		snprintf(sbuf[i], sizeof(sbuf[i]), "mmsg-%d", i);
		siov[i].iov_base = sbuf[i];
		siov[i].iov_len = strlen(sbuf[i]);
		smsgs[i].msg_hdr.msg_name = &g_echo1;
		smsgs[i].msg_hdr.msg_namelen = sizeof(g_echo1);
		smsgs[i].msg_hdr.msg_iov = &siov[i];
		smsgs[i].msg_hdr.msg_iovlen = 1;
	}

	rc = sendmmsg(fd, smsgs, 3, 0);
	TAP_EQ_INT(rc, 3, "sendmmsg reports all three messages sent");
	for (i = 0; i < 3; i++)
		TAP_EQ_INT(smsgs[i].msg_len, strlen(sbuf[i]),
		           "msg_len[%d] is the application's length, not the "
		           "wrapped one",
		           i);

	memset(rmsgs, 0, sizeof(rmsgs));
	for (i = 0; i < 3; i++) {
		memset(rbuf[i], 0, sizeof(rbuf[i]));
		riov[i].iov_base = rbuf[i];
		riov[i].iov_len = sizeof(rbuf[i]);
		rmsgs[i].msg_hdr.msg_iov = &riov[i];
		rmsgs[i].msg_hdr.msg_iovlen = 1;
	}
	rc = recvmmsg(fd, rmsgs, 3, 0, NULL);
	TAP_EQ_INT(rc, 3, "recvmmsg reports all three messages received");
	for (i = 0; i < 3; i++)
		TAP_OK(rmsgs[i].msg_len == strlen(sbuf[i]) &&
		               memcmp(rbuf[i], sbuf[i], rmsgs[i].msg_len) == 0,
		       "message %d round-trips byte-identically", i);
	close(fd);
}

static void t_scatter_gather(void)
{
	int fd = udp4();
	struct iovec siov[3], riov[4];
	char part1[] = "AAAA", part2[] = "BBBBBB", part3[] = "CC";
	char r[4][8];
	struct msghdr msg;
	ssize_t n;

	TAP_GROUP("FR-F-10: scatter/gather, including a header that would straddle");

	siov[0].iov_base = part1;
	siov[0].iov_len = 4;
	siov[1].iov_base = part2;
	siov[1].iov_len = 6;
	siov[2].iov_base = part3;
	siov[2].iov_len = 2;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &g_echo1;
	msg.msg_namelen = sizeof(g_echo1);
	msg.msg_iov = siov;
	msg.msg_iovlen = 3;
	n = sendmsg(fd, &msg, 0);
	TAP_EQ_INT(n, 12, "a 3-iovec send returns the total application length");

	/* Receive into four small iovecs of 3 bytes each.  If the shim ever
	 * failed to strip the header, the first iovec would hold header bytes
	 * -- and because the header is 10 bytes and each iovec is 3, it would
	 * straddle the boundary, which is the case FR-F-10 calls out. */
	memset(r, 0, sizeof(r));
	riov[0].iov_base = r[0];
	riov[0].iov_len = 3;
	riov[1].iov_base = r[1];
	riov[1].iov_len = 3;
	riov[2].iov_base = r[2];
	riov[2].iov_len = 3;
	riov[3].iov_base = r[3];
	riov[3].iov_len = 3;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = riov;
	msg.msg_iovlen = 4;
	n = recvmsg(fd, &msg, 0);
	TAP_EQ_INT(n, 12, "a 4-iovec receive returns 12 bytes");
	TAP_OK(memcmp(r[0], "AAA", 3) == 0 && memcmp(r[1], "ABB", 3) == 0 &&
	               memcmp(r[2], "BBB", 3) == 0 && memcmp(r[3], "BCC", 3) == 0,
	       "the payload is split across iovecs with no header bytes present");
	close(fd);
}

static void t_ancillary(void)
{
	int fd = udp4();
	char buf[64];
	char control[256];
	struct msghdr msg;
	struct iovec iov;
	ssize_t n;

	TAP_GROUP("FR-F-11: ancillary data is returned empty, not misleading");

	sendto(fd, "anc", 3, 0, (struct sockaddr *)&g_echo1, sizeof(g_echo1));

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	n = recvmsg(fd, &msg, 0);
	TAP_EQ_INT(n, 3, "the datagram arrives");
	TAP_EQ_INT(msg.msg_controllen, 0, "msg_controllen is zeroed");
	TAP_OK((msg.msg_flags & MSG_CTRUNC) == 0,
	       "MSG_CTRUNC is not set: nothing was truncated, there was nothing");
	close(fd);
}

static void t_getsockname(void)
{
	int fd = udp4();
	struct sockaddr_in local, bindaddr;
	socklen_t llen = sizeof(local);

	TAP_GROUP("FR-I-05: getsockname reports the application's local address");

	memset(&bindaddr, 0, sizeof(bindaddr));
	bindaddr.sin_family = AF_INET;
	bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	bindaddr.sin_port = 0;
	TAP_EQ_INT(bind(fd, (struct sockaddr *)&bindaddr, sizeof(bindaddr)), 0,
	           "bind to 127.0.0.1:0 succeeds");

	sendto(fd, "gs", 2, 0, (struct sockaddr *)&g_echo1, sizeof(g_echo1));

	memset(&local, 0, sizeof(local));
	TAP_EQ_INT(getsockname(fd, (struct sockaddr *)&local, &llen), 0,
	           "getsockname succeeds");
	TAP_EQ_INT(local.sin_family, AF_INET, "family is AF_INET");
	TAP_OK(local.sin_addr.s_addr == htonl(INADDR_LOOPBACK),
	       "address is the one the application bound");
	TAP_OK(ntohs(local.sin_port) != 0,
	       "port is the concrete one the kernel assigned (%u)",
	       ntohs(local.sin_port));
	close(fd);
}

static void t_ipv6(void)
{
	struct timeval tv = { 3, 0 };
	int fd = socket(AF_INET6, SOCK_DGRAM, 0);
	struct sockaddr_in6 from;
	socklen_t flen = sizeof(from);
	char buf[64];
	ssize_t n;

	TAP_GROUP("IPv6 end to end (M7, FR-F-02 on AF_INET6)");

	if (fd < 0) {
		TAP_OK(0, "AF_INET6 socket creation failed");
		return;
	}
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	n = sendto(fd, "v6payload", 9, 0, (struct sockaddr *)&g_echo6,
	           sizeof(g_echo6));
	TAP_EQ_INT(n, 9, "an IPv6 send returns the application's length");

	memset(buf, 0, sizeof(buf));
	memset(&from, 0, sizeof(from));
	n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &flen);
	TAP_EQ_INT(n, 9, "the IPv6 reply arrives");
	TAP_OK(memcmp(buf, "v6payload", 9) == 0, "and is byte-identical");
	TAP_EQ_INT(from.sin6_family, AF_INET6, "source family is AF_INET6");
	TAP_EQ_INT(ntohs(from.sin6_port), ntohs(g_echo6.sin6_port),
	           "source is the IPv6 echo server, not the relay");
	close(fd);
}

static void t_connected_peer_filter(void)
{
	int fd = udp4();
	char buf[64];
	ssize_t n;

	TAP_GROUP("a connected socket receives only from its connected peer");

	/* An unhooked connected UDP socket only ever receives from the peer it
	 * is connected to; the kernel drops the rest before the application
	 * sees anything.  Under the shim every datagram arrives from the relay,
	 * so that filter has to be reimplemented against the true origin -- or
	 * the shim ends up MORE permissive than a real socket, which is the
	 * wrong direction for §3.
	 *
	 * This is also why TFTP clients use an unconnected socket: the server
	 * replies from a different port than the one addressed. */
	TAP_EQ_INT(connect(fd, (struct sockaddr *)&g_echo1, sizeof(g_echo1)), 0,
	           "connect to the first echo server");

	/* Linux permits sendto with an explicit destination on a connected UDP
	 * socket, so the second echo server can be provoked into replying from
	 * an address this socket is NOT connected to. */
	n = sendto(fd, "stranger", 8, 0, (struct sockaddr *)&g_echo2,
	           sizeof(g_echo2));
	TAP_EQ_INT(n, 8, "sendto a different peer is accepted");

	/* Wait for the stranger's reply to actually arrive before checking that
	 * it is refused.  Without this the non-blocking receive below can report
	 * EAGAIN merely because nothing has arrived yet -- passing for the wrong
	 * reason, and leaving the datagram queued to surface later in this test. */
	{
		struct timespec ts = { 0, 300000000L }; /* 300 ms */
		nanosleep(&ts, NULL);
	}

	errno = 0;
	n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
	TAP_EQ_INT(n, -1, "its reply is NOT delivered");
	TAP_OK(errno == EAGAIN || errno == EWOULDBLOCK,
	       "the socket reports EAGAIN, exactly as the kernel would (errno=%s)",
	       strerror(errno));

	/* The connected peer must still get through -- the filter has to reject
	 * the stranger without breaking the ordinary case. */
	TAP_EQ_INT(send(fd, "expected", 8, 0), 8, "a send to the connected peer works");
	memset(buf, 0, sizeof(buf));
	n = recv(fd, buf, sizeof(buf), 0);
	TAP_OK(n == 8 && memcmp(buf, "expected", 8) == 0,
	       "and its reply is delivered normally");

	/* Once disconnected, the filter must stop applying. */
	{
		struct sockaddr sa;
		memset(&sa, 0, sizeof(sa));
		sa.sa_family = AF_UNSPEC;
		connect(fd, &sa, sizeof(sa));
	}
	n = sendto(fd, "now-ok", 6, 0, (struct sockaddr *)&g_echo2,
	           sizeof(g_echo2));
	TAP_EQ_INT(n, 6, "after AF_UNSPEC, a send to the other peer works");
	memset(buf, 0, sizeof(buf));
	n = recv(fd, buf, sizeof(buf), 0);
	TAP_OK(n == 6 && memcmp(buf, "now-ok", 6) == 0,
	       "and an unconnected socket accepts its reply");

	close(fd);
}

static void t_dualstack_to_ipv4(void)
{
	struct timeval tv = { 3, 0 };
	int fd = socket(AF_INET6, SOCK_DGRAM, 0);
	struct sockaddr_in6 dst, from;
	socklen_t flen = sizeof(from);
	char buf[64];
	char mapped[64];
	ssize_t n;

	TAP_GROUP("dual-stack socket to an IPv4 destination (the interop case)");

	/* This is what an application gets by default on a dual-stack host: an
	 * AF_INET6 socket whose destination is ::ffff:a.b.c.d because
	 * getaddrinfo returned a v4-mapped address for an IPv4-only peer.  nc,
	 * and most getaddrinfo-based clients, land here without asking for it.
	 *
	 * The shim must encode that destination as ATYP 0x01 with four bytes.
	 * Emitting ATYP 0x04 with the sixteen-byte mapped form asks the proxy to
	 * reach an IPv6 address that does not exist -- a real proxy drops the
	 * datagram and says nothing, while the association looks healthy from
	 * both ends.  The fixture is strict about this on purpose. */
	if (fd < 0) {
		TAP_OK(0, "AF_INET6 socket creation failed");
		return;
	}
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	snprintf(mapped, sizeof(mapped), "::ffff:127.0.0.1");
	memset(&dst, 0, sizeof(dst));
	dst.sin6_family = AF_INET6;
	dst.sin6_port = g_echo1.sin_port; /* the IPv4 echo server */
	inet_pton(AF_INET6, mapped, &dst.sin6_addr);

	n = sendto(fd, "dualstack", 9, 0, (struct sockaddr *)&dst, sizeof(dst));
	TAP_EQ_INT(n, 9, "a send to ::ffff:127.0.0.1 returns the app's length");

	memset(buf, 0, sizeof(buf));
	memset(&from, 0, sizeof(from));
	n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &flen);
	TAP_EQ_INT(n, 9, "the reply arrives from the IPv4 echo server");
	TAP_OK(memcmp(buf, "dualstack", 9) == 0, "and is byte-identical");

	/* FR-F-02 on a dual-stack socket: the kernel would report the peer as
	 * ::ffff:a.b.c.d, so the shim must too -- an AF_INET sockaddr is not
	 * something the application has anywhere to put. */
	TAP_EQ_INT(from.sin6_family, AF_INET6,
	           "the source is reported in the socket's own family");
	TAP_OK(IN6_IS_ADDR_V4MAPPED(&from.sin6_addr),
	       "as a v4-mapped address, exactly as the kernel would");
	TAP_EQ_INT(ntohs(from.sin6_port), ntohs(g_echo1.sin_port),
	           "with the echo server's port, not the relay's");

	/* Connected, too -- the path nc actually takes. */
	TAP_EQ_INT(connect(fd, (struct sockaddr *)&dst, sizeof(dst)), 0,
	           "connect to a v4-mapped destination succeeds");
	TAP_EQ_INT(send(fd, "conn-ds", 7, 0), 7, "a connected send works");
	memset(buf, 0, sizeof(buf));
	n = recv(fd, buf, sizeof(buf), 0);
	TAP_OK(n == 7 && memcmp(buf, "conn-ds", 7) == 0,
	       "and round-trips byte-identically");

	close(fd);
}

static void t_unrepresentable(void)
{
	int fd = udp4();
	struct sockaddr_in mc, bc;
	int one = 1;
	ssize_t n;

	TAP_GROUP("D-05 R1 / ADD-01: multicast and broadcast fail with a reason");

	/* SOCKS5 has no way to express either.  With no bypass in v1 (D-05),
	 * failing is the only honest outcome -- what must never happen is the
	 * datagram going out directly. */
	memset(&mc, 0, sizeof(mc));
	mc.sin_family = AF_INET;
	mc.sin_port = htons(5353);
	inet_pton(AF_INET, "224.0.0.251", &mc.sin_addr); /* mDNS */

	errno = 0;
	n = sendto(fd, "mdns", 4, 0, (struct sockaddr *)&mc, sizeof(mc));
	TAP_EQ_INT(n, -1, "a send to multicast 224.0.0.251 fails");
	TAP_EQ_INT(errno, ENETUNREACH, "with ENETUNREACH");

	memset(&bc, 0, sizeof(bc));
	bc.sin_family = AF_INET;
	bc.sin_port = htons(67);
	bc.sin_addr.s_addr = htonl(INADDR_BROADCAST);

	/* SO_BROADCAST is not hooked, so it succeeds and the send then fails.
	 * Odd-looking but honest -- and the diagnostic explains it. */
	TAP_EQ_INT(setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one)), 0,
	           "SO_BROADCAST still succeeds (setsockopt is not hooked)");
	errno = 0;
	n = sendto(fd, "dhcp", 4, 0, (struct sockaddr *)&bc, sizeof(bc));
	TAP_EQ_INT(n, -1, "a send to 255.255.255.255 fails");
	TAP_EQ_INT(errno, ENETUNREACH, "with ENETUNREACH");

	close(fd);

	/* IPv6 multicast too. */
	{
		int fd6 = socket(AF_INET6, SOCK_DGRAM, 0);
		struct sockaddr_in6 mc6;

		memset(&mc6, 0, sizeof(mc6));
		mc6.sin6_family = AF_INET6;
		mc6.sin6_port = htons(5353);
		inet_pton(AF_INET6, "ff02::fb", &mc6.sin6_addr);

		errno = 0;
		n = sendto(fd6, "mdns6", 5, 0, (struct sockaddr *)&mc6, sizeof(mc6));
		TAP_EQ_INT(n, -1, "a send to IPv6 multicast ff02::fb fails");
		TAP_EQ_INT(errno, ENETUNREACH, "with ENETUNREACH");
		close(fd6);
	}
}

static void t_passthrough(void)
{
	int sv[2];
	int tcp;
	char buf[16];

	TAP_GROUP("FR-I-06: non-UDP sockets pass through untouched");

	TAP_EQ_INT(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv), 0,
	           "a unix datagram socketpair is created");
	TAP_EQ_INT(write(sv[0], "unix", 4), 4,
	           "write on a unix socket is not intercepted");
	memset(buf, 0, sizeof(buf));
	TAP_EQ_INT(read(sv[1], buf, sizeof(buf)), 4, "and read returns 4");
	TAP_OK(memcmp(buf, "unix", 4) == 0, "with the exact bytes written");
	close(sv[0]);
	close(sv[1]);

	tcp = socket(AF_INET, SOCK_STREAM, 0);
	TAP_OK(tcp >= 0, "a TCP socket is created and not intercepted");
	close(tcp);
}

/* L1, L2: arguments the shim reads itself are checked the way the kernel would
 * check them, rather than read past or crashed on. */
static void t_argument_checks(void)
{
	static char bytes[IOV_MAX];
	char rb[2 * IOV_MAX];
	struct iovec *v;
	struct msghdr m;
	int fd = udp4(), f6, i;

	TAP_GROUP("L1/L2: arguments are checked as the kernel checks them");

	errno = 0;
	TAP_OK(connect(fd, (struct sockaddr *)&g_echo1, 8) == -1 && errno == EINVAL,
	       "connect() with an address too short for AF_INET is EINVAL");
	errno = 0;
	TAP_OK(sendto(fd, "x", 1, 0, (struct sockaddr *)&g_echo1, 8) == -1 &&
	           errno == EINVAL,
	       "so is sendto()");

	f6 = socket(AF_INET6, SOCK_DGRAM, 0);
	{
		struct timeval tv = { 3, 0 };
		setsockopt(f6, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}
	TAP_EQ_INT(sendto(f6, "v6", 2, 0, (struct sockaddr *)&g_echo6, 24), 2,
	           "a 24-byte AF_INET6 address, without the scope field, is "
	           "accepted as the kernel accepts it");
	TAP_EQ_INT(recv(f6, rb, sizeof(rb), 0), 2, "and round-trips");
	close(f6);

	memset(&m, 0, sizeof(m));
	m.msg_name = &g_echo1;
	m.msg_namelen = sizeof(g_echo1);
	m.msg_iov = NULL;
	m.msg_iovlen = 1;
	errno = 0;
	TAP_OK(sendmsg(fd, &m, 0) == -1 && errno == EFAULT,
	       "sendmsg() with a NULL iovec array is EFAULT, not a crash");

	v = calloc((size_t)IOV_MAX + 1, sizeof(*v));
	m.msg_iov = v;
	m.msg_iovlen = (size_t)IOV_MAX + 1;
	errno = 0;
	TAP_OK(sendmsg(fd, &m, 0) == -1 && errno == EMSGSIZE,
	       "msg_iovlen above IOV_MAX is EMSGSIZE");
	m.msg_iovlen = ((size_t)1 << 32) | 1;
	errno = 0;
	TAP_OK(sendmsg(fd, &m, 0) == -1 && errno == EMSGSIZE,
	       "and one that would wrap to 1 as an int is caught before the cast");

	/* The shim's header needs an iovec of its own; with every one the
	 * kernel allows already used, it must not be the reason a send that
	 * would work unhooked fails. */
	for (i = 0; i < IOV_MAX; i++) {
		bytes[i] = (char)('a' + i % 26);
		v[i].iov_base = &bytes[i];
		v[i].iov_len = 1;
	}
	m.msg_iovlen = IOV_MAX;
	TAP_EQ_INT(sendmsg(fd, &m, 0), IOV_MAX,
	           "a send of exactly IOV_MAX iovecs succeeds, as it does unhooked");
	TAP_EQ_INT(recv(fd, rb, sizeof(rb), 0), IOV_MAX, "and arrives whole");
	TAP_EQ_MEM(rb, bytes, IOV_MAX, "byte for byte");
	free(v);
	close(fd);
}

/* D-29: a datagram socket that is not UDP carries something SOCKS5 cannot relay,
 * so it is refused -- neither sent directly nor wrapped as UDP. */
static void t_non_udp_refused(void)
{
	int fd;
	char buf[16];

	TAP_GROUP("D-29: non-UDP datagram sockets are refused, not let through");

	errno = 0;
	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
	TAP_OK(fd < 0 && errno == EPROTONOSUPPORT,
	       "an ICMP ping socket is refused with EPROTONOSUPPORT");
	errno = 0;
	fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
	TAP_OK(fd < 0 && errno == EPROTONOSUPPORT, "so is an ICMPv6 one");
	errno = 0;
	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDPLITE);
	TAP_OK(fd < 0 && errno == EPROTONOSUPPORT, "and a UDP-Lite one");

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	TAP_OK(fd >= 0, "IPPROTO_UDP named explicitly is still accepted");
	{
		struct timeval tv = { 3, 0 };
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}
	sendto(fd, "udp", 3, 0, (struct sockaddr *)&g_echo1, sizeof(g_echo1));
	TAP_EQ_INT(recv(fd, buf, sizeof(buf), 0), 3, "and proxied like any other");
	close(fd);
}

/* A _FORTIFY_SOURCE build calls these instead of recvfrom/recv/read when the
 * buffer's size is known and the length is not.  glibc's own implementations
 * bypass the hooks and deliver the SOCKS header as payload.  Called directly
 * here, so the test does not depend on how this file happens to be compiled. */
ssize_t __recv_chk(int fd, void *buf, size_t len, size_t buflen, int flags);
ssize_t __recvfrom_chk(int fd, void *buf, size_t len, size_t buflen, int flags,
                       struct sockaddr *src, socklen_t *srclen);
ssize_t __read_chk(int fd, void *buf, size_t len, size_t buflen);

static void t_fortified(void)
{
	int fd = udp4();
	char buf[64];
	struct sockaddr_in from;
	socklen_t flen = sizeof(from);
	ssize_t n;

	TAP_GROUP("FR-I-02: fortified receive entry points strip the header too");

	sendto(fd, "chk1", 4, 0, (struct sockaddr *)&g_echo1, sizeof(g_echo1));
	memset(buf, 0, sizeof(buf));
	memset(&from, 0, sizeof(from));
	n = __recvfrom_chk(fd, buf, sizeof(buf), sizeof(buf), 0,
	                   (struct sockaddr *)&from, &flen);
	TAP_EQ_INT(n, 4, "__recvfrom_chk returns 4, not the wrapped 14");
	TAP_EQ_MEM(buf, "chk1", 4, "__recvfrom_chk delivers the bare payload");
	TAP_EQ_INT(ntohs(from.sin_port), ntohs(g_echo1.sin_port),
	           "__recvfrom_chk reports the true source, not the relay");

	connect(fd, (struct sockaddr *)&g_echo1, sizeof(g_echo1));

	send(fd, "chk2", 4, 0);
	memset(buf, 0, sizeof(buf));
	n = __recv_chk(fd, buf, sizeof(buf), sizeof(buf), 0);
	TAP_EQ_INT(n, 4, "__recv_chk returns 4, not the wrapped 14");
	TAP_EQ_MEM(buf, "chk2", 4, "__recv_chk delivers the bare payload");

	TAP_EQ_INT(write(fd, "chk3", 4), 4, "write sends the third probe");
	memset(buf, 0, sizeof(buf));
	n = __read_chk(fd, buf, sizeof(buf), sizeof(buf));
	TAP_EQ_INT(n, 4, "__read_chk returns 4, not the wrapped 14");
	TAP_EQ_MEM(buf, "chk3", 4, "__read_chk delivers the bare payload");

	close(fd);
}

/* D-36: calls that reach the kernel without passing through a send or receive
 * hook.  Through syscall() they are routed to the hooks; dprintf is formatted
 * and sent through the shim; stdio, sendfile and splice, which glibc and the
 * kernel carry out without any hook, are refused on a UDP socket. */
int __dprintf_chk(int fd, int flag, const char *fmt, ...);

static int vdprintf_wrap(int fd, const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vdprintf(fd, fmt, ap);
	va_end(ap);
	return n;
}

static void t_syscall_routes(void)
{
	struct sockaddr_in peer;
	socklen_t plen = sizeof(peer);
	struct msghdr m;
	struct iovec v;
	char buf[64], s2[] = "sys2";
	int fd = udp4();

	TAP_GROUP("D-36: socket calls made through syscall() go through the shim");

	/* Each syscall() is paired with an ordinary call on the other side.  A
	 * send that bypassed the shim gets a reply the receive hook cannot
	 * parse; a receive that bypassed it returns the SOCKS header. */
	TAP_EQ_INT(syscall(SYS_sendto, fd, "sys1", 4, 0, &g_echo1, sizeof(g_echo1)), 4,
	           "syscall(SYS_sendto) sends 4 bytes");
	memset(buf, 0, sizeof(buf));
	TAP_EQ_INT(recv(fd, buf, sizeof(buf), 0), 4, "and the reply comes back through the proxy");
	TAP_EQ_MEM(buf, "sys1", 4, "byte for byte");

	sendto(fd, "sys2", 4, 0, (struct sockaddr *)&g_echo1, sizeof(g_echo1));
	memset(buf, 0, sizeof(buf));
	TAP_EQ_INT(syscall(SYS_recvfrom, fd, buf, sizeof(buf), 0, NULL, NULL), 4,
	           "syscall(SYS_recvfrom) returns 4, not the wrapped 14");
	TAP_EQ_MEM(buf, "sys2", 4, "and the bare payload");

	v.iov_base = s2;
	v.iov_len = 4;
	memset(&m, 0, sizeof(m));
	m.msg_name = &g_echo1;
	m.msg_namelen = sizeof(g_echo1);
	m.msg_iov = &v;
	m.msg_iovlen = 1;
	TAP_EQ_INT(syscall(SYS_sendmsg, fd, &m, 0), 4, "syscall(SYS_sendmsg) sends 4 bytes");
	memset(buf, 0, sizeof(buf));
	TAP_EQ_INT(recv(fd, buf, sizeof(buf), 0), 4, "and the reply comes back through the proxy");
	TAP_EQ_MEM(buf, "sys2", 4, "byte for byte");
	close(fd);

	fd = udp4();
	TAP_EQ_INT(syscall(SYS_connect, fd, &g_echo1, sizeof(g_echo1)), 0,
	           "syscall(SYS_connect) succeeds");
	TAP_EQ_INT(send(fd, "sys3", 4, 0), 4,
	           "send() then has the destination the shim was told of");
	memset(buf, 0, sizeof(buf));
	TAP_EQ_INT(recv(fd, buf, sizeof(buf), 0), 4, "and the reply is proxied");
	TAP_EQ_INT(syscall(SYS_getpeername, fd, &peer, &plen), 0,
	           "syscall(SYS_getpeername) succeeds");
	TAP_EQ_INT(ntohs(peer.sin_port), ntohs(g_echo1.sin_port),
	           "and reports the program's destination, not the relay");
	TAP_EQ_INT(syscall(SYS_write, fd, "sys4", 4), 4, "syscall(SYS_write) sends 4 bytes");
	memset(buf, 0, sizeof(buf));
	TAP_EQ_INT(read(fd, buf, sizeof(buf)), 4, "and the reply is proxied");
	TAP_EQ_MEM(buf, "sys4", 4, "byte for byte");
	TAP_EQ_INT(write(fd, "sys5", 4), 4, "write() sends 4 bytes");
	memset(buf, 0, sizeof(buf));
	TAP_EQ_INT(syscall(SYS_read, fd, buf, sizeof(buf)), 4,
	           "syscall(SYS_read) returns 4, not the wrapped 14");
	TAP_EQ_MEM(buf, "sys5", 4, "and the bare payload");
	close(fd);
}

static void t_dprintf(void)
{
	char buf[64];
	int fd = udp4();

	TAP_GROUP("D-36: dprintf on a UDP socket is sent through the shim");

	connect(fd, (struct sockaddr *)&g_echo1, sizeof(g_echo1));
	TAP_EQ_INT(dprintf(fd, "dp%d", 1), 3, "dprintf returns the 3 bytes written");
	memset(buf, 0, sizeof(buf));
	TAP_EQ_INT(recv(fd, buf, sizeof(buf), 0), 3, "and they come back through the proxy");
	TAP_EQ_MEM(buf, "dp1", 3, "byte for byte");

	TAP_EQ_INT(vdprintf_wrap(fd, "vdp%d", 2), 4, "vdprintf returns 4");
	memset(buf, 0, sizeof(buf));
	TAP_EQ_INT(recv(fd, buf, sizeof(buf), 0), 4, "and is proxied");
	TAP_EQ_MEM(buf, "vdp2", 4, "byte for byte");

	TAP_EQ_INT(__dprintf_chk(fd, 1, "chk%d", 3), 4,
	           "__dprintf_chk, which _FORTIFY_SOURCE builds call, returns 4");
	memset(buf, 0, sizeof(buf));
	TAP_EQ_INT(recv(fd, buf, sizeof(buf), 0), 4, "and is proxied");
	TAP_EQ_MEM(buf, "chk3", 4, "byte for byte");
	close(fd);
}

ssize_t __write(int fd, const void *buf, size_t len);
ssize_t __read(int fd, void *buf, size_t len);
ssize_t __send(int fd, const void *buf, size_t len, int flags);

static void t_underscored_aliases(void)
{
	char buf[16];
	int fd = udp4();

	TAP_GROUP("D-36: glibc's public underscored aliases go through the shim");

	connect(fd, (struct sockaddr *)&g_echo1, sizeof(g_echo1));
	TAP_EQ_INT(__send(fd, "us1", 3, 0), 3, "__send sends 3 bytes");
	memset(buf, 0, sizeof(buf));
	TAP_EQ_INT(recv(fd, buf, sizeof(buf), 0), 3, "and the reply is proxied");
	TAP_EQ_INT(__write(fd, "us2", 3), 3, "__write sends 3 bytes");
	memset(buf, 0, sizeof(buf));
	TAP_EQ_INT(recv(fd, buf, sizeof(buf), 0), 3, "and the reply is proxied");
	TAP_EQ_INT(write(fd, "us3", 3), 3, "write sends the next probe");
	memset(buf, 0, sizeof(buf));
	TAP_EQ_INT(__read(fd, buf, sizeof(buf)), 3, "__read returns 3, not the wrapped 13");
	TAP_EQ_MEM(buf, "us3", 3, "and the bare payload");
	close(fd);
}

static void t_pwritev2(void)
{
	char buf[16], out[] = "pv2";
	struct iovec v = { out, 3 }, r = { buf, sizeof(buf) };
	int fd = udp4();

	TAP_GROUP("D-36: pwritev2 and preadv2 at the current position go through the shim");

	connect(fd, (struct sockaddr *)&g_echo1, sizeof(g_echo1));
	TAP_EQ_INT(pwritev2(fd, &v, 1, -1, 0), 3, "pwritev2 with offset -1 sends 3 bytes");
	memset(buf, 0, sizeof(buf));
	TAP_EQ_INT(recv(fd, buf, sizeof(buf), 0), 3, "and the reply is proxied");
	TAP_EQ_MEM(buf, "pv2", 3, "byte for byte");
	TAP_EQ_INT(write(fd, "pr2", 3), 3, "write sends the next probe");
	memset(buf, 0, sizeof(buf));
	TAP_EQ_INT(preadv2(fd, &r, 1, -1, 0), 3,
	           "preadv2 with offset -1 returns 3, not the wrapped 13");
	TAP_EQ_MEM(buf, "pr2", 3, "and the bare payload");
	errno = 0;
	TAP_OK(pwritev2(fd, &v, 1, 0, 0) == -1 && errno == ESPIPE,
	       "an explicit offset is ESPIPE, as on any socket");
	close(fd);
}

static void t_unhookable_refused(void)
{
	FILE *tf = tmpfile(), *f;
	int fd = udp4(), sv[2], p[2];
	off_t off = 0;

	TAP_GROUP("D-36: stdio, sendfile and splice are refused on a UDP socket");

	connect(fd, (struct sockaddr *)&g_echo1, sizeof(g_echo1));
	fputs("data", tf);
	fflush(tf);

	errno = 0;
	f = fdopen(fd, "w");
	TAP_OK(f == NULL && errno == EINVAL, "fdopen on a UDP socket fails with EINVAL");
	errno = 0;
	TAP_OK(sendfile(fd, fileno(tf), &off, 4) == -1 && errno == EINVAL,
	       "sendfile onto a UDP socket fails with EINVAL");
	TAP_EQ_INT(pipe(p), 0, "a pipe is created");
	TAP_EQ_INT(write(p[1], "spl", 3), 3, "and filled");
	errno = 0;
	TAP_OK(splice(p[0], NULL, fd, NULL, 3, 0) == -1 && errno == EINVAL,
	       "splice onto a UDP socket fails with EINVAL");

	/* The same calls on a Unix socket are not the shim's business. */
	TAP_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0, "a Unix socketpair is created");
	off = 0;
	TAP_EQ_INT(sendfile(sv[0], fileno(tf), &off, 4), 4,
	           "sendfile onto a Unix socket still works");
	TAP_EQ_INT(splice(p[0], NULL, sv[0], NULL, 3, 0), 3,
	           "and so does splice");
	f = fdopen(sv[0], "w");
	TAP_OK(f != NULL, "and fdopen");
	if (f != NULL)
		fclose(f);
	close(sv[1]);
	close(p[0]);
	close(p[1]);
	fclose(tf);
	close(fd);
}

static void t_cork_refused(void)
{
	union {
		struct cmsghdr align;
		char buf[CMSG_SPACE(sizeof(uint16_t))];
	} ctl;
	struct cmsghdr *c;
	struct msghdr m;
	struct iovec v;
	uint16_t seg = 100;
	char buf[16], gso[] = "gso";
	int fd = udp4();

	TAP_GROUP("D-36: MSG_MORE and GSO are refused rather than corrupting data");

	errno = 0;
	TAP_OK(sendto(fd, "m", 1, MSG_MORE, (struct sockaddr *)&g_echo1,
	              sizeof(g_echo1)) == -1 && errno == EOPNOTSUPP,
	       "sendto with MSG_MORE fails with EOPNOTSUPP");

	memset(&ctl, 0, sizeof(ctl));
	v.iov_base = gso;
	v.iov_len = 3;
	memset(&m, 0, sizeof(m));
	m.msg_name = &g_echo1;
	m.msg_namelen = sizeof(g_echo1);
	m.msg_iov = &v;
	m.msg_iovlen = 1;
	m.msg_control = ctl.buf;
	m.msg_controllen = sizeof(ctl.buf);
	c = CMSG_FIRSTHDR(&m);
	c->cmsg_level = SOL_UDP;
	c->cmsg_type = UDP_SEGMENT;
	c->cmsg_len = CMSG_LEN(sizeof(seg));
	memcpy(CMSG_DATA(c), &seg, sizeof(seg));
	errno = 0;
	TAP_OK(sendmsg(fd, &m, 0) == -1 && errno == EOPNOTSUPP,
	       "sendmsg with a UDP_SEGMENT control message fails with EOPNOTSUPP");

	TAP_EQ_INT(sendto(fd, "ok", 2, 0, (struct sockaddr *)&g_echo1, sizeof(g_echo1)), 2,
	           "a plain send on the same socket still works");
	TAP_EQ_INT(recv(fd, buf, sizeof(buf), 0), 2, "and is proxied");
	close(fd);
}

int main(int argc, char **argv)
{
	if (argc < 4) {
		fprintf(stderr,
		        "usage: test_fidelity <echo1_v4> <echo2_v4> <echo_v6>\n");
		return 2;
	}

	memset(&g_echo1, 0, sizeof(g_echo1));
	g_echo1.sin_family = AF_INET;
	g_echo1.sin_port = htons((uint16_t)atoi(argv[1]));
	inet_pton(AF_INET, "127.0.0.1", &g_echo1.sin_addr);

	memset(&g_echo2, 0, sizeof(g_echo2));
	g_echo2.sin_family = AF_INET;
	g_echo2.sin_port = htons((uint16_t)atoi(argv[2]));
	inet_pton(AF_INET, "127.0.0.1", &g_echo2.sin_addr);

	memset(&g_echo6, 0, sizeof(g_echo6));
	g_echo6.sin6_family = AF_INET6;
	g_echo6.sin6_port = htons((uint16_t)atoi(argv[3]));
	inet_pton(AF_INET6, "::1", &g_echo6.sin6_addr);

	t_send_return_value();
	t_source_address();
	t_datagram_boundaries();
	t_truncation();
	t_peek();
	t_zero_length();
	t_emsgsize();
	t_connect_semantics();
	t_mmsg();
	t_scatter_gather();
	t_ancillary();
	t_getsockname();
	t_ipv6();
	t_connected_peer_filter();
	t_dualstack_to_ipv4();
	t_unrepresentable();
	t_passthrough();
	t_fortified();
	t_non_udp_refused();
	t_argument_checks();
	t_syscall_routes();
	t_dprintf();
	t_pwritev2();
	t_underscored_aliases();
	t_unhookable_refused();
	t_cork_refused();

	TAP_DONE();
}

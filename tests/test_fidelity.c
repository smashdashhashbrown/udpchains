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
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>

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
	t_dualstack_to_ipv4();
	t_unrepresentable();
	t_passthrough();

	TAP_DONE();
}

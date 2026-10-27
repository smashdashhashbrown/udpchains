/* test_supervise_unit.c -- the supervisor's pure parts (D-52, D-53).
 *
 * The kernel floor is checked from the release string uname() gives, which
 * varies by distribution; this host's own kernel says nothing about the
 * others.  Which addresses are the system resolver is checked against a
 * resolv.conf of the test's own, rewritten as a VPN would. */
#include "tap.h"

#include <arpa/inet.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#include "supervise.h"
#include "svint.h"

static struct sockaddr_storage at(const char *ip, int port)
{
	struct sockaddr_storage ss;

	memset(&ss, 0, sizeof(ss));
	if (strchr(ip, ':') != NULL) {
		struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;

		a->sin6_family = AF_INET6;
		a->sin6_port = htons((uint16_t)port);
		inet_pton(AF_INET6, ip, &a->sin6_addr);
	} else {
		struct sockaddr_in *a = (struct sockaddr_in *)&ss;

		a->sin_family = AF_INET;
		a->sin_port = htons((uint16_t)port);
		inet_pton(AF_INET, ip, &a->sin_addr);
	}
	return ss;
}

static bool resolver(const char *ip, int port)
{
	struct sockaddr_storage ss = at(ip, port);

	return svdns_system_resolver((const struct sockaddr *)&ss);
}

/* Writes path anew, as a new file, as DHCP and VPN clients do. */
static void write_conf(const char *path, const char *text)
{
	char tmp[256];
	FILE *f;

	snprintf(tmp, sizeof(tmp), "%s.new", path);
	f = fopen(tmp, "w");
	if (f == NULL)
		return;
	fputs(text, f);
	fclose(f);
	rename(tmp, path);
}

static void system_resolver(void)
{
	char path[] = "/tmp/udpchains-resolv-XXXXXX";
	int fd = mkstemp(path);
	struct sockaddr_storage a, b;

	TAP_GROUP("D-52: which addresses are the system resolver");
	if (fd >= 0)
		close(fd);
	write_conf(path, "# a comment\nnameserver 10.1.2.3\nsearch example.org\n"
	                 "nameserver fe80::1%eth0\noptions edns0\n");
	svdns_set_path(path);
	TAP_OK(resolver("127.0.0.53", 53), "127.0.0.53, port 53: loopback");
	TAP_OK(resolver("127.0.0.1", 53), "127.0.0.1 too");
	TAP_OK(resolver("::1", 53), "::1 too");
	TAP_OK(resolver("::ffff:127.0.0.53", 53), "and loopback in IPv4-mapped form");
	TAP_OK(resolver("10.1.2.3", 53), "a nameserver in resolv.conf");
	TAP_OK(resolver("::ffff:10.1.2.3", 53), "in IPv4-mapped form too");
	TAP_OK(resolver("fe80::1", 53), "an IPv6 nameserver, its zone set aside");
	TAP_OK(!resolver("10.1.2.3", 5353), "but not another port of it");
	TAP_OK(!resolver("127.0.0.53", 5353), "nor of loopback");
	TAP_OK(!resolver("9.9.9.9", 53), "port 53 elsewhere is not the system resolver");
	write_conf(path, "nameserver 10.9.9.9\n");
	TAP_OK(resolver("10.9.9.9", 53), "a nameserver written there since is recognised");
	TAP_OK(!resolver("10.1.2.3", 53), "and one taken out is not");
	unlink(path);
	TAP_OK(!resolver("10.9.9.9", 53), "with no resolv.conf, only loopback is");
	TAP_OK(resolver("127.0.0.53", 53), "as it still is");
	svdns_set_path("/etc/resolv.conf");

	a = at("10.1.2.3", 53);
	b = at("::ffff:10.1.2.3", 53);
	TAP_OK(svdns_same((const struct sockaddr *)&a, (const struct sockaddr *)&b),
	       "an IPv4 address and its IPv4-mapped form are the same");
	b = at("10.1.2.3", 54);
	TAP_OK(!svdns_same((const struct sockaddr *)&a, (const struct sockaddr *)&b),
	       "a different port is not");
}

/* The daemon a Unix address names, its length the path's own (with or
 * without the terminating NUL) unless len is given. */
static const char *daemon_at(const char *path, int len)
{
	struct sockaddr_un un;

	memset(&un, 0, sizeof(un));
	un.sun_family = AF_UNIX;
	memcpy(un.sun_path, path, strlen(path));
	if (len < 0)
		len = (int)(offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1);
	return svdns_resolver_daemon(&un, (socklen_t)len);
}

static void resolver_daemons(void)
{
	struct sockaddr_un un;
	size_t base = offsetof(struct sockaddr_un, sun_path);
	const char *d;

	TAP_GROUP("D-55: which Unix sockets are a resolver daemon's");
	d = daemon_at("/run/systemd/resolve/io.systemd.Resolve", -1);
	TAP_OK(d != NULL && strstr(d, "systemd-resolved") != NULL,
	       "systemd-resolved's, for nss-resolve (%s)", d ? d : "none");
	d = daemon_at("/var/run/nscd/socket", -1);
	TAP_OK(d != NULL && strcmp(d, "nscd") == 0, "nscd's, as glibc names it, under /var/run");
	TAP_OK(daemon_at("/run/nscd/socket", -1) != NULL, "and under /run");
	TAP_OK(daemon_at("/run/avahi-daemon/socket", -1) != NULL &&
	               daemon_at("/var/run/avahi-daemon/socket", -1) != NULL,
	       "avahi's, for nss-mdns, under either");
	TAP_OK(daemon_at("/run/nscd/socket",
	                 (int)(base + strlen("/run/nscd/socket"))) != NULL,
	       "a path given without its NUL, its length exact");
	TAP_OK(daemon_at("/run/nscd/socket2", -1) == NULL, "not a longer path");
	TAP_OK(daemon_at("/run/nscd/socket", (int)(base + 5)) == NULL,
	       "nor one cut short by its length");
	TAP_OK(daemon_at("/run/systemd/resolve/io.systemd.Resolve.Monitor", -1) == NULL,
	       "nor resolved's monitor socket, which answers no lookups");
	TAP_OK(daemon_at("/tmp/socket", -1) == NULL && daemon_at("/var/run/dbus/system_bus_socket",
	                                                         -1) == NULL,
	       "nor any other, the system bus included");
	memset(&un, 0, sizeof(un));
	un.sun_family = AF_UNIX;
	memcpy(un.sun_path + 1, "/run/nscd/socket", 16);
	TAP_OK(svdns_resolver_daemon(&un, (socklen_t)(base + 17)) == NULL,
	       "nor an abstract address of the same name");
	TAP_OK(svdns_resolver_daemon(&un, (socklen_t)base) == NULL, "nor an unnamed one");
	un.sun_family = AF_INET;
	memcpy(un.sun_path, "/run/nscd/socket", 17);
	TAP_OK(svdns_resolver_daemon(&un, (socklen_t)sizeof(un)) == NULL,
	       "nor another family's address");
}

int main(void)
{
	system_resolver();
	resolver_daemons();

	TAP_GROUP("D-53: the kernel floor, from uname's release string");
	TAP_OK(udpc_kernel_at_least("5.14.0", 5, 14), "5.14.0 meets 5.14");
	TAP_OK(udpc_kernel_at_least("5.14.0-427.13.1.el9_4.x86_64", 5, 14),
	       "RHEL 9's 5.14 does");
	TAP_OK(udpc_kernel_at_least("5.15.0-91-generic", 5, 14), "Ubuntu 22.04's 5.15 does");
	TAP_OK(udpc_kernel_at_least("6.1.0-18-amd64", 5, 14), "a 6.x does");
	TAP_OK(udpc_kernel_at_least("7.0.0-38-generic", 5, 14), "a 7.x does");
	TAP_OK(!udpc_kernel_at_least("5.13.19", 5, 14), "5.13 does not");
	TAP_OK(!udpc_kernel_at_least("5.10.0-28-amd64", 5, 14), "Debian 11's 5.10 does not");
	TAP_OK(!udpc_kernel_at_least("4.19.0", 5, 14), "4.19 does not");
	TAP_OK(!udpc_kernel_at_least("5", 5, 14), "a release without a minor is refused");
	TAP_OK(!udpc_kernel_at_least("", 5, 14), "nor is an empty one");
	TAP_OK(!udpc_kernel_at_least("garbage", 5, 14), "nor one that is not a number");
	TAP_DONE();
}

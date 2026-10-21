/* test_config.c -- configuration (FR-C-02, FR-C-03, SEC-04, D-10, D-12).
 *
 * The load-bearing assertion is D-10 / FR-C-03: with no proxy configured, the
 * shim must refuse rather than fall back to something.  A built-in default
 * proxy would make FR-C-03 unfireable and reintroduce the silent-leak class of
 * failure at the configuration layer.
 */
#include "tap.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "addr.h"
#include "config.h"
#include "log.h"

static char g_tmpdir[] = "/tmp/udpchains-cfg-XXXXXX";

static const char *write_conf(const char *name, const char *contents, mode_t mode)
{
	static char path[512];
	FILE *f;

	snprintf(path, sizeof(path), "%s/%s", g_tmpdir, name);
	f = fopen(path, "w");
	if (f == NULL)
		return NULL;
	fputs(contents, f);
	fclose(f);
	chmod(path, mode);
	return path;
}

int main(void)
{
	struct udpc_config cfg, layer;
	const char *err = NULL;
	int line = 0;

	if (mkdtemp(g_tmpdir) == NULL) {
		fprintf(stderr, "cannot create a temporary directory\n");
		return 2;
	}

	TAP_GROUP("D-10: there is no built-in default proxy");
	{
		udpc_config_defaults(&cfg);
		TAP_OK(!cfg.proxy_set, "defaults leave the proxy unset");
		TAP_EQ_INT(cfg.max_datagram, UDPC_DEFAULT_MAX_DATAGRAM,
		           "but max_datagram defaults to 8192 (D-12)");
		TAP_EQ_INT(cfg.connect_timeout_ms, UDPC_DEFAULT_CONNECT_TIMEOUT_MS,
		           "and connect_timeout has a default");

		err = NULL;
		TAP_EQ_INT(udpc_config_finalize(&cfg, &err), -1,
		           "FR-C-03: finalising without a proxy FAILS");
		TAP_OK(err != NULL && strstr(err, "no proxy") != NULL,
		       "with a message naming the problem: %s", err ? err : "(none)");
	}

	TAP_GROUP("FR-C-03: unknown and malformed keys are errors, not warnings");
	{
		udpc_config_init(&layer);
		err = NULL;
		TAP_EQ_INT(udpc_config_set(&layer, "nonsense", "1", &err), -1,
		           "an unknown key is rejected");
		TAP_OK(err != NULL, "with a reason");

		err = NULL;
		TAP_EQ_INT(udpc_config_set(&layer, "max_datagram", "banana", &err), -1,
		           "a non-numeric max_datagram is rejected");
		err = NULL;
		TAP_EQ_INT(udpc_config_set(&layer, "max_datagram", "0", &err), -1,
		           "max_datagram of 0 is rejected");
		err = NULL;
		TAP_EQ_INT(udpc_config_set(&layer, "max_datagram", "70000", &err), -1,
		           "max_datagram beyond a UDP payload is rejected");
		err = NULL;
		TAP_EQ_INT(udpc_config_set(&layer, "strict_loopback", "maybe", &err),
		           -1, "a non-boolean strict_loopback is rejected");

		/* A proxychains.conf brought over by muscle memory should say
		 * something useful rather than "unknown key" (FR-C-04, D-08). */
		err = NULL;
		TAP_EQ_INT(udpc_config_set(&layer, "[ProxyList]", "", &err), -1,
		           "a [ProxyList] stanza is rejected");
		TAP_OK(err != NULL && strstr(err, "FR-C-04") != NULL,
		       "with a message pointing at the deferred requirement");
	}

	TAP_GROUP("valid values are accepted");
	{
		udpc_config_init(&layer);
		err = NULL;
		TAP_EQ_INT(udpc_config_set(&layer, "proxy", "127.0.0.1:1080", &err), 0,
		           "proxy is accepted");
		TAP_EQ_INT(udpc_config_set(&layer, "max_datagram", "4096", &err), 0,
		           "max_datagram is accepted");
		TAP_EQ_INT(udpc_config_set(&layer, "strict_loopback", "yes", &err), 0,
		           "strict_loopback accepts 'yes'");
		TAP_OK(layer.strict_loopback, "and sets it true");
		TAP_EQ_INT(udpc_config_set(&layer, "strict_loopback", "off", &err), 0,
		           "and accepts 'off'");
		TAP_OK(!layer.strict_loopback, "setting it false");
		TAP_EQ_INT(udpc_config_set(&layer, "connect_timeout", "2500", &err), 0,
		           "connect_timeout is accepted");
	}

	TAP_GROUP("FR-C-02: precedence -- a later layer wins, but only for what it set");
	{
		struct udpc_config base, over;

		udpc_config_defaults(&base);
		udpc_config_set(&base, "proxy", "10.0.0.1:1080", &err);
		udpc_config_set(&base, "max_datagram", "4096", &err);

		udpc_config_init(&over);
		udpc_config_set(&over, "proxy", "10.0.0.2:1080", &err);

		udpc_config_merge(&base, &over);

		TAP_EQ_STR(base.proxy_spec, "10.0.0.2:1080",
		           "the higher layer's proxy wins");
		TAP_EQ_INT(base.max_datagram, 4096,
		           "but max_datagram survives, because the higher layer "
		           "never set it");
	}

	TAP_GROUP("config files parse, and errors carry a line number");
	{
		const char *path;

		path = write_conf("good.conf",
		                  "# a comment\n"
		                  "; another comment\n"
		                  "\n"
		                  "proxy = 127.0.0.1:1080\n"
		                  "  max_datagram   =   2048  \n"
		                  "strict_loopback = true\n",
		                  0600);
		udpc_config_init(&layer);
		err = NULL;
		line = 0;
		TAP_EQ_INT(udpc_config_read_file(&layer, path, &err, &line), 0,
		           "a well-formed file parses");
		TAP_EQ_STR(layer.proxy_spec, "127.0.0.1:1080", "proxy is read");
		TAP_EQ_INT(layer.max_datagram, 2048,
		           "whitespace around key and value is trimmed");
		TAP_OK(layer.strict_loopback, "booleans are read");

		path = write_conf("bad.conf",
		                  "proxy = 127.0.0.1:1080\n"
		                  "this line has no equals sign\n",
		                  0600);
		udpc_config_init(&layer);
		err = NULL;
		line = 0;
		TAP_EQ_INT(udpc_config_read_file(&layer, path, &err, &line), -1,
		           "a malformed line fails the whole file");
		TAP_EQ_INT(line, 2, "and reports the offending line number");

		udpc_config_init(&layer);
		err = NULL;
		TAP_EQ_INT(udpc_config_read_file(&layer, "/nonexistent/udpchains.conf",
		                                 &err, &line),
		           -1, "a missing file is reported");
		TAP_EQ_STR(err, "no such file",
		           "distinguishably, so a default location may be absent");
	}

	TAP_GROUP("SEC-04: a group- or world-writable config file is called out");
	{
		const char *path = write_conf("loose.conf", "proxy = 127.0.0.1:1080\n",
		                              0666);
		udpc_config_init(&layer);
		err = NULL;
		line = 0;
		/* The warning goes to stderr; what is asserted here is that a
		 * loose file still parses rather than being silently ignored --
		 * the operator is told, and decides. */
		TAP_EQ_INT(udpc_config_read_file(&layer, path, &err, &line), 0,
		           "a world-writable file still parses (with a warning on "
		           "stderr)");
	}

	TAP_GROUP("finalisation resolves the proxy and classifies its location");
	{
		udpc_config_defaults(&cfg);
		udpc_config_set(&cfg, "proxy", "127.0.0.1:1080", &err);
		err = NULL;
		TAP_EQ_INT(udpc_config_finalize(&cfg, &err), 0,
		           "a configured proxy finalises");
		TAP_EQ_INT(cfg.proxy.ss_family, AF_INET, "resolved as AF_INET");
		TAP_EQ_INT(udpc_sa_port((const struct sockaddr *)&cfg.proxy), 1080,
		           "with the right port");
		TAP_OK(cfg.proxy_is_local,
		       "D-05 R2: a loopback proxy is recognised as local, so the "
		       "loopback guard stays quiet");

		udpc_config_defaults(&cfg);
		udpc_config_set(&cfg, "proxy", "192.0.2.99:1080", &err);
		err = NULL;
		TAP_EQ_INT(udpc_config_finalize(&cfg, &err), 0,
		           "a non-local proxy finalises");
		TAP_OK(!cfg.proxy_is_local,
		       "and is recognised as NOT local, so the loopback guard fires");

		udpc_config_defaults(&cfg);
		udpc_config_set(&cfg, "proxy", "no-such-host.invalid:1080", &err);
		err = NULL;
		TAP_EQ_INT(udpc_config_finalize(&cfg, &err), -1,
		           "an unresolvable proxy fails rather than being ignored");
	}

	TAP_GROUP("L5: password files, switches and long lines");
	{
		char pw[300], text[1200];
		const char *path;
		char *saved = getenv("UDPCHAINS_QUIET");

		saved = saved != NULL ? strdup(saved) : NULL;

		memset(pw, 'p', 256);
		pw[256] = '\0';
		path = write_conf("pw-256", pw, 0600);
		udpc_config_init(&layer);
		err = NULL;
		TAP_EQ_INT(udpc_config_set(&layer, "password_file", path, &err), -1,
		           "a 256-byte password file is an error, not a silent "
		           "truncation");

		memset(pw, 'p', 255);
		memcpy(pw + 255, "\r\n", 3);
		path = write_conf("pw-255-crlf", pw, 0600);
		udpc_config_init(&layer);
		TAP_EQ_INT(udpc_config_set(&layer, "password_file", path, &err), 0,
		           "255 bytes -- RFC 1929's limit -- ending in CR LF is "
		           "accepted");
		TAP_EQ_INT(strlen(layer.password), 255, "with the CR LF stripped");

		setenv("UDPCHAINS_QUIET", "0", 1);
		udpc_config_init(&layer);
		TAP_EQ_INT(udpc_config_from_env(&layer, &err), 0,
		           "UDPCHAINS_QUIET=0 parses");
		TAP_OK(layer.verbosity != UDPC_QUIET, "and does NOT turn quiet mode on");
		setenv("UDPCHAINS_QUIET", "yes", 1);
		udpc_config_init(&layer);
		udpc_config_from_env(&layer, &err);
		TAP_EQ_INT(layer.verbosity, UDPC_QUIET, "UDPCHAINS_QUIET=yes does");
		setenv("UDPCHAINS_QUIET", "maybe", 1);
		udpc_config_init(&layer);
		TAP_EQ_INT(udpc_config_from_env(&layer, &err), -1,
		           "a value that is not a boolean is an error");
		if (saved != NULL)
			setenv("UDPCHAINS_QUIET", saved, 1);
		else
			unsetenv("UDPCHAINS_QUIET");
		free(saved);

		/* Leading whitespace once hid a line's length from the check. */
		memset(text, ' ', 4);
		memset(text + 4, 'x', 1100);
		strcpy(text + 1104, "\n");
		path = write_conf("long-indented.conf", text, 0600);
		udpc_config_init(&layer);
		TAP_EQ_INT(udpc_config_read_file(&layer, path, &err, &(int){0}), -1,
		           "an over-long line is refused even when indented");

		/* A last line exactly filling the buffer, with no newline, is
		 * complete -- not too long. */
		memset(text, ' ', sizeof(text));
		memcpy(text, "proxy = 127.0.0.1:1080", 22);
		text[1023] = '\0';
		path = write_conf("exact-last-line.conf", text, 0600);
		udpc_config_init(&layer);
		TAP_EQ_INT(udpc_config_read_file(&layer, path, &err, &(int){0}), 0,
		           "a final 1023-byte line without a newline still parses");
	}

	TAP_GROUP("D4: comments are whole lines only");
	{
		const char *path;
		int at = 0;

		path = write_conf("inline.conf",
		                  "proxy = 127.0.0.1:1080\n"
		                  "username = alice\n"
		                  "password = s3cret # the old one\n",
		                  0600);
		udpc_config_init(&layer);
		err = NULL;
		TAP_EQ_INT(udpc_config_read_file(&layer, path, &err, &at), -1,
		           "an inline comment after a value is an error");
		TAP_EQ_INT(at, 3, "on the line that holds it");
		TAP_OK(err != NULL && strstr(err, "password_file") != NULL,
		       "and the message says where such a password belongs");

		path = write_conf("inline-tab.conf", "proxy = 127.0.0.1:1080\t#x\n",
		                  0600);
		udpc_config_init(&layer);
		TAP_EQ_INT(udpc_config_read_file(&layer, path, &err, &(int){0}), -1,
		           "after a tab too");

		path = write_conf("inline-empty.conf", "dns_search = # none\n", 0600);
		udpc_config_init(&layer);
		TAP_EQ_INT(udpc_config_read_file(&layer, path, &err, &(int){0}), -1,
		           "and when it opens the value");

		path = write_conf("hash-in-value.conf",
		                  "username = alice\npassword = abc#def\n", 0600);
		udpc_config_init(&layer);
		TAP_EQ_INT(udpc_config_read_file(&layer, path, &err, &(int){0}), 0,
		           "a '#' inside a value is not a comment");
		TAP_EQ_STR(layer.password, "abc#def", "and stays part of it");
	}

	TAP_GROUP("D-38: a chain of one is 0.1.0's configuration");
	{
		const char *path = write_conf("one.conf",
		                              "proxy = 127.0.0.1:1080\n"
		                              "username = alice\n"
		                              "password = apw\n",
		                              0600);

		udpc_config_init(&layer);
		TAP_EQ_INT(udpc_config_read_file(&layer, path, &err, &line), 0,
		           "a 0.1.0 file parses");
		TAP_EQ_INT(layer.nextra, 0, "as a chain of one");
		TAP_EQ_STR(layer.username, "alice", "with its credentials on hop 1");
	}

	TAP_GROUP("D-38: [hop] sections add hops in order");
	{
		char pwpath[600], conf[1400];
		const char *path, *pw;

		pw = write_conf("bob.pw", "bobpw\n", 0600);
		snprintf(pwpath, sizeof(pwpath), "%s", pw);
		snprintf(conf, sizeof(conf),
		         "proxy = 127.0.0.1:1080\n"
		         "username = alice\n"
		         "password = apw\n"
		         "\n"
		         "[hop]\n"
		         "proxy = 10.0.0.5:1081\n"
		         "username = bob\n"
		         "password_file = %s\n"
		         "\n"
		         "[hop]\n"
		         "proxy = internal.example:1082\n"
		         "username = carol\n"
		         "password = cpw\n",
		         pwpath);
		path = write_conf("chain.conf", conf, 0600);

		udpc_config_init(&layer);
		err = NULL;
		TAP_EQ_INT(udpc_config_read_file(&layer, path, &err, &line), 0,
		           "a file with two [hop] sections parses (%s)", err ? err : "ok");
		TAP_EQ_INT(layer.nextra, 2, "into a chain of three");
		TAP_EQ_STR(layer.proxy_spec, "127.0.0.1:1080", "hop 1 is the top-level proxy");
		TAP_EQ_STR(layer.username, "alice", "with the top-level credentials");
		TAP_EQ_STR(layer.hops[0].spec, "10.0.0.5:1081", "hop 2 is the first [hop]");
		TAP_EQ_STR(layer.hops[0].username, "bob", "with its own username");
		TAP_EQ_STR(layer.hops[0].password, "bobpw", "and the password from its file");
		TAP_OK(layer.hops[0].password_file[0] == '/',
		       "remembered by absolute path (D-25)");
		TAP_EQ_STR(layer.hops[1].spec, "internal.example:1082",
		           "hop 3 is kept as written");
		TAP_EQ_STR(layer.hops[1].password, "cpw", "an inline hop password is read");
		TAP_OK(layer.hops[1].password_config[0] == '/',
		       "and is passed on by naming the file (D-25)");
		TAP_OK(layer.password_config[0] == '/',
		       "as hop 1's inline password is");
	}

	TAP_GROUP("D-38: malformed chains are errors, with a line number");
	{
		static const struct {
			const char *name, *text, *needle;
			int line;
		} bad[] = {
			{ "nofirst.conf", "[hop]\nproxy = 10.0.0.5:1081\n", "top-level proxy", 1 },
			{ "noproxy.conf", "proxy = 127.0.0.1:1080\n[hop]\nusername = bob\n",
			  "without a proxy", 2 },
			{ "badkey.conf",
			  "proxy = 127.0.0.1:1080\n[hop]\nproxy = 10.0.0.5:1081\nmax_datagram = 100\n",
			  "[hop] section", 4 },
			{ "section.conf", "proxy = 127.0.0.1:1080\n[hops]\n", "[hop]", 2 },
		};
		size_t i;

		for (i = 0; i < sizeof(bad) / sizeof(*bad); i++) {
			const char *path = write_conf(bad[i].name, bad[i].text, 0600);
			int at = 0;

			udpc_config_init(&layer);
			err = NULL;
			TAP_EQ_INT(udpc_config_read_file(&layer, path, &err, &at), -1,
			           "%s is rejected", bad[i].name);
			TAP_OK(err != NULL && strstr(err, bad[i].needle) != NULL,
			       "saying '%s' (%s)", bad[i].needle, err ? err : "no message");
			TAP_EQ_INT(at, bad[i].line, "on line %d", bad[i].line);
		}
	}

	TAP_GROUP("D-42: a chain has at most 8 hops");
	{
		char conf[2048];
		const char *path;
		int n, at = 0;
		size_t off;

		off = (size_t)snprintf(conf, sizeof(conf), "proxy = 127.0.0.1:1080\n");
		for (n = 2; n <= 8; n++)
			off += (size_t)snprintf(conf + off, sizeof(conf) - off,
			                        "[hop]\nproxy = 10.0.0.%d:1080\n", n);
		path = write_conf("eight.conf", conf, 0600);
		udpc_config_init(&layer);
		TAP_EQ_INT(udpc_config_read_file(&layer, path, &err, &at), 0, "8 hops parse");
		TAP_EQ_INT(layer.nextra, 7, "as hop 1 and seven more");

		snprintf(conf + off, sizeof(conf) - off, "[hop]\nproxy = 10.0.0.9:1080\n");
		path = write_conf("nine.conf", conf, 0600);
		udpc_config_init(&layer);
		err = NULL;
		TAP_EQ_INT(udpc_config_read_file(&layer, path, &err, &at), -1,
		           "a ninth is rejected");
		TAP_OK(err != NULL && strstr(err, "8") != NULL, "naming the limit (%s)",
		       err ? err : "no message");
		err = NULL;
		udpc_config_init(&layer);
		udpc_config_set(&layer, "proxy", "127.0.0.1:1080", &err);
		for (n = 2; n <= 8; n++)
			udpc_config_append_hop(&layer, "10.0.0.2:1080", &err);
		TAP_EQ_INT(udpc_config_append_hop(&layer, "10.0.0.2:1080", &err), -1,
		           "and so is a ninth -p");
	}

	TAP_GROUP("D-38: the environment takes a list, and per-hop credentials");
	{
		char pwpath[600];

		snprintf(pwpath, sizeof(pwpath), "%s/bob.pw", g_tmpdir);
		setenv("UDPCHAINS_PROXY", "127.0.0.1:1080,10.0.0.5:1081,[fd00::9]:1082", 1);
		setenv("UDPCHAINS_USERNAME_2", "bob", 1);
		setenv("UDPCHAINS_PASSWORD_FILE_2", pwpath, 1);
		setenv("UDPCHAINS_USERNAME_3", "carol", 1);
		udpc_config_init(&layer);
		err = NULL;
		TAP_EQ_INT(udpc_config_from_env(&layer, &err), 0,
		           "a list in UDPCHAINS_PROXY is accepted (%s)", err ? err : "ok");
		TAP_EQ_STR(layer.proxy_spec, "127.0.0.1:1080", "its first entry is hop 1");
		TAP_EQ_INT(layer.nextra, 2, "and the rest follow");
		TAP_EQ_STR(layer.hops[1].spec, "[fd00::9]:1082", "an IPv6 hop keeps its brackets");
		TAP_EQ_STR(layer.hops[0].username, "bob", "UDPCHAINS_USERNAME_2 is hop 2's");
		TAP_EQ_STR(layer.hops[0].password, "bobpw", "and so is its password file");
		TAP_EQ_STR(layer.hops[1].username, "carol", "UDPCHAINS_USERNAME_3 is hop 3's");

		setenv("UDPCHAINS_PROXY", "127.0.0.1:1080,,10.0.0.5:1081", 1);
		udpc_config_init(&layer);
		err = NULL;
		TAP_EQ_INT(udpc_config_from_env(&layer, &err), -1, "an empty entry is rejected");
		setenv("UDPCHAINS_PROXY", "127.0.0.1:1080,", 1);
		udpc_config_init(&layer);
		TAP_EQ_INT(udpc_config_from_env(&layer, &err), -1, "so is a trailing comma");
		unsetenv("UDPCHAINS_PROXY");
		unsetenv("UDPCHAINS_USERNAME_2");
		unsetenv("UDPCHAINS_PASSWORD_FILE_2");
		unsetenv("UDPCHAINS_USERNAME_3");
	}

	TAP_GROUP("D-38: precedence -- the chain comes whole from one layer");
	{
		const char *path = NULL;
		struct udpc_config base, over;
		char p[600];

		snprintf(p, sizeof(p), "%s/chain.conf", g_tmpdir);
		path = p;
		udpc_config_defaults(&base);
		udpc_config_init(&layer);
		udpc_config_read_file(&layer, path, &err, &line);
		udpc_config_merge(&base, &layer);
		TAP_EQ_INT(base.nextra, 2, "a file's chain of three is merged");

		udpc_config_init(&over);
		udpc_config_set(&over, "proxy", "10.9.9.9:1080", &err);
		cfg = base;
		udpc_config_merge(&cfg, &over);
		TAP_EQ_INT(cfg.nextra, 0, "a higher layer naming one proxy replaces the chain");
		TAP_EQ_STR(cfg.proxy_spec, "10.9.9.9:1080", "with its own hop 1");

		udpc_config_init(&over);
		setenv("UDPCHAINS_USERNAME_2", "dave", 1);
		udpc_config_from_env(&over, &err);
		unsetenv("UDPCHAINS_USERNAME_2");
		cfg = base;
		udpc_config_merge(&cfg, &over);
		TAP_EQ_INT(cfg.nextra, 2, "a layer setting only hop 2's username keeps the chain");
		TAP_EQ_STR(cfg.hops[0].username, "dave", "and replaces that username");
		TAP_EQ_STR(cfg.hops[0].password, "bobpw", "but not the password it did not set");
	}

	TAP_GROUP("D-39: later hops are checked, never resolved");
	{
		char host[256];
		uint16_t port = 0;

		TAP_EQ_INT(udpc_addr_split("[fd00::9]:1082", 1080, host, sizeof(host), &port,
		                           &err), 0, "[fd00::9]:1082 splits");
		TAP_EQ_STR(host, "fd00::9", "into its host");
		TAP_EQ_INT(port, 1082, "and port");
		TAP_EQ_INT(udpc_addr_split("name.example", 1080, host, sizeof(host), &port,
		                           &err), 0, "a bare name splits");
		TAP_EQ_INT(port, 1080, "with the default port");
		TAP_EQ_INT(udpc_addr_split("x:99999", 1080, host, sizeof(host), &port, &err),
		           -1, "an out-of-range port does not");

		udpc_config_defaults(&cfg);
		udpc_config_set(&cfg, "proxy", "127.0.0.1:1080", &err);
		udpc_config_append_hop(&cfg, "no-such-host.invalid:1080", &err);
		err = NULL;
		TAP_EQ_INT(udpc_config_finalize(&cfg, &err), 0,
		           "a later hop that does not resolve here is accepted (%s)",
		           err ? err : "ok");

		udpc_config_defaults(&cfg);
		udpc_config_set(&cfg, "proxy", "127.0.0.1:1080", &err);
		udpc_config_append_hop(&cfg, "10.0.0.5:99999", &err);
		err = NULL;
		TAP_EQ_INT(udpc_config_finalize(&cfg, &err), -1, "a malformed one is not");
		TAP_OK(err != NULL && strstr(err, "hop 2") != NULL, "and the error names it (%s)",
		       err ? err : "no message");
	}

	TAP_GROUP("D-38: the handoff to the shim round-trips the chain");
	{
		char p[600];
		const char *v;
		int n;

		snprintf(p, sizeof(p), "%s/chain.conf", g_tmpdir);
		udpc_config_defaults(&cfg);
		udpc_config_init(&layer);
		udpc_config_read_file(&layer, p, &err, &line);
		udpc_config_merge(&cfg, &layer);
		err = NULL;
		TAP_EQ_INT(udpc_config_finalize(&cfg, &err), 0, "the file's chain finalises");
		TAP_EQ_INT(udpc_config_export(&cfg), 0, "and exports");
		v = getenv("UDPCHAINS_PROXY");
		TAP_EQ_STR(v ? v : "", "127.0.0.1:1080,10.0.0.5:1081,internal.example:1082",
		           "UDPCHAINS_PROXY lists the hops, later ones as written");
		v = getenv("UDPCHAINS_USERNAME_2");
		TAP_EQ_STR(v ? v : "", "bob", "hop 2's username is exported");
		v = getenv("UDPCHAINS_PASSWORD_FILE_2");
		TAP_EQ_STR(v ? v : "", cfg.hops[0].password_file, "and where its password is");
		TAP_OK(getenv("UDPCHAINS_PASSWORD_2") == NULL, "never the password (D-25)");
		v = getenv("UDPCHAINS_PASSWORD_CONFIG_3");
		TAP_EQ_STR(v ? v : "", cfg.hops[1].password_config,
		           "hop 3's inline password is passed on by naming the file");

		udpc_config_init(&layer);
		err = NULL;
		TAP_EQ_INT(udpc_config_from_env(&layer, &err), 0, "the shim reads it back (%s)",
		           err ? err : "ok");
		TAP_EQ_INT(layer.nextra, 2, "as a chain of three");
		TAP_EQ_STR(layer.hops[0].password, "bobpw", "with hop 2's password from its file");
		TAP_EQ_STR(layer.hops[1].password, "cpw", "and hop 3's from the config file");
		TAP_EQ_STR(layer.password, "apw", "and hop 1's");

		/* FR-CH-01: a chain of one leaves no trace of the longer one. */
		udpc_config_defaults(&cfg);
		udpc_config_set(&cfg, "proxy", "127.0.0.1:1080", &err);
		udpc_config_finalize(&cfg, &err);
		TAP_EQ_INT(udpc_config_export(&cfg), 0, "a chain of one exports");
		v = getenv("UDPCHAINS_PROXY");
		TAP_EQ_STR(v ? v : "", "127.0.0.1:1080", "a single address, as 0.1.0 did");
		for (n = 2; n <= 8; n++) {
			char name[64];
			bool any;

			snprintf(name, sizeof(name), "UDPCHAINS_USERNAME_%d", n);
			any = getenv(name) != NULL;
			snprintf(name, sizeof(name), "UDPCHAINS_PASSWORD_FILE_%d", n);
			any = any || getenv(name) != NULL;
			snprintf(name, sizeof(name), "UDPCHAINS_PASSWORD_CONFIG_%d", n);
			any = any || getenv(name) != NULL;
			if (any)
				break;
		}
		TAP_EQ_INT(n, 9, "and no per-hop variable is left behind");
	}

	{
		char cmd[600];
		snprintf(cmd, sizeof(cmd), "rm -rf %s", g_tmpdir);
		if (system(cmd) != 0)
			fprintf(stderr, "# warning: could not remove %s\n", g_tmpdir);
	}

	TAP_DONE();
}

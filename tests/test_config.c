/* test_config.c -- configuration (FR-C-02, FR-C-03, SEC-04, D-10, D-12).
 *
 * The load-bearing assertion is D-10 / FR-C-03: with no proxy configured, the
 * shim must refuse rather than fall back to something.  A built-in default
 * proxy would make FR-C-03 unfireable and reintroduce the silent-leak class of
 * failure at the configuration layer.
 */
#include "tap.h"

#include <errno.h>
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

	{
		char cmd[600];
		snprintf(cmd, sizeof(cmd), "rm -rf %s", g_tmpdir);
		if (system(cmd) != 0)
			fprintf(stderr, "# warning: could not remove %s\n", g_tmpdir);
	}

	TAP_DONE();
}

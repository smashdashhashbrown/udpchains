#!/bin/sh
# test_auth.sh -- FR-P-09, RFC 1929 username/password authentication.
#
# The unit tests assert the request's byte layout against the RFC.  This
# asserts the EXCHANGE: that a proxy demanding 0x02 is satisfied, that wrong
# credentials fail, and -- the part that matters for SEC-01 -- that a failed
# authentication means no datagram is delivered rather than one going direct.
#
# The fixture is strict on purpose: it rejects a sub-negotiation whose version
# byte is not 0x01.  A fixture that forgives that is how D-14 survived 108 green
# cells.
#
# usage: test_auth.sh <socks5d> <udpecho> <wrapper>
set -eu

SOCKS5D="$1"
UDPECHO="$2"
# Absolute: one case below runs the wrapper from another directory.
WRAPPER="$(cd "$(dirname "$3")" && pwd)/$(basename "$3")"

TMP=$(mktemp -d)
cleanup() {
	# Fixtures are started inside $(...), a subshell, where a PID stored in a
	# variable would never reach this shell.  Each one's PID goes to a file.
	if [ -f "$TMP/pids" ]; then
		for p in $(cat "$TMP/pids"); do kill "$p" 2>/dev/null || true; done
	fi
	rm -rf "$TMP"
}
trap cleanup EXIT

fail=0
n=0

ok() { n=$((n + 1)); echo "ok $n - $1"; }
notok() { n=$((n + 1)); echo "not ok $n - $1"; fail=1; }

start() {
	name=$1; shift
	"$@" > "$TMP/$name.out" 2>&1 &
	echo $! >> "$TMP/pids"
	i=0
	while [ $i -lt 200 ]; do
		port=$(awk '/^PORT/{print $2; exit}' "$TMP/$name.out" 2>/dev/null || true)
		[ -n "${port:-}" ] && { echo "$port"; return 0; }
		i=$((i + 1))
		sleep 0.05
	done
	echo "FATAL: $name did not start" >&2
	exit 1
}

ECHO_PORT=$(start echo "$UDPECHO" --port 0 --quiet)
# NOT --quiet: the proxy's own log is the independent evidence that the
# exchange happened, rather than the shim merely claiming it did.
PROXY=$(start proxy "$SOCKS5D" --port 0 --auth-required \
	--auth-user alice --auth-pass s3cret)

printf 's3cret' > "$TMP/pass"
chmod 600 "$TMP/pass"

echo "# a proxy demanding RFC 1929 authentication"

# --- correct credentials -----------------------------------------------------
out=$(echo "auth-round-trip" | UDPCHAINS_USERNAME=alice \
	UDPCHAINS_PASSWORD_FILE="$TMP/pass" \
	timeout 15 "$WRAPPER" -p "127.0.0.1:$PROXY" \
	nc -u -w 3 127.0.0.1 "$ECHO_PORT" 2>&1) || true

if printf '%s' "$out" | grep -q auth-round-trip; then
	ok "correct credentials authenticate and the datagram round-trips"
else
	notok "correct credentials failed: $out"
fi

if grep -q "user 'alice' accepted" "$TMP/proxy.out"; then
	ok "the proxy logged the authentication, so it really happened"
else
	notok "the proxy did not log a successful authentication"
fi

# NFR-05: the password must never be logged, by either side.
if grep -q s3cret "$TMP/proxy.out" || printf '%s' "$out" | grep -q s3cret; then
	notok "the password appeared in a log -- NFR-05"
else
	ok "the password appears in no log, on either side"
fi

# --- wrong password ----------------------------------------------------------
printf 'wrongpass' > "$TMP/badpass"
chmod 600 "$TMP/badpass"
out=$(echo "must-not-arrive" | UDPCHAINS_USERNAME=alice \
	UDPCHAINS_PASSWORD_FILE="$TMP/badpass" \
	timeout 15 "$WRAPPER" -v -p "127.0.0.1:$PROXY" \
	nc -u -w 3 127.0.0.1 "$ECHO_PORT" 2>&1) || true

if printf '%s' "$out" | grep -q must-not-arrive; then
	notok "a wrong password still delivered the datagram"
else
	ok "a wrong password delivers nothing"
fi

if printf '%s' "$out" | grep -qi "rejected the supplied credentials"; then
	ok "and the failure names the reason rather than a generic error"
else
	notok "no credential-rejection diagnostic: $out"
fi

# --- no credentials at all ---------------------------------------------------
out=$(echo "must-not-arrive" | timeout 15 "$WRAPPER" -v \
	-p "127.0.0.1:$PROXY" nc -u -w 3 127.0.0.1 "$ECHO_PORT" 2>&1) || true

if printf '%s' "$out" | grep -q must-not-arrive; then
	notok "a proxy demanding auth still accepted an unauthenticated send"
else
	ok "no credentials against an auth-demanding proxy delivers nothing"
fi

if printf '%s' "$out" | grep -qi "no credentials are configured"; then
	ok "and the diagnostic says what to configure"
else
	notok "no actionable diagnostic: $out"
fi

# --- credentials against a proxy that does NOT want them ---------------------
PROXY2=$(start proxy2 "$SOCKS5D" --port 0 --quiet)
out=$(echo "open-proxy-ok" | UDPCHAINS_USERNAME=alice \
	UDPCHAINS_PASSWORD_FILE="$TMP/pass" \
	timeout 15 "$WRAPPER" -p "127.0.0.1:$PROXY2" \
	nc -u -w 3 127.0.0.1 "$ECHO_PORT" 2>&1) || true

if printf '%s' "$out" | grep -q open-proxy-ok; then
	ok "configured credentials do not break a proxy that wants none"
else
	notok "credentials broke an unauthenticated proxy: $out"
fi

# --- D-25: the password is never put in the target's environment ------------
# The wrapper passes WHERE the password is, and each shim reads it from there.
# Checked by running env(1) as the target, which prints exactly what the target
# -- and anything it starts -- inherits.
envout=$(UDPCHAINS_USERNAME=alice UDPCHAINS_PASSWORD_FILE="$TMP/pass" \
	"$WRAPPER" -q -p "127.0.0.1:$PROXY" env 2>&1) || true
if printf '%s' "$envout" | grep -q s3cret; then
	notok "D-25: the password from a password file is in the target's environment"
else
	ok "D-25: a password file's contents are not in the target's environment"
fi
if printf '%s' "$envout" | grep -q "^UDPCHAINS_PASSWORD_FILE=$TMP/pass\$"; then
	ok "the target is told where the file is instead"
else
	notok "UDPCHAINS_PASSWORD_FILE was not passed on: $envout"
fi

# A relative path is passed on as an absolute one, so a target that changes
# directory before its first datagram still finds the file.
out=$(cd "$TMP" && echo "relative-path-ok" | UDPCHAINS_USERNAME=alice \
	UDPCHAINS_PASSWORD_FILE=pass \
	timeout 15 "$WRAPPER" -p "127.0.0.1:$PROXY" \
	sh -c "cd / && exec nc -u -w 3 127.0.0.1 $ECHO_PORT" 2>&1) || true
if printf '%s' "$out" | grep -q relative-path-ok; then
	ok "a relative password file still works after the target changes directory"
else
	notok "a relative password file broke after a chdir: $out"
fi

# A password written inline in a config file.
printf 'username = alice\npassword = s3cret\n' > "$TMP/auth.conf"
chmod 600 "$TMP/auth.conf"
envout=$("$WRAPPER" -q -f "$TMP/auth.conf" -p "127.0.0.1:$PROXY" env 2>&1) || true
if printf '%s' "$envout" | grep -q s3cret; then
	notok "D-25: an inline config password is in the target's environment"
else
	ok "D-25: an inline config password is not in the target's environment"
fi
out=$(echo "inline-config-ok" | timeout 15 "$WRAPPER" -f "$TMP/auth.conf" \
	-p "127.0.0.1:$PROXY" nc -u -w 3 127.0.0.1 "$ECHO_PORT" 2>&1) || true
if printf '%s' "$out" | grep -q inline-config-ok; then
	ok "and it still authenticates, read by the shim from the config file"
else
	notok "an inline config password failed to authenticate: $out"
fi

# --- L5 / D-33: permission warnings, once each --------------------------------
# With warnings on, which run.sh turns off.  The wrapper checks each file's
# permissions; the processes under it no longer repeat the warning.
printf 's3cret' > "$TMP/loosepass"
chmod 644 "$TMP/loosepass"
out=$(env -u UDPCHAINS_QUIET UDPCHAINS_USERNAME=alice \
	UDPCHAINS_PASSWORD_FILE="$TMP/loosepass" \
	"$WRAPPER" -p "127.0.0.1:$PROXY" /bin/true 2>&1) || true
c=$(printf '%s\n' "$out" | grep -c 'group- or world-accessible' || true)
if [ "$c" = "1" ]; then
	ok "a readable password file is warned about exactly once"
else
	notok "a readable password file was warned about $c times"
fi

chmod 644 "$TMP/auth.conf"
out=$(env -u UDPCHAINS_QUIET "$WRAPPER" -f "$TMP/auth.conf" \
	-p "127.0.0.1:$PROXY" /bin/true 2>&1) || true
if printf '%s' "$out" | grep -q 'holds a password and is readable'; then
	ok "a config file holding a password is called out when others can read it"
else
	notok "no warning for a readable config file holding a password: $out"
fi

# --- FR-CH-14: a proxychains.conf, as it is (D-47) ----------------------------
# An open hop 1, then the proxy demanding a login as hop 2, with the login
# inline on its [ProxyList] line, as proxychains writes it.  The directives
# udpchains does not apply are warned about by the wrapper, once each.
cat > "$TMP/proxychains.conf" <<PC
# proxychains.conf
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000
localnet 127.0.0.0/255.0.0.0

[ProxyList]
socks5	127.0.0.1	$PROXY2
socks5	127.0.0.1	$PROXY	alice	s3cret
PC
chmod 600 "$TMP/proxychains.conf"
before=$(grep -c "user 'alice' accepted" "$TMP/proxy.out" || true)
out=$(echo "proxychains-conf-ok" | env -u UDPCHAINS_PROXY -u UDPCHAINS_QUIET \
	timeout 15 "$WRAPPER" -f "$TMP/proxychains.conf" \
	nc -u -w 3 127.0.0.1 "$ECHO_PORT" 2>&1) || true
if printf '%s' "$out" | grep -q proxychains-conf-ok; then
	ok "FR-CH-14: a proxychains.conf's chain carries the datagram"
else
	notok "FR-CH-14: a proxychains.conf's chain failed: $out"
fi
after=$(grep -c "user 'alice' accepted" "$TMP/proxy.out" || true)
if [ "$after" -gt "$before" ]; then
	ok "hop 2 authenticated with the login from its [ProxyList] line"
else
	notok "hop 2 logged no authentication"
fi
c=$(printf '%s\n' "$out" | grep -c "proxychains' .* is not applied" || true)
if [ "$c" = "3" ]; then
	ok "proxy_dns, tcp_read_time_out and localnet are each warned about once"
else
	notok "$c warnings about proxychains directives, not 3: $out"
fi
envout=$(env -u UDPCHAINS_PROXY "$WRAPPER" -q -f "$TMP/proxychains.conf" env 2>&1) || true
if printf '%s' "$envout" | grep -q s3cret; then
	notok "D-25: a [ProxyList] password is in the target's environment"
elif printf '%s' "$envout" | grep -q "^UDPCHAINS_PASSWORD_CONFIG_2=$TMP/proxychains.conf\$"; then
	ok "D-25: hop 2's password is passed on by naming the file"
else
	notok "UDPCHAINS_PASSWORD_CONFIG_2 was not passed on: $envout"
fi

printf 'dynamic_chain\n[ProxyList]\nsocks5 127.0.0.1 %s\n' "$PROXY2" \
	> "$TMP/dynamic.conf"
out=$(env -u UDPCHAINS_PROXY "$WRAPPER" -f "$TMP/dynamic.conf" \
	/bin/echo TARGET-RAN 2>&1) || true
if printf '%s' "$out" | grep -q TARGET-RAN; then
	notok "a dynamic_chain file ran the program"
elif printf '%s' "$out" | grep -q "dynamic.conf:1: chains are strict"; then
	ok "a dynamic_chain file is refused, naming the line, and nothing runs"
else
	notok "a dynamic_chain file was refused without the reason: $out"
fi

echo "1..$n"
[ "$fail" -eq 0 ] || exit 1

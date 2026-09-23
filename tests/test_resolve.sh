#!/bin/sh
# test_resolve.sh -- D-22, name resolution through the proxy.
#
# Runs build/test_resolve under the shim in each of its modes, against a dnsd
# fixture reached only through the fixture proxy.  The TAP output is the shim's
# own account; the checks here are the independent ones:
#
#   - the dnsd log, which counts exactly what reached the resolver, and over
#     which transport;
#   - strace, when installed, which shows whether the test process ever
#     addressed a resolver itself.  It must not: every query leaves inside a
#     SOCKS datagram to the relay, or through a SOCKS CONNECT tunnel.
#
# usage: test_resolve.sh <socks5d> <dnsd> <wrapper> <test_resolve>
set -u

SOCKS5D="$1"
DNSD="$2"
WRAPPER="$3"
PROBE="$4"

TMP=$(mktemp -d)
PIDS=""
cleanup() {
	for p in $PIDS; do kill "$p" 2>/dev/null || true; done
	rm -rf "$TMP"
}
trap cleanup EXIT

fail=0
n=0
ok() { n=$((n + 1)); echo "ok $n - $1"; }
notok() { n=$((n + 1)); echo "not ok $n - $1"; fail=1; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else notok "$1 (got $2, want $3)"; fi; }

start() {
	name=$1; shift
	"$@" > "$TMP/$name.out" 2> "$TMP/$name.err" &
	PIDS="$PIDS $!"
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

# NOT --quiet: dnsd's query log is the evidence.
DNS=$(start dnsd "$DNSD" --port 0)
PROXY=$(start proxy "$SOCKS5D" --port 0 --quiet)
NOCONNECT=$(start noconnect "$SOCKS5D" --port 0 --quiet --no-connect)

queries() { grep -c "^QUERY $1" "$TMP/dnsd.err" 2>/dev/null || true; }

cat > "$TMP/hosts" <<EOF
127.0.0.1	localhost
203.0.113.5	hostsonly.test
EOF

# Runs the probe in one mode under the shim.  Extra arguments are env settings.
probe() {
	mode=$1; proxy=$2; shift 2
	env -u UDPCHAINS_DNS "$@" UDPCHAINS_HOSTS_FILE="$TMP/hosts" \
		UDPCHAINS_DNS_SEARCH=search.test UDPCHAINS_DNS_TIMEOUT=2000 \
		timeout 120 "$WRAPPER" -p "$proxy" "$PROBE" "$mode" \
		> "$TMP/$mode.tap" 2>&1
	rc=$?
	sed 's/^/#   /' "$TMP/$mode.tap"
	return $rc
}

echo "# main: every entry point, through the proxy"
if probe main "127.0.0.1:$PROXY" UDPCHAINS_DNS="127.0.0.1:$DNS"; then
	ok "test_resolve main passes"
else
	notok "test_resolve main"
fi
UDP_MAIN=$(queries udp)
TCP_MAIN=$(queries tcp)
[ "$UDP_MAIN" -gt 0 ] && ok "dnsd answered $UDP_MAIN UDP queries, all via the relay" \
	|| notok "dnsd saw no UDP queries: the lookups did not take the proxy"
[ "$TCP_MAIN" -gt 0 ] && ok "dnsd answered $TCP_MAIN TCP queries, via SOCKS CONNECT" \
	|| notok "dnsd saw no TCP query: the truncation fallback did not run"

echo "# nodns: no resolver configured"
before=$(queries "")
if probe nodns "127.0.0.1:$PROXY"; then ok "test_resolve nodns passes"; else notok "test_resolve nodns"; fi
check "no query reached any resolver" "$(queries "")" "$before"

echo "# down: the proxy is unreachable"
before=$(queries "")
if probe down "127.0.0.1:9" UDPCHAINS_DNS="127.0.0.1:$DNS"; then ok "test_resolve down passes"; else notok "test_resolve down"; fi
check "no query reached the resolver" "$(queries "")" "$before"

echo "# noconnect: the proxy refuses CONNECT"
before=$(queries tcp)
if probe noconnect "127.0.0.1:$NOCONNECT" UDPCHAINS_DNS="127.0.0.1:$DNS"; then
	ok "test_resolve noconnect passes"
else
	notok "test_resolve noconnect"
fi
check "no TCP query reached the resolver" "$(queries tcp)" "$before"

# strace sees every connect/send the probe makes.  None may name the resolver's
# port, or port 53: a query addressed to a resolver directly is a leak whatever
# answers it.
if command -v strace > /dev/null 2>&1; then
	for m in main down; do
		if [ $m = main ]; then p="127.0.0.1:$PROXY"; else p="127.0.0.1:9"; fi
		env -u UDPCHAINS_DNS UDPCHAINS_DNS="127.0.0.1:$DNS" \
			UDPCHAINS_HOSTS_FILE="$TMP/hosts" UDPCHAINS_DNS_SEARCH=search.test \
			UDPCHAINS_DNS_TIMEOUT=2000 \
			timeout 180 strace -f -qq -o "$TMP/strace.$m" \
			-e trace=connect,sendto,sendmsg,sendmmsg \
			"$WRAPPER" -p "$p" "$PROBE" $m > /dev/null 2>&1
		direct=$(grep -cE "htons\((53|$DNS)\)" "$TMP/strace.$m" || true)
		check "strace ($m): the process never addressed a resolver directly" \
			"$direct" "0"
	done
else
	echo "# SKIP strace checks -- strace not installed"
fi

echo "1..$n"
exit $fail

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
check() { if [ "$2" = "$3" ]; then ok "$1"; else notok "$1 (got $2, want $3)"; fi; }

start() {
	name=$1; shift
	"$@" > "$TMP/$name.out" 2> "$TMP/$name.err" &
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

# NOT --quiet: dnsd's query log is the evidence.
DNS=$(start dnsd "$DNSD" --port 0)
PROXY=$(start proxy "$SOCKS5D" --port 0 --quiet)
PROXY2=$(start proxy2 "$SOCKS5D" --port 0 --quiet)
NOCONNECT=$(start noconnect "$SOCKS5D" --port 0 --quiet --no-connect)

queries() { grep -c "^QUERY $1" "$TMP/dnsd.err" 2>/dev/null || true; }

cat > "$TMP/hosts" <<EOF
127.0.0.1	localhost
203.0.113.5	hostsonly.test
EOF

# The wrapper's -p arguments for a proxy, or a comma-separated chain of them.
popts() { echo "$1" | sed 's/^/-p /; s/,/ -p /g'; }

# Runs the probe in one mode under the shim.  proxy may be a chain, as
# host:port,host:port.  Extra arguments are env settings.
probe() {
	mode=$1; proxy=$2; shift 2
	# shellcheck disable=SC2046 # popts is split into words on purpose
	env -u UDPCHAINS_DNS "$@" UDPCHAINS_HOSTS_FILE="$TMP/hosts" \
		UDPCHAINS_DNS_SEARCH=search.test UDPCHAINS_DNS_TIMEOUT=2000 \
		timeout 120 "$WRAPPER" $(popts "$proxy") "$PROBE" "$mode" \
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

# --- FR-CH-11: lookups through a chain ----------------------------------------
CHAIN="127.0.0.1:$PROXY,127.0.0.1:$PROXY2"

echo "# chain main: every entry point, through 2 hops"
udp_before=$(queries udp)
tcp_before=$(queries tcp)
if probe main "$CHAIN" UDPCHAINS_DNS="127.0.0.1:$DNS"; then
	ok "test_resolve main passes through 2 hops"
else
	notok "test_resolve main through 2 hops"
fi
[ "$(queries udp)" -gt "$udp_before" ] && ok "dnsd answered UDP queries through the chain" \
	|| notok "dnsd saw no UDP queries through the chain"
[ "$(queries tcp)" -gt "$tcp_before" ] && ok "dnsd answered TCP queries through a chained CONNECT" \
	|| notok "dnsd saw no TCP query through the chain: the truncation fallback did not run"
# shellcheck disable=SC2046
UDPCHAINS_DNS="127.0.0.1:$DNS" UDPCHAINS_HOSTS_FILE="$TMP/hosts" \
	timeout 60 "$WRAPPER" -v $(popts "$CHAIN") "$PROBE" one > "$TMP/one.tap" 2>&1
grep -q "resolver association up: dns 127.0.0.1:$DNS via relay .*, then " "$TMP/one.tap" &&
	ok "the resolver's association line names both relays (FR-CH-12)" ||
	notok "no resolver association line naming both relays"
# FR-CH-T1 for lookups: each hop dead in turn.  Hop 2 dead means hop 1's
# CONNECT to it fails; either way the chain is never set up.
for dead in "127.0.0.1:9,127.0.0.1:$PROXY2" "127.0.0.1:$PROXY,127.0.0.1:9"; do
	echo "# chain down: $dead"
	before=$(queries "")
	if probe down "$dead" UDPCHAINS_DNS="127.0.0.1:$DNS"; then
		ok "test_resolve down passes with $dead"
	else
		notok "test_resolve down with $dead"
	fi
	check "no query reached the resolver" "$(queries "")" "$before"
done

echo "# chain noconnect: the exit hop refuses CONNECT"
before=$(queries tcp)
if probe noconnect "127.0.0.1:$PROXY,127.0.0.1:$NOCONNECT" UDPCHAINS_DNS="127.0.0.1:$DNS"; then
	ok "test_resolve noconnect passes with the exit hop refusing CONNECT"
else
	notok "test_resolve noconnect with the exit hop refusing CONNECT"
fi
check "no TCP query reached the resolver" "$(queries tcp)" "$before"

echo "# chain noconnect: hop 1 refuses CONNECT, so hop 2 cannot be reached"
before=$(queries "")
if probe down "127.0.0.1:$NOCONNECT,127.0.0.1:$PROXY2" UDPCHAINS_DNS="127.0.0.1:$DNS"; then
	ok "test_resolve down passes with hop 1 refusing CONNECT"
else
	notok "test_resolve down with hop 1 refusing CONNECT"
fi
check "no query reached the resolver" "$(queries "")" "$before"

# strace sees every connect/send the probe makes.  None may name the resolver's
# port, or port 53: a query addressed to a resolver directly is a leak whatever
# answers it.
if command -v strace > /dev/null 2>&1; then
	# chain: main through 2 hops, where the process connects only to hop 1.
	for m in main down chain; do
		case $m in
		main) p="127.0.0.1:$PROXY"; mode=main ;;
		down) p="127.0.0.1:9"; mode=down ;;
		chain) p=$CHAIN; mode=main ;;
		esac
		# shellcheck disable=SC2046
		env -u UDPCHAINS_DNS UDPCHAINS_DNS="127.0.0.1:$DNS" \
			UDPCHAINS_HOSTS_FILE="$TMP/hosts" UDPCHAINS_DNS_SEARCH=search.test \
			UDPCHAINS_DNS_TIMEOUT=2000 \
			timeout 180 strace -f -qq -o "$TMP/strace.$m" \
			-e trace=connect,sendto,sendmsg,sendmmsg \
			"$WRAPPER" $(popts "$p") "$PROBE" $mode > /dev/null 2>&1
		direct=$(grep -cE "htons\((53|$DNS)\)" "$TMP/strace.$m" || true)
		check "strace ($m): the process never addressed a resolver directly" \
			"$direct" "0"
	done
else
	echo "# SKIP strace checks -- strace not installed"
fi

echo "1..$n"
exit $fail

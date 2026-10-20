#!/bin/bash
# test_leak.sh -- TST-03 / SEC-01 / SEC-02, the leak test.
#
# With the proxy stopped, assert that NO UDP packet reaches the destination by
# any path.
#
# This guards the defect that motivates the whole project (baseline §0.3.1):
# with proxychains-ng pointed at a dead proxy, TCP correctly fails while UDP
# reaches the destination anyway, silently and with no diagnostic.  Any workflow
# that assumes "I ran it under the proxy tool, therefore it went through the
# proxy" is wrong there.
#
# The assertion is unqualified -- zero datagrams, no whitelist of expected
# direct traffic -- because D-05 gives v1 no bypass path at all.  That is
# precisely the property that makes this test trustworthy: with a bypass rule
# set, this script would have to encode its own exceptions, and those exceptions
# are exactly where a leak hides.
#
# usage: test_leak.sh [ignored]

set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD="$ROOT/build"
WRAPPER="$ROOT/udpchains"
TMP=$(mktemp -d)
FAIL=0

cleanup() {
	# Fixtures are started inside $(...), a subshell, where a PID stored in a
	# variable would never reach this shell.  Each one's PID goes to a file.
	[ -f "$TMP/pids" ] && kill $(cat "$TMP/pids") 2>/dev/null
	rm -rf "$TMP"
}
trap cleanup EXIT

start_echo() {
	local name=$1; shift
	: > "$TMP/$name.out"
	"$BUILD/udpecho" --port 0 "$@" > "$TMP/$name.out" 2> "$TMP/$name.log" &
	echo $! >> "$TMP/pids"
	local i port=""
	for ((i = 0; i < 100; i++)); do
		port=$(awk '/^PORT/{print $2; exit}' "$TMP/$name.out" 2>/dev/null)
		[ -n "$port" ] && break
		sleep 0.05
	done
	echo "$port"
}

# Counts datagrams the destination actually received.  udpecho logs one line per
# datagram to stderr, so this is a direct measurement of "reached the
# destination" rather than an inference from the shim's own reporting.
received() {
	# grep -c already prints 0 when nothing matches, so do not add a
	# fallback echo -- that would emit two values and break the comparison.
	local n
	n=$(grep -c "bytes" "$TMP/$1.log" 2>/dev/null)
	echo "${n:-0}"
}

check() {
	local desc=$1 got=$2 want=$3
	if [ "$got" = "$want" ]; then
		echo "ok - $desc"
	else
		echo "not ok - $desc (got $got, want $want)" >&2
		FAIL=1
	fi
}

# A port with nothing listening on it.  Port 9 (discard) is the same choice the
# baseline used to demonstrate the proxychains-ng leak.
DEAD_PROXY="127.0.0.1:9"

echo "# TST-03 scenario 1: proxy never existed"
ECHO=$(start_echo dead)
if [ -z "$ECHO" ]; then
	echo "not ok - could not start the echo server" >&2
	exit 1
fi

OUT=$(UDPCHAINS_PROXY="$DEAD_PROXY" UDPCHAINS_QUIET=1 \
	timeout 60 "$WRAPPER" "$BUILD/leakclient" 127.0.0.1 "$ECHO" 2>&1)
echo "$OUT" | sed 's/^/#   /'

SENT_OK=$(echo "$OUT" | sed -n 's/.*sent_ok=\([0-9]*\).*/\1/p')
check "every send fails when the proxy is unreachable" "${SENT_OK:-x}" "0"

sleep 0.3
check "ZERO datagrams reached the destination" "$(received dead)" "0"

echo "# TST-03 scenario 2: proxy accepts TCP but refuses UDP ASSOCIATE"
PROXY_OUT="$TMP/refuse.out"
: > "$PROXY_OUT"
"$BUILD/socks5d" --port 0 --refuse-associate --quiet > "$PROXY_OUT" 2>&1 &
echo $! >> "$TMP/pids"
RPORT=""
for ((i = 0; i < 100; i++)); do
	RPORT=$(awk '/^PORT/{print $2; exit}' "$PROXY_OUT" 2>/dev/null)
	[ -n "$RPORT" ] && break
	sleep 0.05
done

ECHO2=$(start_echo refused)
OUT=$(UDPCHAINS_PROXY="127.0.0.1:$RPORT" UDPCHAINS_QUIET=1 \
	timeout 60 "$WRAPPER" "$BUILD/leakclient" 127.0.0.1 "$ECHO2" 2>&1)
echo "$OUT" | sed 's/^/#   /'

SENT_OK=$(echo "$OUT" | sed -n 's/.*sent_ok=\([0-9]*\).*/\1/p')
check "every send fails when UDP ASSOCIATE is refused" "${SENT_OK:-x}" "0"

sleep 0.3
check "ZERO datagrams reached the destination" "$(received refused)" "0"

echo "# TST-03 scenario 3: the shim is not configured at all"
ECHO3=$(start_echo unconfigured)
# LD_PRELOAD directly, with no proxy configured: the wrapper would have refused
# to run (FR-C-03), but the shim itself must still fail closed rather than let
# datagrams through.
OUT=$(env -u UDPCHAINS_PROXY LD_PRELOAD="$ROOT/libudpchains.so" \
	timeout 60 "$BUILD/leakclient" 127.0.0.1 "$ECHO3" 2>&1)
echo "$OUT" | sed 's/^/#   /'

SENT_OK=$(echo "$OUT" | sed -n 's/.*sent_ok=\([0-9]*\).*/\1/p')
check "every send fails when the shim is unconfigured" "${SENT_OK:-x}" "0"

sleep 0.3
check "ZERO datagrams reached the destination" "$(received unconfigured)" "0"

echo "# TST-03 scenario 4: name lookups with the proxy down (D-22)"
# glibc's resolver makes its socket calls through internal aliases, so before
# D-22 every getaddrinfo went straight to the host's resolver whatever the proxy
# was doing.  Now a lookup that needs DNS must fail, and the resolver the shim
# was told to use must see nothing.
: > "$TMP/dnsd.out"
"$BUILD/dnsd" --port 0 > "$TMP/dnsd.out" 2> "$TMP/dnsd.log" &
echo $! >> "$TMP/pids"
DPORT=""
for ((i = 0; i < 100; i++)); do
	DPORT=$(awk '/^PORT/{print $2; exit}' "$TMP/dnsd.out" 2>/dev/null)
	[ -n "$DPORT" ] && break
	sleep 0.05
done
printf '127.0.0.1\tlocalhost\n203.0.113.5\thostsonly.test\n' > "$TMP/hosts"
OUT=$(UDPCHAINS_PROXY="$DEAD_PROXY" UDPCHAINS_QUIET=1 UDPCHAINS_DNS="127.0.0.1:$DPORT" \
	UDPCHAINS_HOSTS_FILE="$TMP/hosts" UDPCHAINS_DNS_TIMEOUT=2000 \
	timeout 60 "$WRAPPER" "$BUILD/test_resolve" down 2>&1)
RC=$?
echo "$OUT" | sed 's/^/#   /'
check "every lookup that needs DNS fails with the proxy down" "$RC" "0"
check "ZERO queries reached the resolver" "$(grep -c '^QUERY' "$TMP/dnsd.log")" "0"

echo "# TST-03 control: the same client DOES reach the destination unproxied"
# Without this, the test could pass because the client is broken rather than
# because the shim is working.
ECHO4=$(start_echo control)
timeout 30 "$BUILD/leakclient" 127.0.0.1 "$ECHO4" > /dev/null 2>&1
sleep 0.3
CONTROL=$(received control)
if [ "$CONTROL" -gt 0 ]; then
	echo "ok - control: $CONTROL datagrams arrive with no shim, so the test is meaningful"
else
	echo "not ok - control: the client reached nothing even unproxied; the leak test proves nothing" >&2
	FAIL=1
fi

if [ "$FAIL" -ne 0 ]; then
	echo "TST-03 FAILED" >&2
	exit 1
fi
echo "# TST-03 passed: no leak by any path"

#!/bin/bash
# test_faults.sh -- behaviour against an unhelpful proxy (FR-P-08, FR-P-04, D-12).
#
# Each scenario starts the fixture proxy with a different fault injected.  These
# are the behaviours D-06 gave the fixture a reason to exist for: a real proxy
# cannot be told to expire an association or stamp FRAG=1 on demand.

set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD="$ROOT/build"
WRAPPER="$ROOT/udpchains"
TMP=$(mktemp -d)
PIDS=()
FAIL=0

cleanup() {
	for pid in "${PIDS[@]:-}"; do
		[ -n "$pid" ] && kill "$pid" 2>/dev/null
	done
	rm -rf "$TMP"
}
trap cleanup EXIT

wait_port() {
	local file=$1 i port=""
	for ((i = 0; i < 100; i++)); do
		port=$(awk '/^PORT/{print $2; exit}' "$file" 2>/dev/null)
		[ -n "$port" ] && break
		sleep 0.05
	done
	echo "$port"
}

start_proxy() {
	local name=$1; shift
	: > "$TMP/$name.out"
	"$BUILD/socks5d" --port 0 "$@" > "$TMP/$name.out" 2> "$TMP/$name.err" &
	PIDS+=($!)
	wait_port "$TMP/$name.out"
}

start_echo() {
	local name=$1
	: > "$TMP/$name.out"
	"$BUILD/udpecho" --port 0 --quiet > "$TMP/$name.out" 2>&1 &
	PIDS+=($!)
	wait_port "$TMP/$name.out"
}

run_scenario() {
	local name=$1 proxy_port=$2 echo_port=$3; shift 3
	echo
	echo "--- $name"
	if UDPCHAINS_PROXY="127.0.0.1:$proxy_port" UDPCHAINS_QUIET=1 \
		timeout 120 "$WRAPPER" "$BUILD/test_faults" "$@" ; then
		echo "--- $name: PASS"
	else
		echo "--- $name: FAIL" >&2
		FAIL=1
	fi
}

ECHO=$(start_echo echo)

# FR-P-08: the reference proxy expires an association after 60 s of silence.
# Two seconds here, so the test does not take a minute.
P_EXPIRE=$(start_proxy expire --expire-after 2 --quiet)
run_scenario "FR-P-08 transparent re-association" "$P_EXPIRE" "$ECHO" reassoc "$ECHO" 2

# FR-P-04: every relayed datagram comes back with FRAG=1 and must be discarded.
P_FRAG=$(start_proxy frag --frag-inject --quiet)
run_scenario "FR-P-04 FRAG != 0 is discarded" "$P_FRAG" "$ECHO" frag "$ECHO"

# D-12: the proxy's real limit is smaller than the shim's configured one, so
# datagrams in between are dropped silently at the proxy.
P_SMALL=$(start_proxy small --max-dgram 1000 --quiet)
run_scenario "D-12 configured limit vs the proxy's real limit" "$P_SMALL" "$ECHO" \
	maxdgram "$ECHO"

if [ "$FAIL" -ne 0 ]; then
	echo "fault scenarios FAILED" >&2
	exit 1
fi
echo
echo "# all fault scenarios passed"

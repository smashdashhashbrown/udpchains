#!/bin/bash
# run.sh -- the test suite.
#
# Starts the fixture proxy and echo servers (D-06), then runs each test under
# the shim.  TST-02 (the symbol check) runs from `make check` before this,
# because a missing receive hook must fail the BUILD, not a test run.
#
# usage: tests/run.sh [name ...]     (default: all)

set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD="$ROOT/build"
WRAPPER="$ROOT/udpchains"
TMP=$(mktemp -d)

PIDS=()
FAILED=0
RAN=0

cleanup() {
	local pid
	for pid in "${PIDS[@]:-}"; do
		[ -n "$pid" ] && kill "$pid" 2>/dev/null
	done
	rm -rf "$TMP"
}
trap cleanup EXIT

# Starts a fixture and echoes the port it bound.  Fixtures print "PORT <n>" on
# stdout once listening, so tests never race against a not-yet-bound socket.
start_fixture() {
	local name=$1; shift
	local out="$TMP/$name.out"
	: > "$out"
	"$@" > "$out" 2> "$TMP/$name.err" &
	PIDS+=($!)
	local i port=""
	for ((i = 0; i < 100; i++)); do
		port=$(awk '/^PORT/{print $2; exit}' "$out" 2>/dev/null)
		[ -n "$port" ] && break
		sleep 0.05
	done
	if [ -z "$port" ]; then
		echo "FATAL: fixture $name did not report a port" >&2
		cat "$TMP/$name.err" >&2
		exit 1
	fi
	echo "$port"
}

want() { case " ${SELECT:-} " in *" $1 "*|"  ") return 0;; esac; [ -z "${SELECT:-}" ]; }

run_test() {
	local name=$1; shift
	want "$name" || return 0
	RAN=$((RAN + 1))
	echo
	echo "=============================================================="
	echo "  $name"
	echo "=============================================================="
	if "$@"; then
		echo "--- $name: PASS"
	else
		echo "--- $name: FAIL" >&2
		FAILED=$((FAILED + 1))
	fi
}

SELECT="${*:-}"

# --- fixtures ----------------------------------------------------------------

PROXY_PORT=$(start_fixture proxy "$BUILD/socks5d" --port 0 --quiet)
ECHO1=$(start_fixture echo1 "$BUILD/udpecho" --port 0 --quiet)
ECHO2=$(start_fixture echo2 "$BUILD/udpecho" --port 0 --quiet)
ECHO6=$(start_fixture echo6 "$BUILD/udpecho" --port 0 -6 --quiet)

echo "fixtures: proxy=$PROXY_PORT echo1=$ECHO1 echo2=$ECHO2 echo6=$ECHO6"

export UDPCHAINS_PROXY="127.0.0.1:$PROXY_PORT"
export UDPCHAINS_QUIET=1

# --- unit tests (no shim; they link the objects directly) --------------------

run_test unit-addr    "$BUILD/test_addr"
run_test unit-config  "$BUILD/test_config"
run_test unit-socks5  "$BUILD/test_socks5"
run_test unit-fdtable "$BUILD/test_fdtable_mt"

# --- integration tests, under the shim ---------------------------------------

run_test TST-01-matrix \
	timeout 180 "$WRAPPER" "$BUILD/test_matrix" "$ECHO1" "$ECHO6"

run_test TST-05-fidelity \
	timeout 120 "$WRAPPER" "$BUILD/test_fidelity" "$ECHO1" "$ECHO2" "$ECHO6"

run_test TST-06-lifecycle \
	timeout 120 "$WRAPPER" "$BUILD/test_lifecycle" "$ECHO1" "$ECHO2"

run_test TST-07-thread \
	timeout 180 "$WRAPPER" "$BUILD/test_thread" "$ECHO1"

# --- SEC-01 / SEC-02: the leak test (TST-03) ---------------------------------

run_test TST-03-leak "$ROOT/tests/test_leak.sh" "$ECHO1"

# --- fault injection: FR-P-08, FR-P-04, D-12 ---------------------------------

run_test faults "$ROOT/tests/test_faults.sh"

# --- TST-04: real tools -------------------------------------------------------

run_test TST-04-realtools "$ROOT/tests/test_realtools.sh" "$PROXY_PORT" "$ECHO1"

# --- NFR-04: latency benchmark (reported, not gated -- D-08) -----------------

if want NFR-04-bench; then
	RAN=$((RAN + 1))
	echo
	echo "=============================================================="
	echo "  NFR-04-bench (reported, not a gate)"
	echo "=============================================================="
	timeout 120 "$WRAPPER" "$BUILD/bench_latency" "$ECHO1" || true
fi

echo
echo "=============================================================="
if [ "$FAILED" -eq 0 ]; then
	echo "  ALL $RAN TEST GROUPS PASSED"
else
	echo "  $FAILED of $RAN TEST GROUPS FAILED" >&2
fi
echo "=============================================================="
exit $((FAILED > 0))

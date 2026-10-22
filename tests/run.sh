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

FAILED=0
RAN=0

cleanup() {
	# Fixtures are started inside $(...), a subshell, where a PID stored in a
	# variable would never reach this shell.  Each one's PID goes to a file.
	[ -f "$TMP/pids" ] && kill $(cat "$TMP/pids") 2>/dev/null
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
	echo $! >> "$TMP/pids"
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
# Later hops for the chained runs (FR-CH-T2).
PROXY2_PORT=$(start_fixture proxy2 "$BUILD/socks5d" --port 0 --quiet)
PROXY3_PORT=$(start_fixture proxy3 "$BUILD/socks5d" --port 0 --quiet)
ECHO1=$(start_fixture echo1 "$BUILD/udpecho" --port 0 --quiet)
ECHO2=$(start_fixture echo2 "$BUILD/udpecho" --port 0 --quiet)
ECHO6=$(start_fixture echo6 "$BUILD/udpecho" --port 0 -6 --quiet)
# Replies from a different port than addressed -- the TFTP/SIP pattern.
ECHOSW=$(start_fixture echosw "$BUILD/udpecho" --port 0 --switch-port --quiet)

echo "fixtures: proxy=$PROXY_PORT proxy2=$PROXY2_PORT proxy3=$PROXY3_PORT echo1=$ECHO1 echo2=$ECHO2 echo6=$ECHO6 echosw=$ECHOSW"

export UDPCHAINS_PROXY="127.0.0.1:$PROXY_PORT"
export UDPCHAINS_QUIET=1

# --- unit tests (no shim; they link the objects directly) --------------------

run_test unit-addr    "$BUILD/test_addr"
run_test unit-config  "$BUILD/test_config"
run_test unit-socks5  "$BUILD/test_socks5"
run_test unit-chain   "$BUILD/test_chain"
run_test unit-fdtable "$BUILD/test_fdtable_mt"
run_test unit-dns     "$BUILD/test_dns"
run_test unit-supervise "$BUILD/test_supervise_unit"

# --- integration tests, under the shim ---------------------------------------

run_test TST-01-matrix \
	timeout 180 "$WRAPPER" "$BUILD/test_matrix" "$ECHO1" "$ECHO6"

run_test TST-05-fidelity \
	timeout 120 "$WRAPPER" "$BUILD/test_fidelity" "$ECHO1" "$ECHO2" "$ECHO6"

run_test portswitch \
	timeout 60 "$WRAPPER" "$BUILD/test_portswitch" "$ECHOSW"

run_test TST-06-lifecycle \
	timeout 120 "$WRAPPER" "$BUILD/test_lifecycle" "$ECHO1" "$ECHO2"

run_test TST-07-thread \
	timeout 180 "$WRAPPER" "$BUILD/test_thread" "$ECHO1"

# --- FR-CH-T2: the same tests through chains of fixture proxies --------------

# Every test above that runs under the shim, again with UDPCHAINS_PROXY a
# chain.  The third hop is given as localhost, so CONNECT carries a name (D-39)
# and its relay is kept as loopback (D-40).
through_chain() {
	local chain=$1 rc=0

	UDPCHAINS_PROXY="$chain" timeout 180 "$WRAPPER" "$BUILD/test_matrix" \
		"$ECHO1" "$ECHO6" || rc=1
	UDPCHAINS_PROXY="$chain" timeout 120 "$WRAPPER" "$BUILD/test_fidelity" \
		"$ECHO1" "$ECHO2" "$ECHO6" || rc=1
	UDPCHAINS_PROXY="$chain" timeout 60 "$WRAPPER" "$BUILD/test_portswitch" \
		"$ECHOSW" || rc=1
	UDPCHAINS_PROXY="$chain" timeout 120 "$WRAPPER" "$BUILD/test_lifecycle" \
		"$ECHO1" "$ECHO2" || rc=1
	UDPCHAINS_PROXY="$chain" timeout 180 "$WRAPPER" "$BUILD/test_thread" \
		"$ECHO1" || rc=1
	return $rc
}

run_test FR-CH-T2-2hop through_chain \
	"127.0.0.1:$PROXY_PORT,127.0.0.1:$PROXY2_PORT"
run_test FR-CH-T2-3hop through_chain \
	"127.0.0.1:$PROXY_PORT,127.0.0.1:$PROXY2_PORT,localhost:$PROXY3_PORT"

# FR-CH-08 / D-40: the loopback guard looks at the exit hop.  Every hop here is
# on this host, but a chain's exit is reached through other hops, so with
# strict_loopback a connected send to 127.0.0.1 is refused; through the same
# first hop alone, which is local, it is not.
exit_hop_guard() {
	local out rc=0

	out=$(UDPCHAINS_STRICT_LOOPBACK=yes \
		UDPCHAINS_PROXY="127.0.0.1:$PROXY_PORT,127.0.0.1:$PROXY2_PORT" \
		timeout 60 "$WRAPPER" "$BUILD/leakclient" 127.0.0.1 "$ECHO1" 2>&1)
	if printf '%s\n' "$out" | grep -q '^ok send failed: Network is unreachable$'; then
		echo "ok - a chain refuses a loopback destination under strict_loopback"
	else
		echo "not ok - a chain refuses a loopback destination under strict_loopback"
		rc=1
	fi
	out=$(UDPCHAINS_STRICT_LOOPBACK=yes UDPCHAINS_PROXY="127.0.0.1:$PROXY_PORT" \
		timeout 60 "$WRAPPER" "$BUILD/leakclient" 127.0.0.1 "$ECHO1" 2>&1)
	if printf '%s\n' "$out" | grep -q '^LEAK-RISK send reported success'; then
		echo "ok - a single local proxy still sends to it, as in 0.1.0"
	else
		echo "not ok - a single local proxy still sends to it, as in 0.1.0"
		rc=1
	fi
	return $rc
}

run_test FR-CH-08-exit-hop exit_hop_guard

# --- SEC-01 / SEC-02: the leak test (TST-03) ---------------------------------

run_test FR-P-09-auth "$ROOT/tests/test_auth.sh" "$BUILD/socks5d" \
	"$BUILD/udpecho" "$WRAPPER"

# D-22: name resolution through the proxy, never by the host's resolver.
run_test D-22-resolve "$ROOT/tests/test_resolve.sh" "$BUILD/socks5d" \
	"$BUILD/dnsd" "$WRAPPER" "$BUILD/test_resolve"

run_test wrapper-loadable "$ROOT/tests/test_wrapper.sh" "$WRAPPER" \
	"$ROOT/libudpchains.so"

run_test TST-03-leak "$ROOT/tests/test_leak.sh" "$ECHO1"

# --- supervisor mode (D-48 to D-53): static programs, under the filter -------

run_test FR-SV-supervise "$ROOT/tests/test_supervise.sh" "$WRAPPER" "$BUILD"

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
	# NFR-04 excludes proxy and network time, which a single run cannot
	# separate from the shim's own cost.  Running the SAME binary against the
	# SAME echo server with and without the shim makes loopback, the echo
	# server and the syscall path cancel, so the delta bounds what the shim
	# adds.  The proxy hop is still inside that delta -- it is an upper
	# bound, not the shim's share, and the output says so.
	BENCH_DIRECT=$(timeout 120 "$BUILD/bench_latency" "$ECHO1" \
		--tag direct 2>/dev/null | awk '/^NFR04/{print}') || true
	BENCH_SHIM=$(timeout 120 "$WRAPPER" "$BUILD/bench_latency" "$ECHO1" \
		--tag proxied 2>/dev/null | awk '/^NFR04/{print}') || true

	d_med=$(printf '%s\n' "$BENCH_DIRECT" | sed -n 's/.*median=\([0-9.]*\).*/\1/p')
	s_med=$(printf '%s\n' "$BENCH_SHIM"   | sed -n 's/.*median=\([0-9.]*\).*/\1/p')
	d_p99=$(printf '%s\n' "$BENCH_DIRECT" | sed -n 's/.*p99=\([0-9.]*\).*/\1/p')
	s_p99=$(printf '%s\n' "$BENCH_SHIM"   | sed -n 's/.*p99=\([0-9.]*\).*/\1/p')

	if [ -n "$d_med" ] && [ -n "$s_med" ]; then
		printf '#   %-8s median %8.1f us   p99 %8.1f us\n' direct \
			"$d_med" "$d_p99"
		printf '#   %-8s median %8.1f us   p99 %8.1f us\n' proxied \
			"$s_med" "$s_p99"
		awk -v a="$s_med" -v b="$d_med" -v c="$s_p99" -v d="$d_p99" \
		    -v budget=100 'BEGIN {
			dm = a - b; dp = c - d;
			printf "#\n";
			printf "#   ADDED    median %8.1f us   p99 %8.1f us\n", dm, dp;
			printf "#\n";
			printf "# NFR-04 budget is %d us per datagram, excluding proxy and\n", budget;
			printf "# network time.  The added figure above still CONTAINS the\n";
			printf "# proxy hop, which this harness cannot separate, so it is an\n";
			printf "# upper bound: the shim%s own share is at most this.\n", "\47s";
			if (dm <= budget)
				printf "#   -> within budget even counting the proxy hop.\n";
			else
				printf "#   -> ABOVE budget, but only as an upper bound; the\n" \
				       "#      proxy hop is included and is not the shim%s cost.\n", "\47s";
		}'
	else
		echo "# NFR-04: benchmark did not produce results"
	fi
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

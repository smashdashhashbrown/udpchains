#!/bin/bash
# test_faults.sh -- behaviour against an unhelpful proxy (FR-P-08, FR-P-04, D-12),
# and against an unhelpful hop of a chain (FR-CH-T3, FR-CH-10).
#
# Each scenario starts the fixture proxy with a different fault injected.  These
# are the behaviours D-06 gave the fixture a reason to exist for: a real proxy
# cannot be told to expire an association or stamp FRAG=1 on demand.

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
	echo $! >> "$TMP/pids"
	wait_port "$TMP/$name.out"
}

start_echo() {
	local name=$1
	: > "$TMP/$name.out"
	"$BUILD/udpecho" --port 0 --quiet > "$TMP/$name.out" 2>&1 &
	echo $! >> "$TMP/pids"
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

# D-34: a proxy that pins each association to its declared address.  After a
# fork, the child cannot re-bind the parent's port, and must stop declaring it.
P_PIN=$(start_proxy pin --pin-declared --quiet)
run_scenario "D-34 a forked child's failed re-bind" "$P_PIN" "$ECHO" forkbind "$ECHO"

# --- FR-CH-T3: faults in a chain ---------------------------------------------
#
# Three hops, the fault at one of them.  Run with -v, so the shim's account of
# each drop can be checked as well as the program's.

# The proxy's latest relay port, from its own log (not --quiet).
relay_port() {
	sed -n 's/.*association up, relay .*:\([0-9]*\)$/\1/p' "$TMP/$1.err" | tail -1
}

# Datagrams an echo server started without --quiet received.
echoed() { grep -c bytes "$TMP/$1.err"; }

start_loud_echo() {
	local name=$1
	: > "$TMP/$name.out"
	"$BUILD/udpecho" --port 0 > "$TMP/$name.out" 2> "$TMP/$name.err" &
	echo $! >> "$TMP/pids"
	wait_port "$TMP/$name.out"
}

# As run_scenario, through a chain and with -v.  The program's output goes to
# $TMP/chain.out, the shim's to $TMP/chain.err.
run_chain() {
	local name=$1 chain=$2; shift 2
	echo
	echo "--- $name"
	if UDPCHAINS_PROXY="$chain" timeout 120 "$WRAPPER" -v "$BUILD/test_faults" "$@" \
		> "$TMP/chain.out" 2> "$TMP/chain.err"; then
		sed 's/^/#   /' "$TMP/chain.out"
		echo "--- $name: PASS"
	else
		sed 's/^/#   /' "$TMP/chain.out" >&2
		grep -v ' debug: ' "$TMP/chain.err" | sed 's/^/#   /' | tail -20 >&2
		echo "--- $name: FAIL" >&2
		FAIL=1
	fi
}

check() {
	if [ "$2" = "$3" ]; then
		echo "ok - $1"
	else
		echo "not ok - $1 (got $2, want $3)" >&2
		FAIL=1
	fi
}

# Says whether the shim's output from the last chain run has $1.
said() {
	if grep -q -- "$1" "$TMP/chain.err"; then
		echo "ok - $2"
	else
		echo "not ok - $2: no \"$1\" in the shim's output" >&2
		FAIL=1
	fi
}

HA=$(start_proxy ha --quiet)
HC=$(start_proxy hc --quiet)

P_EXP2=$(start_proxy exp2 --expire-after 2 --quiet)
run_chain "FR-CH-T3 expiry at a middle hop" \
	"127.0.0.1:$HA,127.0.0.1:$P_EXP2,127.0.0.1:$HC" reassoc "$ECHO" 2
check "the association was set up twice, through all 3 hops" \
	"$(grep -c 'association up: .*, then .*, then ' "$TMP/chain.err")" 2

P_FRAG2=$(start_proxy frag2 --frag-inject --quiet)
run_chain "FR-CH-T3 FRAG set at an inner layer" \
	"127.0.0.1:$HA,127.0.0.1:$P_FRAG2,127.0.0.1:$HC" frag "$ECHO"
said "its layer 2 of 3 has FRAG set" "the shim dropped it at layer 2, for its FRAG"

run_chain "FR-CH-T3 FRAG set at the innermost layer" \
	"127.0.0.1:$HA,127.0.0.1:$HC,127.0.0.1:$P_FRAG" frag "$ECHO"

# Hop 2 logs (not --quiet), for its relay port.  The program waits, receiving,
# while the forger -- not under the shim -- sends to that relay.
HB=$(start_proxy hb)
echo
echo "--- FR-CH-T3 a forged inner source behind a genuine outer one"
: > "$TMP/chain.out"
UDPCHAINS_PROXY="127.0.0.1:$HA,127.0.0.1:$HB,127.0.0.1:$HC" timeout 60 \
	"$WRAPPER" -v "$BUILD/test_faults" forged "$ECHO" 4 \
	> "$TMP/chain.out" 2> "$TMP/chain.err" &
FPID=$!
for ((i = 0; i < 100; i++)); do
	grep -q READY "$TMP/chain.out" 2>/dev/null && break
	sleep 0.05
done
RELAY2=$(relay_port hb)
FORGED=1
[ -n "$RELAY2" ] &&
	env -u LD_PRELOAD "$BUILD/test_faults" forge "$ECHO" "$RELAY2" > "$TMP/forge.out" &&
	FORGED=0
if wait "$FPID" && [ "$FORGED" = 0 ]; then
	sed 's/^/#   /' "$TMP/chain.out"
	echo "--- FR-CH-T3 a forged inner source behind a genuine outer one: PASS"
else
	sed 's/^/#   /' "$TMP/chain.out" "$TMP/forge.out" >&2
	echo "--- FR-CH-T3 a forged inner source behind a genuine outer one: FAIL" \
		"(hop 2's relay port: ${RELAY2:-not found})" >&2
	FAIL=1
fi
if grep -q "<- 127.0.0.1:[0-9]*, 16 bytes" "$TMP/hb.err"; then
	echo "ok - hop 2 relayed the forgeries onward, so the shim received them"
else
	echo "not ok - hop 2 never relayed the forgeries; the case proved nothing" >&2
	FAIL=1
fi
said "its layer 2 of 3 is not from hop 3's relay" \
	"the shim dropped them at layer 2, for its source"

# A hop that does not do CONNECT cannot be an intermediate hop.
P_NOCONN=$(start_proxy noconn --no-connect --quiet)
NECHO=$(start_loud_echo necho)
echo
echo "--- FR-CH-T3 a hop refusing CONNECT"
OUT=$(UDPCHAINS_PROXY="127.0.0.1:$HA,127.0.0.1:$P_NOCONN,127.0.0.1:$HC" \
	timeout 60 "$WRAPPER" "$BUILD/leakclient" 127.0.0.1 "$NECHO" 2> "$TMP/chain.err")
echo "$OUT" | sed 's/^/#   /'
check "every send fails" "$(echo "$OUT" | sed -n 's/.*sent_ok=\([0-9]*\).*/\1/p')" 0
sleep 0.3
check "ZERO datagrams reached the destination" "$(echoed necho)" 0
said "hop 3 of 3 (127.0.0.1:$HC): hop 2's CONNECT to it failed: Operation not supported" \
	"the shim names hop 3, and hop 2's refusal"

# --- FR-CH-10: the shim's descriptors run out (D-46) ---------------------------
#
# A soft limit of 64 puts the shim's range at 32 to 63, room for ten 3-hop
# associations.  The exit hop logs (not --quiet), so the datagrams it relayed
# can be counted against what the program was told it sent, and what the
# destination received.
HX=$(start_proxy hx)
BECHO=$(start_loud_echo becho)
run_chain "FR-CH-10 the shim's descriptor range runs out" \
	"127.0.0.1:$HA,127.0.0.1:$HC,127.0.0.1:$HX" fdband "$BECHO" 64
said "no free descriptor at 32 or above for the shim's own connection" \
	"the range filling is reported"
SENT=$(sed -n 's/^# sent_ok=\([0-9]*\)$/\1/p' "$TMP/chain.out")
if [ "${SENT:-0}" -gt 10 ]; then
	echo "ok - $SENT associations worked, more than the range holds"
else
	echo "not ok - only ${SENT:-0} associations worked; the range never filled" >&2
	FAIL=1
fi
sleep 0.3
check "the exit hop relayed exactly the datagrams reported sent" \
	"$(grep -c -- '-> 127.0.0.1' "$TMP/hx.err")" "${SENT:-x}"
check "and the destination received exactly those: none went direct" \
	"$(echoed becho)" "${SENT:-x}"

# D-33: diagnostics.  These need no working proxy -- multicast is refused
# before any association -- and run with warnings ON, which run.sh turns off.
echo
echo "--- D-33 diagnostics"
diag() { env -u UDPCHAINS_QUIET UDPCHAINS_PROXY=127.0.0.1:9 timeout 60 "$WRAPPER" "$@"; }

if diag "$BUILD/test_faults" mcast-burst 9 > "$TMP/burst.out" 2> "$TMP/burst.err" &&
   grep -q '^ok' "$TMP/burst.out"; then
	n=$(grep -c 'cannot send to multicast' "$TMP/burst.err")
	if [ "$n" -ge 1 ] && [ "$n" -le 2 ]; then
		echo "ok - 50 refused multicast sends produce $n warning line(s), not 50"
	else
		echo "not ok - 50 refused multicast sends produced $n warning lines" >&2
		FAIL=1
	fi
else
	echo "not ok - the multicast burst did not run" >&2
	FAIL=1
fi

diag -q "$BUILD/test_faults" mcast-burst 9 > /dev/null 2> "$TMP/quiet.err"
n=$(grep -c 'warning' "$TMP/quiet.err")
if [ "$n" -eq 0 ]; then
	echo "ok - under -q, which means errors only, no warning is printed"
else
	echo "not ok - -q still printed $n warning lines" >&2
	FAIL=1
fi

if diag "$BUILD/test_faults" stderr-reused 9 "$TMP/applog" > "$TMP/reuse.out" &&
   ! grep -q '^not ok' "$TMP/reuse.out"; then
	echo "ok - a warning is not written into a file that took over descriptor 2"
else
	echo "not ok - the shim wrote into the program's file on descriptor 2:" >&2
	sed 's/^/#   /' "$TMP/reuse.out" "$TMP/applog" >&2
	FAIL=1
fi

if [ "$FAIL" -ne 0 ]; then
	echo "fault scenarios FAILED" >&2
	exit 1
fi
echo
echo "# all fault scenarios passed"

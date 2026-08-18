#!/bin/bash
# test_realtools.sh -- TST-04, real-tool integration.
#
# The requirement names dig, nc -u, ntpdate or chronyd -Q, tftp and iperf3 -u.
# Tools that are not installed are SKIPPED and reported as such -- a skip is not
# a pass, and acceptance criterion 4 needs dig, nc -u and iperf3 -u run against
# the reference proxy by hand before v1 is done.
#
# Note on dig: D-04 makes DNS ordinary UDP with no special case, so on a
# systemd-resolved host the stub resolver at 127.0.0.53 is itself proxied.  The
# dig case therefore uses an EXPLICIT @server; without one it could pass for the
# wrong reason.
#
# usage: test_realtools.sh <proxy_port> <echo_port>

set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WRAPPER="$ROOT/udpchains"
PROXY_PORT=${1:?need proxy port}
ECHO_PORT=${2:?need echo port}

export UDPCHAINS_PROXY="127.0.0.1:$PROXY_PORT"
export UDPCHAINS_QUIET=1

FAIL=0
SKIPPED=""

skip() {
	echo "# SKIP $1 -- $2"
	SKIPPED="$SKIPPED $1"
}

pass() { echo "ok - $1"; }
fail() { echo "not ok - $1" >&2; FAIL=1; }

# --- dig ---------------------------------------------------------------------

if ! command -v dig > /dev/null 2>&1; then
	skip dig "not installed"
else
	# Find a DNS server that answers directly, so a failure through the shim
	# is attributable to the shim rather than to the network.
	DNS=""
	for cand in 127.0.0.53 1.1.1.1 8.8.8.8; do
		if timeout 5 dig +short +tries=1 +time=2 "@$cand" example.com A \
			> /dev/null 2>&1; then
			DNS=$cand
			break
		fi
	done

	if [ -z "$DNS" ]; then
		skip dig "no reachable DNS server to test against"
	else
		OUT=$(timeout 20 "$WRAPPER" dig +short +tries=1 +time=5 \
			"@$DNS" example.com A 2>&1)
		if echo "$OUT" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
			pass "dig @$DNS resolves through the shim"
		else
			fail "dig @$DNS through the shim: $OUT"
		fi
	fi
fi

# --- nc -u -------------------------------------------------------------------

if ! command -v nc > /dev/null 2>&1; then
	skip nc "not installed"
else
	OUT=$(echo "hello-from-nc" | timeout 15 "$WRAPPER" \
		nc -u -w 3 127.0.0.1 "$ECHO_PORT" 2>&1)
	if echo "$OUT" | grep -q "hello-from-nc"; then
		pass "nc -u round-trips through the shim"
	else
		fail "nc -u through the shim returned: $OUT"
	fi
fi

# --- tftp --------------------------------------------------------------------

if ! command -v tftp > /dev/null 2>&1; then
	skip tftp "not installed"
else
	# Without a TFTP server, all that can be shown is that the client runs
	# under the shim and its traffic is proxied rather than leaking.
	skip tftp "no TFTP server available in this environment"
fi

# --- ntpdate / chronyd -------------------------------------------------------

if command -v chronyd > /dev/null 2>&1; then
	skip chronyd "needs a reachable NTP server and privileges"
elif command -v ntpdate > /dev/null 2>&1; then
	skip ntpdate "needs a reachable NTP server"
else
	skip ntpdate/chronyd "not installed"
fi

# --- iperf3 -u ---------------------------------------------------------------

if ! command -v iperf3 > /dev/null 2>&1; then
	skip iperf3 "not installed"
else
	iperf3 -s -1 -p 5201 > /dev/null 2>&1 &
	IPERF_PID=$!
	sleep 0.5
	if timeout 25 "$WRAPPER" iperf3 -u -c 127.0.0.1 -p 5201 -t 2 -b 1M \
		> /dev/null 2>&1; then
		pass "iperf3 -u runs through the shim"
	else
		fail "iperf3 -u through the shim"
	fi
	kill $IPERF_PID 2>/dev/null
fi

echo
if [ -n "$SKIPPED" ]; then
	echo "# TST-04 skipped:$SKIPPED"
	echo "# A skip is NOT a pass.  Acceptance criterion 4 requires dig, nc -u"
	echo "# and iperf3 -u run against the reference proxy, with that proxy's"
	echo "# own logs confirming the traffic arrived via the tunnel."
fi

[ "$FAIL" -eq 0 ] || exit 1
echo "# TST-04: every available tool worked through the shim"

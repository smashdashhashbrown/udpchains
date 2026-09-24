#!/bin/bash
# test_failclosed_capture.sh -- SEC-01/SEC-02 observed on the WIRE.
#
# TST-03 already asserts that zero datagrams reach the destination, by watching
# the destination.  That cannot see a datagram which leaves this host and goes
# somewhere else -- a leak to the wrong address looks identical to no leak at
# all.  This watches the wire instead.
#
# Needs CAP_NET_RAW, so it is NOT part of `make test`; run it by hand:
#
#   sudo tests/test_failclosed_capture.sh [dest_ip] [dest_port]
#
# The default destination is 192.0.2.1 (TEST-NET-1, RFC 5737): routable-looking,
# guaranteed unallocated, so any packet addressed to it is unambiguous and
# nothing can answer.  Pass a real proxy's destination instead to run this
# against a real deployment.
#
# THE POSITIVE CONTROL IS THE POINT.  A capture that sees nothing because the
# filter or interface is wrong would "pass" every fail-closed assertion while
# proving nothing.  So the first case runs the client WITHOUT the shim and
# requires the capture to see traffic.  If that case fails, every result below
# it is meaningless.
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD="$ROOT/build"
WRAPPER="$ROOT/udpchains"

DEST=${1:-192.0.2.1}
DPORT=${2:-9}

# The interface the kernel will actually use for DEST.  Capturing on "any" is
# convenient but is a pseudo-device; when it yields nothing the real interface
# is the thing to try, so prefer it from the start and keep "any" as fallback.
IFACE=$(ip route get "$DEST" 2>/dev/null |
	sed -n 's/.*dev \([^ ]*\).*/\1/p' | head -1)
IFACE=${IFACE:-any}

if [ "$(id -u)" -ne 0 ]; then
	echo "not ok - must run as root (tcpdump needs CAP_NET_RAW)" >&2
	exit 1
fi
for t in tcpdump "$WRAPPER" "$BUILD/socks5d"; do
	command -v "$t" >/dev/null 2>&1 || [ -x "$t" ] || {
		echo "not ok - missing $t (run make first)" >&2; exit 1; }
done

TMP=$(mktemp -d)
PIDS=()
FAIL=0
n=0

cleanup() {
	for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
	if [ -n "${KEEP_TMP:-}" ]; then
		echo "# artifacts kept in $TMP" >&2
	else
		rm -rf "$TMP"
	fi
}
trap cleanup EXIT

ok()    { n=$((n+1)); echo "ok $n - $1"; }
notok() { n=$((n+1)); echo "not ok $n - $1"; FAIL=1; }

# Runs $2.. with the capture active, and echoes the packet count seen.
capture_run() {
	local tag=$1; shift
	local cap="$TMP/$tag.pcap"

	# Capture ALL udp and match offline.  An in-kernel filter that silently
	# matches nothing is indistinguishable from a clean run, which is the one
	# failure this test cannot afford; matching offline means a miss shows up
	# as captured-but-unmatched packets we can print, rather than silence.
	# --immediate-mode matters more than it looks.  libpcap on Linux uses a
	# TPACKET_V3 ring that retires blocks on a timer, so packets can sit in
	# an unretired block and never reach the file if the capture is stopped
	# shortly after them -- producing "0 packets captured, 0 dropped", which
	# reads exactly like a clean run.  For a test whose entire purpose is to
	# prove nothing was sent, a buffering artefact that looks like proof is
	# the worst possible failure.
	tcpdump -i "$IFACE" -n -p -U --immediate-mode -w "$cap" udp \
		> "$TMP/$tag.tcpdump" 2>&1 &
	local tcpid=$!
	PIDS+=("$tcpid")

	# Wait for tcpdump to actually be listening; starting the client first
	# would race and could miss the very packet under test.
	local i
	for ((i = 0; i < 100; i++)); do
		grep -q "listening on" "$TMP/$tag.tcpdump" 2>/dev/null && break
		sleep 0.05
	done

	sleep 0.5          # let the capture socket settle after the banner
	"$@" > "$TMP/$tag.client" 2>&1
	sleep 2            # let the ring flush before stopping the capture

	kill -INT "$tcpid" 2>/dev/null
	wait "$tcpid" 2>/dev/null

	tcpdump -r "$cap" "dst host $DEST and dst port $DPORT" 2>/dev/null |
		grep -c . || true
}

# Everything the capture saw, for when a count is surprising.
dump_capture() {
	local tag=$1
	echo "# --- all udp captured during '$tag' ---"
	tcpdump -r "$TMP/$tag.pcap" -n -c 40 2>/dev/null | sed 's/^/#   /' ||
		echo "#   (nothing)"
}

# A client that sends a handful of datagrams and reports how many succeeded.
client() { "$BUILD/leakclient" "$DEST" "$DPORT"; }

echo "# capturing udp to $DEST:$DPORT on interface $IFACE"

# --- 0. POSITIVE CONTROL: no shim at all -------------------------------------
got=$(capture_run control env -u LD_PRELOAD "$BUILD/leakclient" "$DEST" "$DPORT")
if [ "${got:-0}" -gt 0 ]; then
	ok "POSITIVE CONTROL: unproxied traffic IS captured ($got packets) -- the capture works"
else
	notok "POSITIVE CONTROL FAILED: captured nothing without the shim. The filter or interface is wrong; every result below is meaningless"
	echo "#"
	echo "# --- tcpdump said: ---"
	sed 's/^/#   /' "$TMP/control.tcpdump" 2>/dev/null
	echo "# --- the client said: ---"
	sed 's/^/#   /' "$TMP/control.client" 2>/dev/null
	dump_capture control
	echo "#"
	echo "# If the client reports sent_ok=0, nothing was sent and the capture"
	echo "# is fine -- look at the client, not tcpdump.  If it reports sends"
	echo "# succeeding, try: tcpdump -i $IFACE -n \"udp and host $DEST\""
	echo "# and re-run with KEEP_TMP=1 to inspect the pcap."
	echo "1..$n"
	exit 1
fi

# --- 1. proxy never existed ---------------------------------------------------
got=$(capture_run dead env UDPCHAINS_PROXY=127.0.0.1:9 UDPCHAINS_QUIET=1 \
	"$WRAPPER" "$BUILD/leakclient" "$DEST" "$DPORT")
sent=$(sed -n 's/.*sent_ok=\([0-9]*\).*/\1/p' "$TMP/dead.client")
[ "${sent:-x}" = "0" ] && ok "unreachable proxy: every send fails" \
	|| notok "unreachable proxy: $sent sends succeeded, want 0"
[ "${got:-1}" -eq 0 ] && ok "unreachable proxy: ZERO packets on the wire" \
	|| notok "LEAK: $got packets reached the wire with the proxy down"

# --- 2. proxy accepts TCP but refuses UDP ASSOCIATE ---------------------------
: > "$TMP/refuse.out"
"$BUILD/socks5d" --port 0 --refuse-associate --quiet > "$TMP/refuse.out" 2>&1 &
PIDS+=($!)
RPORT=""
for ((i = 0; i < 100; i++)); do
	RPORT=$(awk '/^PORT/{print $2; exit}' "$TMP/refuse.out" 2>/dev/null)
	[ -n "$RPORT" ] && break
	sleep 0.05
done
got=$(capture_run refused env "UDPCHAINS_PROXY=127.0.0.1:$RPORT" UDPCHAINS_QUIET=1 \
	"$WRAPPER" "$BUILD/leakclient" "$DEST" "$DPORT")
sent=$(sed -n 's/.*sent_ok=\([0-9]*\).*/\1/p' "$TMP/refused.client")
[ "${sent:-x}" = "0" ] && ok "refused ASSOCIATE: every send fails" \
	|| notok "refused ASSOCIATE: $sent sends succeeded, want 0"
[ "${got:-1}" -eq 0 ] && ok "refused ASSOCIATE: ZERO packets on the wire" \
	|| notok "LEAK: $got packets reached the wire after a refused ASSOCIATE"

# --- 3. shim loaded but unconfigured -----------------------------------------
got=$(capture_run unconfigured env -u UDPCHAINS_PROXY \
	LD_PRELOAD="$ROOT/libudpchains.so" "$BUILD/leakclient" "$DEST" "$DPORT")
sent=$(sed -n 's/.*sent_ok=\([0-9]*\).*/\1/p' "$TMP/unconfigured.client")
[ "${sent:-x}" = "0" ] && ok "unconfigured shim: every send fails" \
	|| notok "unconfigured shim: $sent sends succeeded, want 0"
[ "${got:-1}" -eq 0 ] && ok "unconfigured shim: ZERO packets on the wire" \
	|| notok "LEAK: $got packets reached the wire with no configuration"

# --- 4. WORKING proxy ---------------------------------------------------------
#
# The intent here is to catch a shim that sends a datagram BOTH ways round --
# correctly to the relay, and also directly to the destination.  TST-03 cannot
# see that, because the relayed copy arrives and looks like success.
#
# But it is only testable against a proxy on ANOTHER host.  A co-located proxy
# relays the datagram onward from this same interface (socks5d does exactly
# that, as any proxy must), so a packet to the destination on the wire is the
# expected behaviour and is indistinguishable from a leak.  Asserting zero there
# fails against a correctly working system -- which is what it did on first run.
: > "$TMP/live.out"
"$BUILD/socks5d" --port 0 > "$TMP/live.out" 2>&1 &
PIDS+=($!)
LPORT=""
for ((i = 0; i < 100; i++)); do
	LPORT=$(awk '/^PORT/{print $2; exit}' "$TMP/live.out" 2>/dev/null)
	[ -n "$LPORT" ] && break
	sleep 0.05
done

got=$(capture_run live env "UDPCHAINS_PROXY=127.0.0.1:$LPORT" UDPCHAINS_QUIET=1 \
	"$WRAPPER" "$BUILD/leakclient" "$DEST" "$DPORT")

if grep -q -- "-> " "$TMP/live.out" 2>/dev/null; then
	ok "working proxy: the proxy logged relaying the datagrams onward"
else
	notok "working proxy: the proxy never relayed anything, so this case proved nothing"
fi

if [ "${got:-0}" -gt 0 ]; then
	ok "working proxy: $got packets reached the destination, VIA THE PROXY (a co-located proxy relays from this same interface, so this cannot distinguish relay from leak -- see below)"
else
	notok "working proxy: nothing reached the destination at all; the relay path is broken"
fi

# --- 5. name lookups (D-22) ---------------------------------------------------
#
# glibc's resolver makes its socket calls through internal aliases, so before
# D-22 a lookup went to the host's resolver whatever the proxy was doing.  The
# datagram cases above cannot see that: the leak is to port 53, not to DEST.
#
# Captures on loopback as well as $IFACE, because a host running
# systemd-resolved sends every libc lookup to 127.0.0.53 first.
#
# Every process on the host shares that resolver, so a lookup by anything else
# during the window -- NetworkManager, snapd, a browser -- also puts packets on
# port 53.  Counting those failed the leak cases at random.  Each case looks up
# a name of its own, and only packets carrying that name count; the rest are
# reported and ignored.  Echoes "<carrying the name> <unrelated>".
dns_capture_run() {
	local tag=$1 name=$2; shift 2
	local ifs="lo" f i c u mine=0 other=0
	local -a tpids=()

	[ "$IFACE" != "lo" ] && [ "$IFACE" != "any" ] && ifs="lo $IFACE"
	for f in $ifs; do
		tcpdump -i "$f" -n -p -U --immediate-mode -w "$TMP/$tag.$f.pcap" \
			udp or tcp > "$TMP/$tag.$f.tcpdump" 2>&1 &
		tpids+=($!)
		PIDS+=($!)
	done
	for f in $ifs; do
		for ((i = 0; i < 100; i++)); do
			grep -q "listening on" "$TMP/$tag.$f.tcpdump" 2>/dev/null && break
			sleep 0.05
		done
	done

	sleep 0.5
	"$@" > "$TMP/$tag.client" 2>&1
	sleep 2

	for f in "${tpids[@]}"; do
		kill -INT "$f" 2>/dev/null
		wait "$f" 2>/dev/null
	done
	# -i: a resolver may randomise the case of a query name (DNS 0x20).
	for f in $ifs; do
		tcpdump -n -r "$TMP/$tag.$f.pcap" "dst port 53" 2>/dev/null \
			> "$TMP/$tag.$f.dns"
		c=$(grep -ciF -- "$name" "$TMP/$tag.$f.dns" || true)
		u=$(grep -viF -- "$name" "$TMP/$tag.$f.dns" | grep -c . || true)
		mine=$((mine + ${c:-0}))
		other=$((other + ${u:-0}))
	done
	echo "$mine $other"
}

# One line naming the packets ignored, if any.
dns_note_other() {
	[ "$1" -gt 0 ] &&
		echo "# ($1 unrelated port-53 packets from other processes ignored)"
	return 0
}

# A fresh name each run, so no cache along the way can answer it silently.
dns_name() { echo "udpc-$$-$RANDOM.example.org"; }
# getent prints one line per address it resolved, and nothing on failure.
resolved() { grep -cE '^[0-9a-fA-F:.]+[[:space:]]' "$TMP/$1.client" || true; }

if command -v getent > /dev/null 2>&1; then
	name=$(dns_name)
	read -r got other < <(dns_capture_run dnscontrol "$name" \
		env -u LD_PRELOAD getent ahosts "$name")
	if [ "${got:-0}" -gt 0 ]; then
		ok "DNS POSITIVE CONTROL: an unproxied lookup IS captured ($got packets to port 53 asking for its name)"
		dns_note_other "${other:-0}"

		name=$(dns_name)
		read -r got other < <(dns_capture_run dnsdown "$name" \
			env UDPCHAINS_PROXY=127.0.0.1:9 \
			UDPCHAINS_DNS=192.0.2.53 UDPCHAINS_QUIET=1 \
			"$WRAPPER" getent ahosts "$name")
		[ "$(resolved dnsdown)" = "0" ] && ok "lookup with the proxy down: fails" \
			|| notok "lookup with the proxy down: it RESOLVED"
		[ "${got:-1}" -eq 0 ] && ok "lookup with the proxy down: ZERO packets to port 53 asking for its name" \
			|| notok "LEAK: $got packets to port 53 asking for $name with the proxy down"
		dns_note_other "${other:-0}"

		name=$(dns_name)
		read -r got other < <(dns_capture_run dnsunset "$name" \
			env -u UDPCHAINS_DNS \
			"UDPCHAINS_PROXY=127.0.0.1:$LPORT" UDPCHAINS_QUIET=1 \
			"$WRAPPER" getent ahosts "$name")
		[ "$(resolved dnsunset)" = "0" ] && ok "lookup with no dns configured: fails" \
			|| notok "lookup with no dns configured: it RESOLVED"
		[ "${got:-1}" -eq 0 ] && ok "lookup with no dns configured: ZERO packets to port 53 asking for its name" \
			|| notok "LEAK: $got packets to port 53 asking for $name with no resolver configured"
		dns_note_other "${other:-0}"
	else
		notok "DNS POSITIVE CONTROL FAILED: no packet to port 53 asked for the looked-up name, so the D-22 cases would prove nothing. nscd, or no resolver at all? See KEEP_TMP=1"
	fi
else
	echo "# SKIP D-22 lookups -- getent not installed"
fi

echo "#"
echo "# NOTE: the both-ways-round check needs a proxy on another host, where any"
echo "# packet to the destination leaving THIS host is unambiguously a leak."
echo "# Re-run as:  REMOTE_PROXY=<host:port> sudo $0 <dest> <port>"
if [ -n "${REMOTE_PROXY:-}" ]; then
	got=$(capture_run remote env "UDPCHAINS_PROXY=$REMOTE_PROXY" UDPCHAINS_QUIET=1 \
		"$WRAPPER" "$BUILD/leakclient" "$DEST" "$DPORT")
	[ "${got:-1}" -eq 0 ] && ok "remote proxy: ZERO packets went direct to the destination" \
		|| notok "LEAK: $got packets went direct despite a remote proxy"
fi

echo "1..$n"
[ "$FAIL" -eq 0 ] || exit 1

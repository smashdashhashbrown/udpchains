#!/bin/bash
# test_supervise.sh -- supervisor mode (D-48 to D-53, FR-SV-*).
#
# The supervisor installs the filter, carries UDP through the proxy for the
# sockets it makes in the reserved range, refuses what it cannot carry, and
# passes on the program's exit status and signals.  The probes are static
# binaries, which the shim cannot see at all.
#
# usage: test_supervise.sh <wrapper> <build dir>
#
# NO_SHIM=1 skips the checks that load the shim, for a sanitiser build, whose
# shim cannot be preloaded into programs that were not built with it.
set -u

W="$1"
B="$2"
P="$B/test_supervise"

TMP=$(mktemp -d)
PIDS=()
cleanup() {
	local p
	for p in "${PIDS[@]:-}"; do
		[ -n "$p" ] && kill "$p" 2> /dev/null
	done
	rm -rf "$TMP"
}
trap cleanup EXIT

n=0
fail=0
ok() { n=$((n + 1)); echo "ok $n - $1"; }
notok() { n=$((n + 1)); echo "not ok $n - $1"; fail=1; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else notok "$1 (got '$2', want '$3')"; fi; }
skip() { n=$((n + 1)); echo "ok $n - # SKIP $1"; }
NO_SHIM=${NO_SHIM:-0}

# Starts a fixture and stores the port it reports in the variable named $1.
# Not in a subshell, so its PID reaches PIDS.
start() {
	local var=$1 name=$2 i port=""
	shift 2
	"$@" > "$TMP/$name.out" 2> "$TMP/$name.err" &
	PIDS+=($!)
	for ((i = 0; i < 100; i++)); do
		port=$(awk '/^PORT/{print $2; exit}' "$TMP/$name.out" 2> /dev/null)
		[ -n "$port" ] && break
		sleep 0.05
	done
	[ -n "$port" ] || { echo "FATAL: $name did not start" >&2; exit 1; }
	printf -v "$var" '%s' "$port"
}

start PROXY proxy "$B/socks5d" --port 0 --quiet
start ECHO echo "$B/udpecho" --port 0
start DELAYED delayed "$B/udpecho" --port 0 --delay 10
# A proxy that accepts the connection and never answers (D-54).
start SILENT silent "$P" silent
# A proxy that is not there: a fixture started and stopped, so its port is
# free.
"$B/socks5d" --port 0 --quiet > "$TMP/dead.out" 2>&1 &
dead=$!
for ((i = 0; i < 100; i++)); do
	DEAD=$(awk '/^PORT/{print $2; exit}' "$TMP/dead.out" 2> /dev/null)
	[ -n "$DEAD" ] && break
	sleep 0.05
done
kill "$dead"
wait "$dead" 2> /dev/null
SV=("$W" --supervise -p "127.0.0.1:$PROXY")
echoed() { grep -c bytes "$TMP/echo.err"; }

echo "# exit status is the program's (FR-SV-11)"
timeout 20 "${SV[@]}" true; check "true exits 0" "$?" 0
timeout 20 "${SV[@]}" false; check "false exits 1" "$?" 1
timeout 20 "${SV[@]}" sh -c 'exit 42'; check "exit 42 is 42" "$?" 42
timeout 20 "${SV[@]}" sh -c 'kill -TERM $$'
check "a program killed by SIGTERM: udpchains dies of it too" "$?" 143
env -u UDPCHAINS_PROXY -u UDPCHAINS_CONFIG HOME="$TMP" timeout 20 "$W" --supervise \
	sh -c 'exit 0' 2> "$TMP/noproxy.err"
check "no proxy configured: refused, as in shim mode" "$?" 1

echo "# the program is supervised, and given no shim (D-49)"
out=$(timeout 20 "${SV[@]}" sh -c 'grep "^Seccomp:" /proc/self/status')
check "the program runs under a seccomp filter" "$out" "$(printf 'Seccomp:\t2')"
if [ "$NO_SHIM" = 1 ]; then
	skip "LD_PRELOAD stripping (NO_SHIM)"
	skip "LD_PRELOAD unset (NO_SHIM)"
	skip "the shim preloaded into udpchains itself (NO_SHIM)"
else
	# The shim also loads into the wrapper itself here, and says it is
	# not configured; that is not what is checked.
	out=$(LD_PRELOAD="$PWD/libudpchains.so:/nonexistent-other.so" timeout 20 "${SV[@]}" \
		sh -c 'echo "[$LD_PRELOAD]"' 2> /dev/null)
	check "libudpchains.so is removed from an inherited LD_PRELOAD, the rest kept" \
		"$out" "[/nonexistent-other.so]"
	out=$(LD_PRELOAD="$PWD/libudpchains.so" timeout 20 "${SV[@]}" \
		sh -c 'echo "[${LD_PRELOAD-unset}]"' 2> /dev/null)
	check "and an LD_PRELOAD of only the shim is unset" "$out" "[unset]"
	# Loaded into the supervisor, the shim would wrap its datagrams to the
	# relay a second time; udpchains runs itself again without it.
	out=$(LD_PRELOAD="$PWD/libudpchains.so" timeout 30 "${SV[@]}" "$P" range "$ECHO" \
		2> /dev/null | grep -c '^not ok')
	check "with the shim in an inherited LD_PRELOAD, UDP is still carried once" "$out" 0
fi
out=$(UDPCHAINS_SUPERVISE=1 timeout 20 "$W" -p "127.0.0.1:$PROXY" \
	sh -c 'grep "^Seccomp:" /proc/self/status; echo "[${UDPCHAINS_SUPERVISE-unset}]"')
check "UDPCHAINS_SUPERVISE=1 chooses it, and is not passed to the program" \
	"$out" "$(printf 'Seccomp:\t2\n[unset]')"
printf 'proxy = 127.0.0.1:%s\nsupervise = yes\n' "$PROXY" > "$TMP/sv.conf"
chmod 600 "$TMP/sv.conf"
out=$(env -u UDPCHAINS_PROXY timeout 20 "$W" -f "$TMP/sv.conf" \
	sh -c 'grep "^Seccomp:" /proc/self/status')
check "supervise = yes in a config file chooses it" "$out" "$(printf 'Seccomp:\t2')"
if [ "$NO_SHIM" = 1 ]; then
	skip "shim mode has no filter (NO_SHIM)"
else
	out=$(timeout 20 "$W" -p "127.0.0.1:$PROXY" sh -c 'grep "^Seccomp:" /proc/self/status')
	check "without it, shim mode as before: no filter" "$out" "$(printf 'Seccomp:\t0')"
fi

echo "# signals sent to udpchains reach the program"
# Not under timeout(1), whose PID $! would then be: the signal must go to
# udpchains itself.  A watchdog ends a run that hangs instead.
signalled() {	# <signal> <program...>
	local sig=$1 pid dog rc
	shift
	"${SV[@]}" "$@" &
	pid=$!
	(sleep 20; kill -KILL "$pid") 2> /dev/null &
	dog=$!
	sleep 0.5
	kill "-$sig" "$pid"
	wait "$pid"
	rc=$?
	kill "$dog" 2> /dev/null
	return $rc
}
signalled TERM sleep 30
check "SIGTERM to udpchains ends the program, and udpchains with it" "$?" 143
signalled USR1 sh -c 'trap "exit 7" USR1; while :; do sleep 0.1; done'
check "a signal the program handles is delivered to it (exit 7 from its handler)" "$?" 7

echo "# signals during a traced call (FR-SV-T4, D-54)"
timeout 120 "${SV[@]}" "$P" signals "$DELAYED" "$ECHO" > "$TMP/signals.tap" 2> /dev/null
rc=$?
sed 's/^/#   /' "$TMP/signals.tap"
check "test_supervise signals passes, -static" "$rc" 0
UDPCHAINS_CONNECT_TIMEOUT=1000 timeout 30 "$W" --supervise -p "127.0.0.1:$SILENT" \
	"$P" abandon "$ECHO" > "$TMP/abandon.tap" 2> /dev/null
rc=$?
sed 's/^/#   /' "$TMP/abandon.tap"
check "test_supervise abandon passes, -static" "$rc" 0
# SIGTERM to udpchains is passed to the program while its send waits for the
# silent proxy; the setup is abandoned, and the program dies at once rather
# than after connect_timeout.
start=$(date +%s%N)
UDPCHAINS_CONNECT_TIMEOUT=10000 "$W" --supervise -p "127.0.0.1:$SILENT" \
	"$P" abandon "$ECHO" > /dev/null 2>&1 &
pid=$!
(sleep 20; kill -KILL "$pid") 2> /dev/null &
dog=$!
sleep 0.15
kill -TERM "$pid"
wait "$pid"
rc=$?
kill "$dog" 2> /dev/null
elapsed=$((($(date +%s%N) - start) / 1000000))
check "SIGTERM during a hung association setup ends the program" "$rc" 143
[ "$elapsed" -lt 2000 ] && ok "at once (${elapsed} ms), not after connect_timeout" ||
	notok "only after ${elapsed} ms"

echo "# fail-closed: the program dies with the supervisor (FR-SV-13, D-54)"
"${SV[@]}" "$P" churn "$ECHO" 1 30 > /dev/null 2>&1 &
pid=$!
for ((i = 0; i < 100; i++)); do
	prog=$(pgrep -P "$pid" -x test_supervise)
	[ -n "$prog" ] && break
	sleep 0.05
done
kill -KILL "$pid"
wait "$pid" 2> /dev/null
for ((i = 0; i < 40; i++)); do
	[ -n "$prog" ] && [ -e "/proc/$prog" ] || break
	sleep 0.05
done
[ -n "$prog" ] && [ ! -e "/proc/$prog" ] &&
	ok "udpchains killed: its program is killed with it (PTRACE_O_EXITKILL)" ||
	notok "the program (${prog:-not found}) outlived its supervisor"
# LeakSanitizer, in a sanitiser build of udpchains, cannot run under ptrace;
# here udpchains is traced by strace.
NOLEAK="${ASAN_OPTIONS:+$ASAN_OPTIONS:}detect_leaks=0"
if command -v strace > /dev/null; then
	out=$(ASAN_OPTIONS="$NOLEAK" timeout 30 strace -f -o /dev/null "${SV[@]}" \
		/bin/echo PROGRAM-RAN 2>&1)
	rc=$?
	case $out in
	*PROGRAM-RAN*) notok "the program ran under strace -f, unsupervised" ;;
	*"cannot trace the program"*) check "under strace -f, refused to start (D-54)" "$rc" 1 ;;
	*) notok "under strace -f: $out" ;;
	esac
else
	skip "refusal under strace -f (no strace)"
fi

echo "# the supervisor stays for descendants the program leaves running (FR-SV-11)"
start=$(date +%s%N)
timeout 30 "${SV[@]}" sh -c \
	'(sleep 1; grep "^Seccomp:" /proc/self/status > "$0") &' "$TMP/late"
elapsed=$((($(date +%s%N) - start) / 1000000))
[ "$elapsed" -ge 900 ] && ok "udpchains waited for the orphaned descendant (${elapsed} ms)" ||
	notok "udpchains returned after ${elapsed} ms, before its descendant"
check "and the descendant was supervised" "$(cat "$TMP/late" 2> /dev/null)" \
	"$(printf 'Seccomp:\t2')"

echo "# a static program: refusals, and what still runs (D-48, D-50, D-53)"
timeout 30 "${SV[@]}" "$P" refusals "$PROXY" > "$TMP/refusals.tap" 2> "$TMP/refusals.err"
rc=$?
sed 's/^/#   /' "$TMP/refusals.tap"
check "test_supervise refusals passes, -static" "$rc" 0
for what in "ICMP" "raw and packet" "io_uring" "pidfd_getfd"; do
	grep -q "$what" "$TMP/refusals.err" && ok "a diagnostic for $what, not hidden by another" ||
		notok "no diagnostic mentioning $what"
done

echo "# a process the supervisor cannot inspect fails closed (D-48)"
timeout 30 "${SV[@]}" "$P" nodump "$PROXY" > "$TMP/nodump.tap" 2> "$TMP/nodump.err"
rc=$?
sed 's/^/#   /' "$TMP/nodump.tap"
check "test_supervise nodump passes, -static" "$rc" 0
grep -q "cannot be inspected: it has made itself non-dumpable" "$TMP/nodump.err" &&
	ok "the refusal names the cause" || notok "no diagnostic naming non-dumpable"

echo "# a static program's UDP, carried (D-50, D-51, FR-SV-04)"
# -v: the association line is information, which run.sh's UDPCHAINS_QUIET hides.
timeout 60 "${SV[@]}" -v "$P" range "$ECHO" > "$TMP/range.tap" 2> "$TMP/range.err"
rc=$?
sed 's/^/#   /' "$TMP/range.tap"
check "test_supervise range passes, -static" "$rc" 0
grep -q "association up: process [0-9]* fd 768 " "$TMP/range.err" &&
	ok "the association is reported, naming the process and descriptor (FR-C-06)" ||
	notok "no association line for fd 768"
grep -q "dup2 refused" "$TMP/range.err" && ok "the refused dup2 says why" ||
	notok "no diagnostic for the refused dup2"

echo "# the supervisor lets go of sockets the program has closed"
timeout 60 "${SV[@]}" "$P" churn "$ECHO" 40 6 > "$TMP/churn.out" 2> "$TMP/churn.err" &
churn=$!
PIDS+=($churn)
for ((i = 0; i < 200; i++)); do
	grep -q CHURNED "$TMP/churn.out" 2> /dev/null && break
	sleep 0.05
done
check "40 sockets made, used and closed" "$(cat "$TMP/churn.out")" "CHURNED 40 of 40"
sleep 1
# timeout(1) runs udpchains as its child; the supervisor's own descriptors are
# the listener, the signals, a process descriptor and stdio.
svpid=$(pgrep -P "$churn" -x udpchains)
nfd=$(ls "/proc/$svpid/fd" 2> /dev/null | wc -l)
[ -n "$svpid" ] && [ "$nfd" -le 8 ] &&
	ok "within a second, no control connection is left open ($nfd descriptors)" ||
	notok "the supervisor still holds $nfd descriptors"
wait "$churn"
check "and the program exits 0" "$?" 0

echo "# fail-closed: with the proxy down, nothing is sent (SEC-01)"
before=$(echoed)
# A sanitiser build's leakclient cannot run LeakSanitizer once supervised, as
# it traces its own threads (D-54); udpchains keeps its own.
for client in "$B/leakclient-static" "$B/leakclient"; do
	out=$(timeout 60 "$W" --supervise -p "127.0.0.1:$DEAD" \
		env ASAN_OPTIONS="$NOLEAK" "$client" 127.0.0.1 "$ECHO" 2> /dev/null)
	check "$(basename "$client"): every send fails" \
		"$(echo "$out" | sed -n 's/.*sent_ok=\([0-9]*\).*/\1/p')" 0
done
sleep 0.3
check "and nothing reached the destination" "$(echoed)" "$before"
out=$(timeout 60 "${SV[@]}" "$B/leakclient-static" 127.0.0.1 "$ECHO" 2> /dev/null)
sent=$(echo "$out" | sed -n 's/.*sent_ok=\([0-9]*\).*/\1/p')
[ "${sent:-0}" -gt 20 ] && ok "with the proxy up, the same sends are carried ($sent)" ||
	notok "with the proxy up, only ${sent:-0} sends were carried"

echo "# a UDP socket received from an unsupervised process (D-50)"
"$P" pass "$TMP/u.sock" "$ECHO" > "$TMP/pass.out" 2>&1 &
PIDS+=($!)
for ((i = 0; i < 100; i++)); do
	grep -q READY "$TMP/pass.out" 2> /dev/null && break
	sleep 0.05
done
before=$(echoed)
timeout 30 "${SV[@]}" "$P" received "$TMP/u.sock" > "$TMP/received.tap" 2> /dev/null
rc=$?
sed 's/^/#   /' "$TMP/received.tap"
check "test_supervise received passes" "$rc" 0
sleep 0.3
check "only the documented write() gap reached the destination, 1 byte" \
	"$(($(echoed) - before))" 1

echo "# an inherited UDP socket stops the program from starting (D-50)"
exec 5<> "/dev/udp/127.0.0.1/$ECHO"
out=$(timeout 20 "${SV[@]}" /bin/echo PROGRAM-RAN 2>&1)
rc=$?
exec 5>&-
check "refused" "$rc" 1
case $out in
*PROGRAM-RAN*) notok "THE PROGRAM RAN with an inherited UDP socket" ;;
*"descriptor 5"*) ok "naming the descriptor, and the program never ran" ;;
*) notok "refused without naming the descriptor: $out" ;;
esac

echo "1..$n"
exit $fail

#!/bin/bash
# run_sanitizers.sh -- TST-08.
#
# TST-08 asks for the suite under ASan/UBSan and Valgrind.  Which tool covers
# which part is not arbitrary, and the reason is worth recording.
#
# ---------------------------------------------------------------------------
# Why ASan cannot run the LD_PRELOAD integration tests
# ---------------------------------------------------------------------------
#
# ASan installs its own interceptors for read(), recv() and recvfrom() -- but
# not for readv(), recvmsg() or recvmmsg().  Each interceptor forwards to the
# "real" function it resolved with dlsym(RTLD_NEXT) from libasan's own position
# in the link map.  The shim interposes those same three symbols by being in
# LD_PRELOAD.  Two interception mechanisms, one slot:
#
#   shim before libasan: ASan's RTLD_NEXT search starts after the shim and
#                        lands on libc, so the shim's hooks never run.
#   libasan before shim: ASan still forwards past the shim to libc.
#
# Either way the application gets its payload back with the 10-byte SOCKS
# header still attached, and exactly the read/recv/recvfrom column of the hook
# matrix fails -- 54 of 108 cells.  That is the harness manufacturing the very
# FR-I-02 defect the matrix exists to detect, not a defect in the shim.  Do not
# "fix" it by loosening the matrix.
#
# So the work is split by what each tool can actually see:
#
#   ASan + UBSan   the unit tests, which LINK the shim's objects directly and
#                  never involve LD_PRELOAD.  Full memory and undefined-
#                  behaviour checking of the header codec, address handling and
#                  configuration parsing.
#
#   Valgrind       the integration tests under the real preloaded shim.
#                  Valgrind runs the program on a synthetic CPU rather than by
#                  interposing symbols, so the shim's hooks run exactly as they
#                  do in production and the whole hook/core/fdtable/assoc path
#                  is covered.
#
#   TSan           the fd table itself, via tests/test_fdtable_mt.c, which
#                  LINKS the table directly instead of preloading the shim.
#                  TSan has the same interception conflict as ASan, but linking
#                  sidesteps it -- and TSan is the only tool here that models
#                  C11 atomics, so it is the only one that can say anything
#                  meaningful about the lock-free design D-07 chose.  It found a
#                  real race on the entry family/type fields, since fixed.
#
#   Helgrind       lock ordering and pthread API misuse under the real preloaded
#                  shim.  Helgrind does NOT model C11 atomics and reports every
#                  atomic access as a possible race, so tests/helgrind.supp
#                  silences that noise; see the comments in that file.
#
# usage: tests/run_sanitizers.sh [asan|tsan|valgrind|helgrind|all]

set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD="$ROOT/build"
MODE="${1:-all}"
OVERALL=0

TMP=""
PIDS=()
PROXY=""
ECHO1=""
ECHO2=""
ECHO6=""

stop_fixtures() {
	local pid
	for pid in "${PIDS[@]:-}"; do
		[ -n "$pid" ] && kill "$pid" 2>/dev/null
	done
	PIDS=()
}

cleanup() {
	stop_fixtures
	[ -n "$TMP" ] && [ -z "${KEEP_TMP:-}" ] && rm -rf "$TMP"
	return 0
}
trap cleanup EXIT

banner() {
	echo
	echo "=============================================================="
	echo "  $1"
	echo "=============================================================="
}

start_fixtures() {
	TMP=$(mktemp -d)
	"$BUILD/socks5d" --port 0 --quiet > "$TMP/proxy.out" 2>&1 &
	PIDS+=($!)
	# A second hop, for the chained runs (FR-CH-T2).
	"$BUILD/socks5d" --port 0 --quiet > "$TMP/proxy2.out" 2>&1 &
	PIDS+=($!)
	"$BUILD/udpecho" --port 0 --quiet > "$TMP/e1.out" 2>&1 &
	PIDS+=($!)
	# A SECOND IPv4 echo server, distinct from the first.  test_fidelity's
	# connected-peer filter (D-15) provokes a reply from an address the
	# socket is NOT connected to; with one server passed twice the
	# "stranger" IS the connected peer, its reply is correctly delivered,
	# and the test fails while the shim is behaving perfectly.
	# test_lifecycle likewise connects to two different peers.
	"$BUILD/udpecho" --port 0 --quiet > "$TMP/e2.out" 2>&1 &
	PIDS+=($!)
	"$BUILD/udpecho" --port 0 -6 --quiet > "$TMP/e6.out" 2>&1 &
	PIDS+=($!)
	# The D-22 resolver's test zone.
	"$BUILD/dnsd" --port 0 --quiet > "$TMP/dns.out" 2>&1 &
	PIDS+=($!)

	local i
	for ((i = 0; i < 200; i++)); do
		PROXY=$(awk '/^PORT/{print $2; exit}' "$TMP/proxy.out" 2>/dev/null)
		PROXY2=$(awk '/^PORT/{print $2; exit}' "$TMP/proxy2.out" 2>/dev/null)
		ECHO1=$(awk '/^PORT/{print $2; exit}' "$TMP/e1.out" 2>/dev/null)
		ECHO2=$(awk '/^PORT/{print $2; exit}' "$TMP/e2.out" 2>/dev/null)
		ECHO6=$(awk '/^PORT/{print $2; exit}' "$TMP/e6.out" 2>/dev/null)
		DNS=$(awk '/^PORT/{print $2; exit}' "$TMP/dns.out" 2>/dev/null)
		[ -n "$PROXY" ] && [ -n "$PROXY2" ] && [ -n "$ECHO1" ] && [ -n "$ECHO2" ] &&
			[ -n "$ECHO6" ] && [ -n "$DNS" ] && return 0
		sleep 0.05
	done
	echo "FATAL: fixtures did not start" >&2
	return 1
}

# A test counts as failed if it exits non-zero OR if the tool reported anything,
# even when every assertion passed.  A clean run with a leak is not a pass.
report() {
	local name=$1 out=$2 rc=$3
	local findings=0

	if grep -qE "(ERROR: (Address|Leak|Thread)Sanitizer|runtime error:|Invalid (read|write|free)|Conditional jump|uninitialised|Syscall param|bytes in [0-9,]+ blocks are (definitely|indirectly) lost|Possible data race)" \
		"$out" 2>/dev/null; then
		findings=1
	fi

	grep -E "^(1\.\.|# FAILED)" "$out" 2>/dev/null | head -2

	if [ "$rc" -ne 0 ] || [ "$findings" -ne 0 ]; then
		echo "--- $name: FAIL (exit $rc)" >&2
		grep -E "(^not ok|ERROR:|runtime error:|Invalid |Conditional |uninitialised|lost|Possible data race)" \
			"$out" 2>/dev/null | head -15 >&2
		OVERALL=1
	else
		echo "--- $name: PASS"
	fi
}

# --- ASan + UBSan on the unit tests ------------------------------------------

run_asan() {
	banner "TST-08: ASan + UBSan (unit tests -- no LD_PRELOAD involved)"

	make -C "$ROOT" clean > /dev/null 2>&1
	if ! make -C "$ROOT" ASAN=1 all fixtures tests > "$ROOT/build-asan.log" 2>&1; then
		echo "not ok - ASan build failed; see build-asan.log" >&2
		OVERALL=1
		return
	fi

	TMP=$(mktemp -d)
	export ASAN_OPTIONS="detect_leaks=1:abort_on_error=0:exitcode=99"
	export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0:exitcode=99"

	local t rc
	for t in test_addr test_config test_socks5 test_chain test_dns \
		test_supervise_unit; do
		echo "--- $t"
		"$BUILD/$t" > "$TMP/$t.out" 2>&1
		rc=$?
		report "$t" "$TMP/$t.out" "$rc"
	done

	# The supervisor (D-48) lives in the wrapper, built with the sanitisers
	# here; the programs it runs are not.
	echo "--- supervisor"
	NO_SHIM=1 "$ROOT/tests/test_supervise.sh" "$ROOT/udpchains" "$BUILD" > "$TMP/sv.out" 2>&1
	rc=$?
	report "supervisor" "$TMP/sv.out" "$rc"

	unset ASAN_OPTIONS UBSAN_OPTIONS
	rm -rf "$TMP"; TMP=""
}

# --- TSan on the fd table ----------------------------------------------------

run_tsan() {
	banner "TST-08: ThreadSanitizer (fd table -- the D-07 lock-free design)"

	make -C "$ROOT" clean > /dev/null 2>&1
	if ! make -C "$ROOT" TSAN=1 build/test_fdtable_mt > "$ROOT/build-tsan.log" 2>&1; then
		echo "not ok - TSan build failed; see build-tsan.log" >&2
		OVERALL=1
		return
	fi

	TMP=$(mktemp -d)
	export TSAN_OPTIONS="halt_on_error=0:exitcode=99"

	# TSan's shadow-memory layout collides with the ASLR entropy on recent
	# kernels ("unexpected memory mapping"), so randomisation is disabled for
	# this run only.
	local rc
	echo "--- test_fdtable_mt"
	setarch "$(uname -m)" -R "$BUILD/test_fdtable_mt" > "$TMP/tsan.out" 2>&1
	rc=$?
	report test_fdtable_mt "$TMP/tsan.out" "$rc"

	unset TSAN_OPTIONS
	rm -rf "$TMP"; TMP=""
}

# --- Valgrind memcheck on the integration tests ------------------------------

run_valgrind() {
	banner "TST-08: Valgrind memcheck (integration tests, real preloaded shim)"

	if ! command -v valgrind > /dev/null 2>&1; then
		echo "# SKIP valgrind -- not installed" >&2
		return
	fi

	make -C "$ROOT" clean > /dev/null 2>&1
	make -C "$ROOT" all fixtures tests > /dev/null 2>&1
	start_fixtures || { OVERALL=1; return; }

	export UDPCHAINS_PROXY="127.0.0.1:$PROXY"
	export UDPCHAINS_QUIET=1

	local rc
	local -a VG=(valgrind --error-exitcode=99 --leak-check=full
	             --show-leak-kinds=definite --track-origins=yes --quiet)

	echo "--- matrix"
	LD_PRELOAD="$ROOT/libudpchains.so" "${VG[@]}" \
		"$BUILD/test_matrix" "$ECHO1" "$ECHO6" > "$TMP/vg_matrix.out" 2>&1
	rc=$?
	report matrix "$TMP/vg_matrix.out" "$rc"

	echo "--- fidelity"
	LD_PRELOAD="$ROOT/libudpchains.so" "${VG[@]}" \
		"$BUILD/test_fidelity" "$ECHO1" "$ECHO2" "$ECHO6" \
		> "$TMP/vg_fidelity.out" 2>&1
	rc=$?
	report fidelity "$TMP/vg_fidelity.out" "$rc"

	echo "--- lifecycle"
	LD_PRELOAD="$ROOT/libudpchains.so" "${VG[@]}" \
		"$BUILD/test_lifecycle" "$ECHO1" "$ECHO2" > "$TMP/vg_life.out" 2>&1
	rc=$?
	report lifecycle "$TMP/vg_life.out" "$rc"

	# FR-CH-T2: the chain codec and the n-hop association, under memcheck.
	echo "--- matrix, 2 hops"
	UDPCHAINS_PROXY="127.0.0.1:$PROXY,127.0.0.1:$PROXY2" \
	LD_PRELOAD="$ROOT/libudpchains.so" "${VG[@]}" \
		"$BUILD/test_matrix" "$ECHO1" "$ECHO6" > "$TMP/vg_matrix2.out" 2>&1
	rc=$?
	report "matrix, 2 hops" "$TMP/vg_matrix2.out" "$rc"

	echo "--- lifecycle, 2 hops"
	UDPCHAINS_PROXY="127.0.0.1:$PROXY,127.0.0.1:$PROXY2" \
	LD_PRELOAD="$ROOT/libudpchains.so" "${VG[@]}" \
		"$BUILD/test_lifecycle" "$ECHO1" "$ECHO2" > "$TMP/vg_life2.out" 2>&1
	rc=$?
	report "lifecycle, 2 hops" "$TMP/vg_life2.out" "$rc"

	# D-22: the resolver -- its pool, both transports and every hook --
	# under the real preloaded shim.  The timeout is raised because
	# Valgrind runs everything an order of magnitude slower.
	echo "--- resolve"
	printf '127.0.0.1\tlocalhost\n203.0.113.5\thostsonly.test\n' > "$TMP/hosts"
	UDPCHAINS_DNS="127.0.0.1:$DNS" UDPCHAINS_DNS_SEARCH=search.test \
	UDPCHAINS_DNS_TIMEOUT=20000 UDPCHAINS_HOSTS_FILE="$TMP/hosts" \
	LD_PRELOAD="$ROOT/libudpchains.so" "${VG[@]}" \
		"$BUILD/test_resolve" main > "$TMP/vg_resolve.out" 2>&1
	rc=$?
	report resolve "$TMP/vg_resolve.out" "$rc"

	# FR-CH-11: the pool holding a control connection per hop, and the
	# TCP fallback's CONNECT tunnelled through the chain.
	echo "--- resolve, 2 hops"
	UDPCHAINS_PROXY="127.0.0.1:$PROXY,127.0.0.1:$PROXY2" \
	UDPCHAINS_DNS="127.0.0.1:$DNS" UDPCHAINS_DNS_SEARCH=search.test \
	UDPCHAINS_DNS_TIMEOUT=20000 UDPCHAINS_HOSTS_FILE="$TMP/hosts" \
	LD_PRELOAD="$ROOT/libudpchains.so" "${VG[@]}" \
		"$BUILD/test_resolve" main > "$TMP/vg_resolve2.out" 2>&1
	rc=$?
	report "resolve, 2 hops" "$TMP/vg_resolve2.out" "$rc"

	stop_fixtures
	unset UDPCHAINS_PROXY UDPCHAINS_QUIET
}

# --- Helgrind on the threaded stress test ------------------------------------

run_helgrind() {
	banner "TST-08: Helgrind (threaded stress -- the D-07 lock-free fd table)"

	if ! command -v valgrind > /dev/null 2>&1; then
		echo "# SKIP helgrind -- valgrind not installed" >&2
		return
	fi

	make -C "$ROOT" clean > /dev/null 2>&1
	make -C "$ROOT" all fixtures tests > /dev/null 2>&1
	start_fixtures || { OVERALL=1; return; }

	export UDPCHAINS_PROXY="127.0.0.1:$PROXY"
	export UDPCHAINS_QUIET=1

	local rc
	echo "--- thread"
	LD_PRELOAD="$ROOT/libudpchains.so" \
		valgrind --tool=helgrind --error-exitcode=99 --quiet \
		--suppressions="$ROOT/tests/helgrind.supp" \
		"$BUILD/test_thread" "$ECHO1" > "$TMP/hg_thread.out" 2>&1
	rc=$?
	report thread "$TMP/hg_thread.out" "$rc"

	echo "--- thread, 2 hops"
	UDPCHAINS_PROXY="127.0.0.1:$PROXY,127.0.0.1:$PROXY2" \
	LD_PRELOAD="$ROOT/libudpchains.so" \
		valgrind --tool=helgrind --error-exitcode=99 --quiet \
		--suppressions="$ROOT/tests/helgrind.supp" \
		"$BUILD/test_thread" "$ECHO1" > "$TMP/hg_thread2.out" 2>&1
	rc=$?
	report "thread, 2 hops" "$TMP/hg_thread2.out" "$rc"

	stop_fixtures
	unset UDPCHAINS_PROXY UDPCHAINS_QUIET
}

case "$MODE" in
asan) run_asan ;;
tsan) run_tsan ;;
valgrind) run_valgrind ;;
helgrind) run_helgrind ;;
all)
	run_asan
	run_tsan
	run_valgrind
	run_helgrind
	;;
*)
	echo "usage: run_sanitizers.sh [asan|tsan|valgrind|helgrind|all]" >&2
	exit 2
	;;
esac

# Leave the tree uninstrumented.
make -C "$ROOT" clean > /dev/null 2>&1
make -C "$ROOT" all fixtures tests > /dev/null 2>&1

echo
if [ "$OVERALL" -eq 0 ]; then
	echo "# TST-08 passed"
else
	echo "# TST-08 FAILED" >&2
fi
exit $OVERALL

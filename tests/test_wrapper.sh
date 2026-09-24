#!/bin/sh
# test_wrapper.sh -- the wrapper refuses to exec when the shim cannot be LOADED.
#
# find_shim() proves the shim is readable.  Readable is not loadable, and the
# difference is a silent leak: if ld.so cannot map the object it prints one
# warning and runs the program ANYWAY, unproxied.  That is the outcome SEC-06
# already refuses for setuid binaries -- LD_PRELOAD ignored, traffic direct --
# reached by a different route.
#
# Each case below asserts two things, and the second matters more than the
# first: the wrapper exits non-zero, AND the target program never runs.  A
# diagnostic followed by an unproxied execution would still be a leak.
#
# usage: test_wrapper.sh <wrapper> <shim>
set -eu

WRAPPER="${1:-./udpchains}"
SHIM="${2:-libudpchains.so}"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

fail=0
n=0

# Runs the wrapper with UDPCHAINS_LIB set to $1 and asserts it refuses.
refuses() {
	lib=$1
	what=$2
	out=$(UDPCHAINS_LIB="$lib" "$WRAPPER" -p 127.0.0.1:1080 \
		/bin/echo TARGET-RAN 2>&1) && rc=0 || rc=$?

	n=$((n + 1))
	if [ "$rc" -eq 0 ]; then
		echo "not ok $n - $what: wrapper exited 0"
		fail=1
	else
		echo "ok $n - $what: wrapper refuses (exit $rc)"
	fi

	n=$((n + 1))
	if printf '%s' "$out" | grep -q TARGET-RAN; then
		echo "not ok $n - $what: THE TARGET RAN ANYWAY -- unproxied leak"
		fail=1
	else
		echo "ok $n - $what: the target never ran"
	fi
}

echo "# the shim must be loadable, not merely readable"

# Not an ELF object at all: a truncated or interrupted copy.
head -c 100 /dev/urandom > "$TMP/junk.so"
refuses "$TMP/junk.so" "non-ELF shim"

# Zero-length, the degenerate form of the same thing.
: > "$TMP/empty.so"
refuses "$TMP/empty.so" "empty shim"

# Built for another architecture: e_machine at offset 18 is overwritten with a
# value no host will match.  This is what copying a build between hosts does.
cp "$SHIM" "$TMP/wrongarch.so"
printf '\376\377' | dd of="$TMP/wrongarch.so" bs=1 seek=18 conv=notrunc status=none
refuses "$TMP/wrongarch.so" "wrong-architecture shim"

# The control: an intact shim must still run the target.
n=$((n + 1))
if out=$(UDPCHAINS_LIB="$SHIM" "$WRAPPER" -p 127.0.0.1:1080 \
	/bin/echo TARGET-RAN 2>&1) && printf '%s' "$out" | grep -q TARGET-RAN; then
	echo "ok $n - a valid shim still runs the target"
else
	echo "not ok $n - a valid shim FAILED to run the target: $out"
	fail=1
fi

# --- D-27: the shim takes the wrapper's configuration, and only that ---------

check() {
	n=$((n + 1))
	if [ "$1" = "$2" ]; then
		echo "ok $n - $3"
	else
		echo "not ok $n - $3 (got '$1', want '$2')"
		fail=1
	fi
}

echo "# the shim takes its configuration from the wrapper alone (D-27)"

# A broken ~/.udpchains.conf, and a run whose -f names a good file.  The
# wrapper reads only the good one.  The shim used to read the home file as well,
# and reported itself unconfigured -- after the wrapper had said all was well.
mkdir -p "$TMP/home"
printf 'this line is not key = value at all\n' > "$TMP/home/.udpchains.conf"
printf 'proxy = 127.0.0.1:1080\n' > "$TMP/good.conf"
chmod 600 "$TMP/good.conf"
out=$(HOME="$TMP/home" UDPCHAINS_LIB="$SHIM" "$WRAPPER" -f "$TMP/good.conf" \
	/bin/echo TARGET-RAN 2>&1) || true
check "$(printf '%s' "$out" | grep -c 'not configured')" "0" \
	"a broken home config file does not reach the shim when -f names another"
check "$(printf '%s' "$out" | grep -c TARGET-RAN)" "1" "and the target runs"

# The proxy is exported as the address the wrapper resolved, so no process
# under the shim looks the name up again, directly.
out=$(UDPCHAINS_LIB="$SHIM" "$WRAPPER" -q -p localhost:1080 /usr/bin/env 2>&1) || true
exported=$(printf '%s\n' "$out" | sed -n 's/^UDPCHAINS_PROXY=//p')
case "$exported" in
127.0.0.1:1080 | "[::1]:1080") ok_num=yes ;;
*) ok_num="no ($exported)" ;;
esac
check "$ok_num" "yes" "a proxy named 'localhost' is exported as its address"
check "$(printf '%s\n' "$out" | grep -c '^UDPCHAINS_RESOLVED=1$')" "1" \
	"and the environment is marked as resolved"

# --- D-28: the wrapper runs the file it checked -------------------------------

echo "# the wrapper execs the file it checked (D-28)"

# execv() rather than execvp() must keep execvp's one extra: a script with no
# #! line runs under /bin/sh.
mkdir -p "$TMP/bin"
printf 'echo NOSHEBANG-RAN "$1"\n' > "$TMP/bin/noshebang"
chmod 755 "$TMP/bin/noshebang"
out=$(PATH="$TMP/bin:$PATH" UDPCHAINS_LIB="$SHIM" "$WRAPPER" -q \
	-p 127.0.0.1:1080 noshebang arg1 2>&1) || true
check "$out" "NOSHEBANG-RAN arg1" "a script with no #! line still runs, with its arguments"

# NOTE: the noexec / security-policy case exercises the same refusal through the
# PROT_EXEC probe, and is not covered here because creating a noexec mount needs
# either root or unprivileged user namespaces, neither of which a test run can
# assume.  Verify it by hand with:
#   mount -t tmpfs -o noexec tmpfs /mnt && cp libudpchains.so /mnt/
#   UDPCHAINS_LIB=/mnt/libudpchains.so ./udpchains -p ... /bin/echo SHOULD-NOT-RUN

echo "1..$n"
[ "$fail" -eq 0 ] || exit 1

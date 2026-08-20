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

# NOTE: the noexec / security-policy case exercises the same refusal through the
# PROT_EXEC probe, and is not covered here because creating a noexec mount needs
# either root or unprivileged user namespaces, neither of which a test run can
# assume.  Verify it by hand with:
#   mount -t tmpfs -o noexec tmpfs /mnt && cp libudpchains.so /mnt/
#   UDPCHAINS_LIB=/mnt/libudpchains.so ./udpchains -p ... /bin/echo SHOULD-NOT-RUN

echo "1..$n"
[ "$fail" -eq 0 ] || exit 1

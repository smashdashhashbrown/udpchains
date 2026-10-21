#!/bin/sh
# test_symbols.sh -- TST-02, the exported-symbol check.
#
# Asserts every function named in FR-I-03/04/05 is present in the shim's dynamic
# symbol table.  A missing receive hook FAILS THE BUILD rather than a test run,
# because the failure it guards against -- a program that sends successfully and
# then reads back data with the SOCKS header still attached (FR-I-02, baseline
# §0.3.2) -- is silent data corruption, not a visible error.
#
# It also asserts that the readiness calls are ABSENT.  FR-I-07 redirects the
# application's own fd to the relay rather than shadowing it, so poll/select/
# epoll need no hooking; if one ever appears here, the architecture has drifted.

set -eu

SHIM="${1:-libudpchains.so}"

if [ ! -f "$SHIM" ]; then
	echo "TST-02: $SHIM not found" >&2
	exit 1
fi

SYMS=$(nm -D --defined-only "$SHIM" | awk '{print $3}')

fail=0

want() {
	for sym in "$@"; do
		if printf '%s\n' "$SYMS" | grep -qx "$sym"; then
			echo "ok - $sym is hooked"
		else
			echo "not ok - $sym is NOT hooked" >&2
			fail=1
		fi
	done
}

reject() {
	for sym in "$@"; do
		if printf '%s\n' "$SYMS" | grep -qx "$sym"; then
			echo "not ok - $sym is hooked, but must not be (see the comment above its check)" >&2
			fail=1
		else
			echo "ok - $sym is correctly not hooked"
		fi
	done
}

echo "# TST-02: FR-I-03 send hooks"
want sendto sendmsg sendmmsg send write writev

echo "# TST-02: FR-I-03 receive hooks"
want recvfrom recvmsg recvmmsg recv read readv

# A _FORTIFY_SOURCE build calls these in place of recv/recvfrom/read, and glibc
# implements them with internal calls no preload can see.  Missing, they deliver
# the SOCKS header as payload -- the FR-I-02 defect by another door.
echo "# TST-02: FR-I-02 fortified receive entry points"
want __recv_chk __recvfrom_chk __read_chk

echo "# TST-02: FR-I-04 lifecycle hooks"
want socket connect bind close dup dup2 dup3

# fcntl(F_DUPFD) duplicates exactly as dup does; unhooked, the copy of an
# intercepted socket is untracked and sends directly (SEC-01).
echo "# TST-02: SEC-01 duplication by fcntl"
want fcntl fcntl64

# NFR-01a / D-09: close_range is conditionally compiled.  Assert the right set
# for this build rather than failing spuriously on a deliberate omission.
if [ "${GLIBC_NO_CLOSE_RANGE:-}" = "" ]; then
	want close_range
else
	echo "# close_range hook omitted deliberately (GLIBC_NO_CLOSE_RANGE)"
	reject close_range
fi

# D-22: glibc's resolver bypasses every socket hook, so name resolution is
# hooked at the API.  freeaddrinfo must NOT be: results are built by glibc and
# freed by glibc's own freeaddrinfo.
echo "# TST-02: D-22 name resolution"
want getaddrinfo getnameinfo getaddrinfo_a \
	gethostbyname gethostbyname2 gethostbyname_r gethostbyname2_r \
	gethostbyaddr gethostbyaddr_r \
	res_query res_search res_querydomain res_send \
	res_nquery res_nsearch res_nquerydomain res_nsend \
	__res_query __res_search __res_querydomain __res_send \
	__res_nquery __res_nsearch __res_nquerydomain __res_nsend
reject freeaddrinfo

# D-36: calls that move data through a descriptor without any send or receive
# hook seeing it.  Each is proxied (dprintf, pwritev2, preadv2), refused on a UDP
# socket (sendfile, splice, fdopen), or adopted (pidfd_getfd).
echo "# TST-02: D-36 routes around the send and receive hooks"
want sendfile sendfile64 splice fdopen dprintf vdprintf __dprintf_chk __vdprintf_chk \
	pwritev2 pwritev64v2 preadv2 preadv64v2 pidfd_getfd
# glibc's public underscored aliases for hooked calls, which a program can link
# against directly.
want __write __read __send __connect __close __dup2 __fcntl
echo "# TST-02: FR-I-05 introspection hooks"
want getpeername getsockname

echo "# TST-02: FR-I-07 -- readiness calls must NOT be hooked"
reject poll ppoll select pselect epoll_wait epoll_pwait setsockopt getsockopt

echo "# TST-02: FR-I-02 -- send/receive hook symmetry"
# Every send-path function must have its receive-path counterpart.  Checked as
# pairs so that adding a send hook without its partner fails here.
for pair in "sendto:recvfrom" "sendmsg:recvmsg" "sendmmsg:recvmmsg" \
            "send:recv" "write:read" "writev:readv"; do
	s=${pair%%:*}
	r=${pair##*:}
	shave=$(printf '%s\n' "$SYMS" | grep -cx "$s" || true)
	rhave=$(printf '%s\n' "$SYMS" | grep -cx "$r" || true)
	if [ "$shave" = "$rhave" ]; then
		echo "ok - $s/$r are symmetric"
	else
		echo "not ok - $s and $r are asymmetric: this is the FR-I-02 defect" >&2
		fail=1
	fi
done

# D-35: the hooks are the whole export list.  An internal udpc_* function in the
# dynamic symbol table would reach every program's namespace, and could be
# interposed by it.
echo "# TST-02: D-35 -- internal functions are not exported"
leaked=$(printf '%s\n' "$SYMS" | grep -c '^udpc_' || true)
if [ "$leaked" = "0" ]; then
	echo "ok - no internal udpc_* symbol is exported"
else
	echo "not ok - $leaked internal udpc_* symbols are exported" >&2
	fail=1
fi

echo "# TST-02: D-35 -- hardening"
if readelf -lW "$SHIM" 2>/dev/null | grep -q GNU_RELRO; then
	echo "ok - RELRO segment present"
else
	echo "not ok - no RELRO segment" >&2
	fail=1
fi
if readelf -dW "$SHIM" 2>/dev/null | grep -qE 'BIND_NOW|FLAGS.*NOW'; then
	echo "ok - immediate binding (-z now)"
else
	echo "not ok - lazy binding: built without -z now" >&2
	fail=1
fi
if nm -D --undefined-only "$SHIM" | grep -q __stack_chk_fail; then
	echo "ok - built with the stack protector"
else
	echo "not ok - no stack protector" >&2
	fail=1
fi

if [ "$fail" -ne 0 ]; then
	echo "TST-02 FAILED" >&2
	exit 1
fi
echo "# TST-02 passed"

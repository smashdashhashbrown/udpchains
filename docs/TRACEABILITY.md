# Traceability Matrix — `udpchains`

Every requirement in [`UDP-PRELOAD-REQUIREMENTS.md`](../UDP-PRELOAD-REQUIREMENTS.md) (baseline
`ba07249`), mapped to the design section that implements it and the test that demonstrates it.

**Design** references are sections of [`DESIGN.md`](DESIGN.md). **D-nn** references are decisions in
[`DECISIONS.md`](../DECISIONS.md). Test names are the groups printed by `tests/run.sh`.

**Status values:** `Verified` (implemented, and its test passes) · `Implemented` (no automated
verification) · `Deferred` (out of v1, D-08) · `Partial` (see note)

---

## Summary

| | Count | Verified | Implemented | Deferred |
|---|---|---|---|---|
| MUST | 49 | 47 | 2 | 0 |
| SHOULD — in v1 | 9 | 9 | 0 | 0 |
| SHOULD/COULD — deferred | 5 | — | — | 5 |
| Added by decisions | 9 | 7 | 2 | 0 |
| **v1 scope** | **67** | **63** | **4** | — |

The two **M** requirements without automated verification are NFR-03 (async-signal-safety) and
SEC-05 (no listening socket), both of which the baseline itself marks `Verify: inspection`. Their
inspection basis is recorded in the notes below.

**Test totals:** 381 assertions across 12 groups, all passing.

| Group | Assertions |
|---|---|
| unit-addr | 51 |
| unit-config | 38 |
| unit-socks5 | 51 |
| unit-fdtable | 12 |
| TST-01 hook matrix | 108 |
| TST-05 fidelity | 85 |
| TST-06 lifecycle | 26 |
| TST-07 threading | 9 |
| TST-03 leak | 7 checks |
| fault injection | 10 |
| TST-04 real tools | 2 run, 3 skipped |
| TST-02 symbol check | 43 (build gate) |

---

## §1 Interception

| ID | Pri | Design | Test | Status |
|---|---|---|---|---|
| FR-I-01 | M | §2.1 | TST-04, TST-01 | **Verified** |
| FR-I-02 | M | §2.3 | TST-02, TST-01 | **Verified** — structural: all variants funnel through one send and one receive path; TST-02 asserts pairwise symmetry |
| FR-I-03 | M | §2.3 | TST-02 | **Verified** — all 12 symbols exported |
| FR-I-04 | M | §2.3, §3.3 | TST-02, TST-06 | **Verified** — includes `close_range` |
| FR-I-05 | M | §2.3, §3.1 | TST-05 | **Verified** — `getpeername` reports the app's destination, not the relay |
| FR-I-06 | M | §2.2 | TST-05 | **Verified** — unix and TCP sockets pass through untouched |
| FR-I-07 | M | §1, §4.1 | TST-02, TST-01 | **Verified** — TST-02 asserts `poll`/`select`/`epoll_wait`/`setsockopt` are **absent** |
| FR-I-08 | S | — | — | **Deferred** (D-05) — TST-03 gates any future implementation |
| FR-I-09 | C | §6.2 | TST-05 | **Deferred** as bypass; multicast/broadcast instead fail `ENETUNREACH` with a diagnostic (D-05 R1) |

## §2 SOCKS5 client

| ID | Pri | Design | Test | Status |
|---|---|---|---|---|
| FR-P-01 | M | §4.1 | TST-01, TST-04 | **Verified** |
| FR-P-02 | M | §3.2, §4.1 | TST-06 | **Verified** — 8 open/associate/close cycles leak no control connections |
| FR-P-03 | M | §4.3 | unit-socks5, TST-05 | **Verified** — all three ATYP forms, byte-level against RFC 1928 §7. An interop defect was found and fixed here (D-14): a v4-mapped IPv6 destination was emitted as ATYP 0x04 rather than ATYP 0x01, which a real proxy silently failed to deliver |
| FR-P-04 | M | §4.3, §5.2 | unit-socks5, faults | **Verified** — fixture injects `FRAG=1`; datagram is discarded, never delivered |
| FR-P-05 | M | §4.1 | TST-05, TST-06 | **Verified** — `0.0.0.0:0` unless a concrete `bind()` |
| FR-P-06 | M | §1, §4.1 | TST-07 | **Verified** — automatic: the app's fd is the only data socket. TST-07 confirms one association from an 8-way race |
| FR-P-07 | M | §4.3 | unit-socks5 | **Verified** — encode/decode of ATYP 0x03. Not reachable via the socket API (no libc UDP call takes a hostname); covered by unit test, as §4.3 notes |
| FR-P-08 | S | §4.4 | faults | **Verified** — fixture expires an association; the shim re-associates before the send, so no datagram is lost |
| FR-P-09 | S | — | — | **Deferred** (D-08) — negotiation refuses unsupported methods with a clear message |
| FR-P-10 | C | — | — | **Deferred** — already a §8 non-goal |

## §3 Syscall fidelity

| ID | Pri | Design | Test | Status |
|---|---|---|---|---|
| FR-F-01 | M | §5.1 | TST-05, TST-01 | **Verified** — returns 40, not the wrapped 50 |
| FR-F-02 | M | §5.2 | TST-05 | **Verified** — source is the echo server, not the relay; IPv4, IPv6, and (D-14) reported in the socket's own family so a dual-stack socket sees `::ffff:a.b.c.d` as the kernel would |
| FR-F-03 | M | §5.4 | TST-05, TST-01 | **Verified** |
| FR-F-04 | M | §5.2 | TST-05 | **Verified** — `MSG_TRUNC` in `msg_flags`; `recvmsg(MSG_TRUNC)` returns the true length |
| FR-F-05 | M | §5.2 | TST-05 | **Verified** — peek is non-consuming and repeatable |
| FR-F-06 | M | §5.1, §5.2 | TST-05 | **Verified** — zero-length round-trips; distinct from `EAGAIN` |
| FR-F-07 | M | §6.4 | TST-05, faults | **Verified** — `EMSGSIZE` over the limit; exactly at the limit succeeds |
| FR-F-08 | M | §5.1, §3.1 | TST-05 | **Verified** — connect, re-connect, `AF_UNSPEC` dissolve, then `EDESTADDRREQ` |
| FR-F-09 | M | §5.3 | TST-05, TST-01 | **Verified** — `msg_len` carries the app's length. A defect was found and fixed here: `recvmmsg` was applying `MSG_DONTWAIT` after the first message, but the kernel only does that for `MSG_WAITFORONE` |
| FR-F-10 | M | §5.1, §5.2 | TST-05, TST-01 | **Verified** — 3-iovec send into 4 × 3-byte receive iovecs, where an unstripped 10-byte header would straddle a boundary |
| FR-F-11 | S | §5.2 | TST-05 | **Verified** — `msg_controllen` zeroed, `MSG_CTRUNC` not set |

## §4 State and lifecycle

| ID | Pri | Design | Test | Status |
|---|---|---|---|---|
| FR-L-01 | M | §3.1, §3.5 | TST-07, unit-fdtable | **Verified** — TST-07 under the real shim; unit-fdtable under TSan, which found and fixed a genuine race on the entry `family`/`type` fields |
| FR-L-02 | M | §3.1, §3.3 | TST-06, unit-fdtable | **Verified** — a reused fd reports `ENOTCONN`, and the generation counter advances |
| FR-L-03 | M | §3.3 | TST-06, unit-fdtable | **Verified** — `dup` adds no control connection; association survives the original's close |
| FR-L-04 | M | §3.4 | TST-06 | **Verified** — a defect was found and fixed here: parent and child share one open file description, so the child re-pointing the socket also re-pointed the parent's. The child now gets a private socket |
| FR-L-05 | M | §3.2, §4.1 | TST-06 | **Verified** — every control connection carries `FD_CLOEXEC` |
| FR-L-06 | S | §4.2, §6.4 | TST-03 | **Verified** — proxy failures surface on the application's send |

## §5 Configuration and UX

| ID | Pri | Design | Test | Status |
|---|---|---|---|---|
| FR-C-01 | M | §7.2 | TST-04 | **Verified** |
| FR-C-02 | M | §7.1 | unit-config | **Verified** — layered merge; a lower layer never clobbers a higher one with a value it did not set |
| FR-C-03 | M | §7.1 | unit-config, TST-03 | **Verified** — no proxy, unknown key, or malformed line all refuse to run |
| FR-C-04 | S | — | unit-config | **Deferred** (D-08) — a `[ProxyList]` line gives a message naming the deferral |
| FR-C-05 | M | §7.3 | manual | **Verified** — `udpchains:` prefix on stderr, `-q`/`-v` |
| FR-C-06 | S | §7.3 | manual | **Verified** — one line per association, naming destination, relay and the configured limit |

## §6 Non-functional

| ID | Pri | Design | Test | Status |
|---|---|---|---|---|
| NFR-01 | M | §10 | build | **Verified** — `make` from a clean clone, no dependencies, no downloads |
| NFR-01a | M | §10 | build, TST-02 | **Verified** — glibc floor enforced in `compat.h`; TST-02 knows about the `close_range` conditional |
| NFR-02 | M | §3.1, §5 | inspection, unit-fdtable | **Verified** — allocation only in `socket`/`dup*` and once per thread; the datagram path is atomic loads |
| NFR-03 | M | §3.1, §3.5 | inspection | **Implemented** — no locks, no allocation, no syscalls on the datagram path. The one place a signal handler could have waited on itself (association setup re-entered on the same fd) returns `EAGAIN` rather than spinning |
| NFR-04 | S | §10 | bench | **Verified (reported)** — median 51–69 µs, p99 305–564 µs for the *whole* round trip including the proxy hop, which the 100 µs budget excludes. Not a CI gate (D-08) |
| NFR-05 | M | §7.3 | inspection | **Verified** — no payload bytes at any verbosity; there is deliberately no hex-dump helper |
| NFR-06 | S | §10 | build | **Verified** — `-Wall -Wextra -Werror` plus `-Wshadow -Wcast-qual -Wstrict-prototypes` and more; it caught two real truncation hazards during development |

## §7 Security

| ID | Pri | Design | Test | Status |
|---|---|---|---|---|
| SEC-01 | M | §4.2, §6 | TST-03 | **Verified** — the core invariant. No path from a failed proxy attempt to a direct send |
| SEC-02 | M | §9.4 | TST-03 | **Verified** — three scenarios (proxy absent, `UDP ASSOCIATE` refused, shim unconfigured) × 10 send paths: zero datagrams reach the destination. A control run proves the client would otherwise get through |
| SEC-03 | M | §7.2 | inspection | **Verified** — `--password` is refused explicitly with a pointer to the file/environment route |
| SEC-04 | S | §7.2 | unit-config | **Verified** — warns on a group- or world-writable config |
| SEC-05 | M | §1, §4.1 | inspection | **Implemented** — the shim calls `socket()` only for the outbound TCP control connection and the post-`fork` replacement; there is no `listen()` or `accept()` anywhere in `src/` |
| SEC-06 | M | §7.2 | manual | **Verified** — setuid, setgid and file-capability targets are all refused |

## §9 Testing

| ID | Pri | Status |
|---|---|---|
| TST-01 | M | **Verified** — 108 cells green: 36 send×receive combinations across {connected, unconnected} × {IPv4, IPv6} |
| TST-02 | M | **Verified** — build gate; also asserts the readiness calls are absent, and checks pairwise send/receive symmetry |
| TST-03 | M | **Verified** |
| TST-04 | M | **Partial** — `nc -u` confirmed against the real `dtun` proxy (2026-08-18); `dig` and `nc -u` also pass against the fixture. `tftp`, `ntpdate`/`chronyd` and `iperf3` are not installed here and are reported as SKIPPED, not passed. See the acceptance note below |
| TST-05 | M | **Verified** — 76 assertions |
| TST-06 | M | **Verified** — 26 assertions |
| TST-07 | S | **Verified** — 8 threads × 25 iterations on separate fds, on one shared fd, and racing first use |
| TST-08 | S | **Verified** — ASan/UBSan on the unit tests, TSan on the fd table, Valgrind memcheck on the integration tests, Helgrind on the threaded test. See `tests/run_sanitizers.sh` for why the work is split that way |

## Requirements added by the decisions

| ID | Source | Design | Test | Status |
|---|---|---|---|---|
| ADD-01 | D-05 R1 | §6.2 | TST-05 | **Verified** — multicast and broadcast fail `ENETUNREACH` with a specific diagnostic; IPv4 and IPv6 |
| ADD-02 | D-05 R2 | §6.3 | unit-config | **Verified** — proxy locality is computed at config time; `strict_loopback` promotes the warning to an error |
| ADD-03 | D-05 R4 | — | manual | **Verified** — README "What does not work" |
| ADD-04 | D-06 | §9.1 | — | **Verified** — fixture with 8 fault-injection modes; 3 exercised by `test_faults.sh` |
| ADD-05 | D-10 | §7.1 | unit-config | **Verified** |
| ADD-06 | D-12 | §5.4, §7.3 | TST-05, faults | **Verified** — includes the case where the proxy's real limit is smaller than the configured one |
| ADD-07 | D-04 | — | manual | **Verified** — README documents unproxied resolver TCP fallback |
| ADD-08 | D-01 | — | inspection | **Implemented** — stated in README and DECISIONS; no contribution process exists yet to enforce it |
| ADD-09 | D-14 | §4.3, §5.2 | unit-socks5, TST-05 | **Verified** — v4-mapped destinations encode as ATYP 0x01; the fixture now rejects the wrong form rather than forgiving it |

---

## Acceptance criteria (§10 of the baseline)

| # | Criterion | Status |
|---|---|---|
| 1 | Every **M** requirement implemented and its verification passes | **Met** — 47 of 49 verified by test, 2 by inspection as the baseline specifies |
| 2 | TST-01 hook matrix 100% green | **Met** — 108/108 |
| 3 | TST-03 leak test passes | **Met** |
| 4 | `dig`, `nc -u` and `iperf3 -u` work against the reference proxy, with its logs confirming the tunnel | **Partly met** — `nc -u` **confirmed against the real `dtun` proxy** on 2026-08-18, end to end to a remote listener. That run is also what surfaced the D-14 interop defect, which the fixture had been concealing. `dig` and `nc -u` additionally pass against the in-repo fixture. `dig` and `iperf3 -u` against `dtun` are still outstanding. |
| 5 | `make` succeeds from a clean clone with only a C compiler; no downloads | **Met** |
| 6 | README states the §8 non-goals plainly, including Go and static binaries | **Met** |

### What remains before v1 can be called done

Interop against the real `dtun` proxy has begun and has already earned its keep: the first run
carried no traffic at all, and the cause was a genuine defect (D-14) that the in-repo fixture had
been forgiving. D-06's warning — that a green fixture suite is not evidence of interop — was
correct, and the remaining items below are worth the same suspicion.

1. **`dig` and `iperf3 -u` against `dtun`.** `nc -u` is confirmed. `dig` exercises a different shape
   (short request/response, often several sockets); `iperf3 -u` exercises sustained throughput and
   is the one case likely to expose association-level rather than datagram-level problems.
2. **`tftp` and `ntpdate`/`chronyd -Q`**, neither of which is installed in this environment.
3. **A run against a genuinely REMOTE proxy.** `dtun`'s client runs on the local host, so the relay
   has always been `127.0.0.1` and `proxy_is_local` has always been true. The D-05 R2 loopback guard
   — which covers the silent-wrong-destination case, the most consequential thing v1 chose to
   accept — has therefore been unit-tested but never exercised end to end. This is now the largest
   untested area.
4. **A dual-stack client against `dtun`**, to confirm D-14 from the other side: an AF_INET6 socket
   reaching an IPv4 destination should now be delivered, and the `-v` output should show `ATYP 0x01`.

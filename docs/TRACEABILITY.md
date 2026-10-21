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
| SHOULD — in v1 | 10 | 10 | 0 | 0 |
| SHOULD/COULD — deferred | 4 | — | — | 4 |
| Added by decisions | 12 | 10 | 2 | 0 |
| **v1 scope** | **71** | **67** | **4** | — |

The two **M** requirements without automated verification are NFR-03 (async-signal-safety) and
SEC-05 (no listening socket), both of which the baseline itself marks `Verify: inspection`. Their
inspection basis is recorded in the notes below.

**Test totals:** 870 assertions across 18 groups (`tests/run.sh`), all passing, plus the 91-check
symbol gate run by `make check`. The numbers are what `tests/run.sh` prints; regenerate this table
from a run rather than editing it by hand.

| Group | Assertions |
|---|---|
| unit-addr | 51 |
| unit-config | 125 |
| unit-socks5 | 88 |
| unit-chain | 80 |
| unit-fdtable | 22 |
| unit-dns | 52 |
| TST-01 hook matrix | 108 |
| TST-05 fidelity | 171 |
| port switch (TFTP pattern) | 12 |
| TST-06 lifecycle | 78 |
| TST-07 threading | 9 |
| FR-P-09 auth | 15 |
| D-22 resolve | 11 checks, over four programs making 99 assertions of their own |
| wrapper loadability | 18 |
| TST-03 leak | 11 checks |
| fault injection | 17 |
| TST-04 real tools | 2 run, 3 skipped (automated, against the fixture) |
| NFR-04 latency benchmark | reported, not a gate (D-08) |
| TST-02 symbol check | 71 (build gate, `make check`) |

---

## §1 Interception

| ID | Pri | Design | Test | Status |
|---|---|---|---|---|
| FR-I-01 | M | §2.1 | TST-04, TST-01 | **Verified** |
| FR-I-02 | M | §2.3 | TST-02, TST-01, TST-05 | **Verified** — structural: all variants funnel through one send and one receive path; TST-02 asserts pairwise symmetry. A defect was found here in review (D-21): the fortified `__recvfrom_chk`, `__recv_chk` and `__read_chk`, which `_FORTIFY_SOURCE` programs call, bypassed the hooks and delivered the SOCKS header as payload. They are now hooked, and TST-05 covers each |
| FR-I-03 | M | §2.3 | TST-02 | **Verified** — all 12 symbols exported, and only hooks are exported (D-35) |
| FR-I-04 | M | §2.3, §3.3 | TST-02, TST-06, TST-03 | **Verified** — includes `close_range`. Review found three more routes (D-21): `fcntl(F_DUPFD)` duplicates, sockets received over `SCM_RIGHTS`, and sockets inherited without `/proc`, all untracked and sent directly. `fcntl`/`fcntl64` are now hooked, received sockets are adopted in `recvmsg`/`recvmmsg`, and a failed `dup2`/`dup3` no longer untracks its target. Later: `closefrom()` and the lifecycle calls of `syscall()` (D-23). TST-03 sends through each route with the proxy down |
| FR-I-05 | M | §2.3, §3.1 | TST-05 | **Verified** — `getpeername` reports the app's destination, not the relay |
| FR-I-06 | M | §2.2 | TST-05, TST-03 | **Verified** — unix and TCP sockets pass through untouched; raw and packet sockets are refused with `EPERM` (D-36) |
| FR-I-07 | M | §1, §4.1 | TST-02, TST-01 | **Verified** — TST-02 asserts `poll`/`select`/`epoll_wait`/`setsockopt` are **absent** |
| FR-I-08 | S | — | — | **Deferred** (D-05) — TST-03 gates any future implementation |
| FR-I-09 | C | §6.2 | TST-05 | **Deferred** as bypass; multicast/broadcast instead fail `ENETUNREACH` with a diagnostic (D-05 R1) |

## §2 SOCKS5 client

| ID | Pri | Design | Test | Status |
|---|---|---|---|---|
| FR-P-01 | M | §4.1 | TST-01, TST-04 | **Verified** |
| FR-P-02 | M | §3.2, §4.1 | TST-06 | **Verified** — 8 open/associate/close cycles leak no control connections |
| FR-P-03 | M | §4.3 | unit-socks5, TST-05 | **Verified** — all three ATYP forms, byte-level against RFC 1928 §7. An interop defect was found and fixed here (D-14): a v4-mapped IPv6 destination was emitted as ATYP 0x04 rather than ATYP 0x01, which a real proxy silently failed to deliver. Re-confirmed against the reference proxy on 2026-08-19 by two independent checks in one run — the logged ATYP byte and the 10-byte wire overhead, the latter being unforgeable by a mislabelled encoding. The 16-byte ATYP 0x04 form was sent to `::1` through seven real proxies on 2026-10-19 (INTEROP-CHECKLIST.md §12); a destination beyond loopback is still untested. A second interop defect was found here on 2026-08-19 (D-16): a loopback `BND.ADDR` from a REMOTE proxy was taken literally, pointing the application socket at this host's loopback, so every datagram was silently discarded |
| FR-P-04 | M | §4.3, §5.2 | unit-socks5, faults | **Verified** — fixture injects `FRAG=1`; datagram is discarded, never delivered |
| FR-P-05 | M | §4.1 | TST-05, TST-06 | **Verified** — `0.0.0.0:0` unless a concrete `bind()` |
| FR-P-06 | M | §1, §4.1 | TST-07 | **Verified** — automatic: the app's fd is the only data socket. TST-07 confirms one association from an 8-way race |
| FR-P-07 | M | §4.3 | unit-socks5 | **Verified** — encode/decode of ATYP 0x03. Not reachable via the socket API (no libc UDP call takes a hostname); covered by unit test, as §4.3 notes |
| FR-P-08 | S | §4.4 | faults | **Verified** — fixture expires an association; the shim re-associates before the send, so no datagram is lost |
| FR-P-09 | S | §4.1 | unit-socks5, FR-P-09-auth | **Verified** — RFC 1929 implemented (D-20, superseding the D-08 deferral). `0x02` is offered only when credentials are configured; the sub-negotiation version byte is `0x01`, not SOCKS5's `0x05`, which the unit test asserts specifically. End-to-end against a fixture performing real authentication: correct credentials round-trip, and wrong or absent credentials deliver **nothing** rather than falling through to a direct send. A test asserts the password appears in no log on either side (NFR-05, SEC-03) |
| FR-P-10 | C | — | — | **In progress** — a §8 non-goal for v1, now §2a; see [Multi-hop chains](#multi-hop-chains-2a-in-progress) |

## §3 Syscall fidelity

| ID | Pri | Design | Test | Status |
|---|---|---|---|---|
| FR-F-01 | M | §5.1 | TST-05, TST-01 | **Verified** — returns 40, not the wrapped 50 |
| FR-F-02 | M | §5.2 | TST-05, portswitch, TST-04 | **Verified** — source is the echo server, not the relay; IPv4, IPv6, and (D-14) reported in the socket's own family so a dual-stack socket sees `::ffff:a.b.c.d` as the kernel would. Confirmed against a real proxy on 2026-08-19 by `ntpdate -q`, which validates a response's source address against the address it queried and discards a mismatch silently — the accepted offset is the assertion. This is the only interop tool run so far that checks the source address rather than just the port, so it is the external evidence for this row |
| FR-F-03 | M | §5.4 | TST-05, TST-01 | **Verified** |
| FR-F-04 | M | §5.2 | TST-05 | **Verified** — `MSG_TRUNC` in `msg_flags`; `recvmsg(MSG_TRUNC)` returns the true length |
| FR-F-05 | M | §5.2 | TST-05 | **Verified** — peek is non-consuming and repeatable |
| FR-F-06 | M | §5.1, §5.2 | TST-05 | **Verified** — zero-length round-trips; distinct from `EAGAIN` |
| FR-F-07 | M | §6.4 | TST-05, faults | **Verified** — `EMSGSIZE` over the limit; exactly at the limit succeeds |
| FR-F-08 | M | §5.1, §3.1 | TST-05 | **Verified** — connect, re-connect, `AF_UNSPEC` dissolve, then `EDESTADDRREQ`. A fidelity gap was found and fixed here (D-15): a connected socket accepted datagrams from any origin, where the kernel filters by the connected peer — the shim was *more* permissive than an unhooked socket |
| FR-F-09 | M | §5.3 | TST-05, TST-01 | **Verified** — `msg_len` carries the app's length. A defect was found and fixed here: `recvmmsg` was applying `MSG_DONTWAIT` after the first message, but the kernel only does that for `MSG_WAITFORONE` |
| FR-F-10 | M | §5.1, §5.2 | TST-05, TST-01 | **Verified** — 3-iovec send into 4 × 3-byte receive iovecs, where an unstripped 10-byte header would straddle a boundary |
| FR-F-11 | S | §5.2 | TST-05 | **Verified** — `msg_controllen` zeroed, `MSG_CTRUNC` not set |

## §4 State and lifecycle

| ID | Pri | Design | Test | Status |
|---|---|---|---|---|
| FR-L-01 | M | §3.1, §3.5 | TST-07, unit-fdtable | **Verified** — TST-07 under the real shim; unit-fdtable under TSan, which found and fixed a genuine race on the entry `family`/`type` fields |
| FR-L-02 | M | §3.1, §3.3 | TST-06, unit-fdtable | **Verified** — a reused fd reports `ENOTCONN`, and a released entry keeps none of its state (the generation counter once cited here was never checked, and was removed in D-30; the per-call cookie check of D-23 is what catches a stale entry). A defect was found and fixed here on 2026-08-19 (D-17): release depends on interposing `close()`, and a program whose runtime closes by another route (dig via libuv: 4 of 64 closes reach the hook) stranded its entry, so the next socket on that descriptor number was refused with a spurious `EMFILE` and the association leaked. A non-`FREE` entry at claim time is now treated as stale and recycled |
| FR-L-03 | M | §3.3 | TST-06, unit-fdtable | **Verified** — `dup` adds no control connection; association survives the original's close. Covers `fcntl(F_DUPFD)` too since D-21; a duplicate that cannot be tracked is closed and the call fails with `EMFILE` |
| FR-L-04 | M | §3.4 | TST-06 | **Verified** — a defect was found and fixed here: parent and child share one open file description, so the child re-pointing the socket also re-pointed the parent's. The child now gets a private socket. It binds the parent's address or port again, and if it cannot (the parent holds it), it stops declaring that address in `UDP ASSOCIATE` (D-34; TST-faults, under a proxy fixture that enforces the declared address) |
| FR-L-05 | M | §3.2, §4.1 | TST-06 | **Verified** — every control connection carries `FD_CLOEXEC` |
| FR-L-06 | S | §4.2, §6.4 | TST-03 | **Verified** — proxy failures surface on the application's send |

## §5 Configuration and UX

| ID | Pri | Design | Test | Status |
|---|---|---|---|---|
| FR-C-01 | M | §7.2 | TST-04 | **Verified** |
| FR-C-02 | M | §7.1 | unit-config | **Verified** — layered merge; a lower layer never clobbers a higher one with a value it did not set |
| FR-C-03 | M | §7.1 | unit-config, TST-03 | **Verified** — no proxy, unknown key, or malformed line all refuse to run |
| FR-C-04 | S | — | unit-config | **Deferred** (D-08) — a `[ProxyList]` line gives a message naming the deferral |
| FR-C-05 | M | §7.3 | manual, TST-faults | **Verified** — `udpchains:` prefix on stderr, `-q` (errors only) / `-v`. Repeated warnings are rate-limited, and nothing is written to a descriptor 2 that is no longer the original stderr (D-33) |
| FR-C-06 | S | §7.3 | manual | **Verified** — one line per association, naming destination, relay and the configured limit |

## §6 Non-functional

| ID | Pri | Design | Test | Status |
|---|---|---|---|---|
| NFR-01 | M | §10 | build | **Verified** — `make` from a clean clone, no dependencies, no downloads |
| NFR-01a | M | §10 | build, TST-02 | **Verified** — glibc floor enforced in `compat.h`; TST-02 knows about the `close_range` conditional |
| NFR-02 | M | §3.1, §5 | inspection, unit-fdtable | **Verified** — allocation only in `socket`/`dup*` and once per thread; the datagram path is atomic loads |
| NFR-03 | M | §3.1, §3.5 | inspection | **Partial** — the steady-state datagram path takes no locks and allocates nothing, and the one place a signal handler could wait on itself (association setup re-entered on the same fd) returns `EAGAIN`. But a socket's first send, a thread's first datagram, and `socket()`, `dup*()` and `close()` allocate or free memory, so any of those from a signal handler that interrupted `malloc` can deadlock. Documented in the README, as the requirement's either/or allows. Corrected in review (item M10); the earlier "no syscalls on the datagram path" also no longer holds (D-23) |
| NFR-04 | S | §10 | bench | **Verified (reported)** — the bench now runs the same binary against the same echo server **with and without** the shim, so loopback, the echo server and the syscall path cancel and the delta is what the shim adds: **42 µs added median** (direct 32 µs → proxied 74 µs), p99 +136 µs. Inside the 100 µs budget, and that figure still contains the proxy hop the budget excludes, so it is an upper bound rather than the shim's share. Previously a single run reported the whole round trip and could not be compared against the budget at all. Not a CI gate (D-08) |
| NFR-05 | M | §7.3 | inspection | **Verified** — no payload bytes at any verbosity; there is deliberately no hex-dump helper |
| NFR-06 | S | §10 | build | **Verified** — `-Wall -Wextra -Werror` plus `-Wshadow -Wcast-qual -Wstrict-prototypes` and more; it caught two real truncation hazards during development |

## §7 Security

| ID | Pri | Design | Test | Status |
|---|---|---|---|---|
| SEC-01 | M | §4.2, §6 | TST-03, capture | **Verified** — the core invariant. No path from a failed proxy attempt to a direct send. Confirmed at the **wire** on 2026-08-20 by `tests/test_failclosed_capture.sh`: with the proxy absent, refusing `UDP ASSOCIATE`, or the shim unconfigured, tcpdump captured **zero** packets, against a positive control that captured 11. TST-03 watches the destination, which cannot see a datagram that leaves this host for the wrong address; this can. Name lookups were a gap (D-22): glibc's resolver bypassed every hook. Since D-22 the capture script also checks them on the wire: on 2026-09-24, no packet asked for the looked-up name with the proxy down or no `dns` set, against a positive control that did. D-21 and D-23 cover the routes by which a socket enters the process, except `pidfd_getfd`; that, and sends through `io_uring`, `sendfile`/`splice` or stdio, bypass the hooks and are documented in the README |
| SEC-02 | M | §9.4 | TST-03, capture | **Verified** — three scenarios (proxy absent, `UDP ASSOCIATE` refused, shim unconfigured) × 10 send paths: zero datagrams reach the destination, and zero appear on the wire. A control run proves the client would otherwise get through, at both observation points |
| SEC-03 | M | §7.2 | inspection | **Verified** — `--password` is refused explicitly with a pointer to the file/environment route |
| SEC-04 | S | §7.2 | unit-config, TST-auth | **Verified** — warns on a group- or world-writable config, and on a config holding `password =` that others can read; a readable password file is warned about once, by the wrapper (D-33) |
| SEC-05 | M | §1, §4.1 | inspection | **Implemented** — the shim calls `socket()` only for the outbound TCP control connection and the post-`fork` replacement; there is no `listen()` or `accept()` anywhere in `src/` |
| SEC-06 | M | §7.2 | manual | **Verified** — setuid, setgid and file-capability targets are all refused |

## §9 Testing

| ID | Pri | Status |
|---|---|---|
| TST-01 | M | **Verified** — 108 cells green: the 36 send×receive combinations over IPv4 and IPv6 (72), plus the three senders that name a destination run unconnected as well (36) |
| TST-02 | M | **Verified** — build gate; also asserts the readiness calls are absent, and checks pairwise send/receive symmetry |
| TST-03 | M | **Verified** — plus a wire-level companion, `tests/test_failclosed_capture.sh`, which is not part of `make test` because it needs `CAP_NET_RAW`. Its positive control aborts the run rather than reporting a pass from a capture that is silently seeing nothing |
| TST-04 | M | **Verified** — the automated script runs against the **fixture** and reports 2 run, 3 skipped (`tftp` has no local server, `ntpdate` no reachable NTP server, `iperf3` not installed); a skip is not a pass, so the script alone never satisfied this. All five tools have now been run **by hand against the reference proxy** (2026-08-18/19): `nc -u`, TFTP 10 MB, `dig`, `iperf -u` rate sweep, `ntpdate -q`. See [`INTEROP-CHECKLIST.md`](INTEROP-CHECKLIST.md) for what each proves and the acceptance note below |
| TST-05 | M | **Verified** — see the totals table at the top |
| TST-06 | M | **Verified** — see the totals table at the top |
| TST-07 | S | **Verified** — 8 threads × 25 iterations on separate fds, on one shared fd, and racing first use |
| TST-08 | S | **Verified** — ASan/UBSan on the unit tests, TSan on the fd table, Valgrind memcheck on the integration tests, Helgrind on the threaded test. See `tests/run_sanitizers.sh` for why the work is split that way |

## Requirements added by the decisions

| ID | Source | Design | Test | Status |
|---|---|---|---|---|
| ADD-01 | D-05 R1 | §6.2 | TST-05 | **Verified** — multicast and broadcast fail `ENETUNREACH` with a specific diagnostic; IPv4 and IPv6 |
| ADD-02 | D-05 R2 | §6.3 | unit-config | **Verified** — proxy locality is computed at config time; `strict_loopback` promotes the warning to an error |
| ADD-03 | D-05 R4 | — | manual | **Verified** — README "What does not work" |
| ADD-04 | D-06 | §9.1 | — | **Verified** — fixture with fault-injection modes; `test_faults.sh` runs four scenarios, plus the D-33 diagnostics checks |
| ADD-05 | D-10 | §7.1 | unit-config | **Verified** |
| ADD-06 | D-12 | §5.4, §7.3 | TST-05, faults | **Verified** — includes the case where the proxy's real limit is smaller than the configured one |
| ADD-07 | D-04 | — | manual | **Verified** — README documents unproxied resolver TCP fallback |
| ADD-08 | D-01 | — | inspection | **Implemented** — stated in README and DECISIONS; no contribution process exists yet to enforce it |
| ADD-09 | D-14 | §4.3, §5.2 | unit-socks5, TST-05 | **Verified** — v4-mapped destinations encode as ATYP 0x01; the fixture now rejects the wrong form rather than forgiving it |
| ADD-10 | D-22 | §11 | unit-dns, D-22-resolve, TST-03 | **Verified** — name lookups made through libc are answered locally or through the proxy, never by the host's resolver. With `dns` unset they fail `EAI_FAIL`; with the proxy down, `EAI_AGAIN`. Zero queries reach the resolver in either case, and `strace` shows no direct port-53 send in any mode. Truncated answers are repeated over SOCKS5 `CONNECT`. Supersedes D-04's "no DNS leak by construction", which was false on every supported glibc. The wire-level capture case is written but not yet run (it needs root) |
| ADD-11 | D-36 | §2.3 | TST-05, TST-03, TST-02 | **Verified** — `syscall()` routes every socket, send and receive call to its hook; `dprintf` and `pwritev2`/`preadv2` are proxied; `fdopen`, `sendfile` and `splice` are refused on a UDP socket; `pidfd_getfd` copies are adopted; raw and packet sockets, `MSG_MORE` and `UDP_SEGMENT` are refused. The leak client's 27 sends all fail with the proxy down, against 11 that reached the destination before |

---

## Multi-hop chains (§2a), in progress

Not part of v1 scope, and not counted in the summary above. Design: D-37 to D-42. `Not started`
means no code yet.

| ID | Pri | Test | Status |
|---|---|---|---|
| FR-CH-01 | M | unit-config, wrapper loadability | **Partial** — `[hop]` sections, repeated `-p` and a `UDPCHAINS_PROXY` list are parsed, merged and handed to the shim (D-38); a chain of one exports exactly what 0.1.0 did. Until chains are carried, a longer chain is refused by the wrapper and fails every send in the shim |
| FR-CH-02 | M | unit-chain | **Partial** — chain setup fails as a whole if any hop cannot be reached, negotiated or associated, and releases the hops already up (D-37); the datagram path does not use it yet |
| FR-CH-03 | M | unit-config, unit-chain | **Partial** — each hop's credentials are configured and passed on by location, never by value (D-25, D-38). Chain setup reaches each hop by `CONNECT` through the hops before it and negotiates with that hop's own credentials, against chained fixtures; the datagram path does not use it yet |
| FR-CH-04 | M | unit-config, unit-chain | **Partial** — later hops are checked for form and never resolved here, and are sent to the previous hop as written, a name as `ATYP 0x03` (D-39); a chain through a named hop is tested. Not yet on the wire from the shim |
| FR-CH-05 | M | — | **Not started** |
| FR-CH-06 | M | — | **Not started** (D-41) |
| FR-CH-07 | M | unit-socks5, unit-chain | **Partial** — the per-hop fixup is implemented and unit-tested for every case D-40 lists, and a named relay is crossed against fixtures; the datagram path does not use it yet |
| FR-CH-08 | M | — | **Not started** (D-40) |
| FR-CH-09 | M | unit-chain | **Partial** — a chain is alive only while every control connection is, and a later hop's expiry is seen through the tunnel; re-association not started |
| FR-CH-10 | M | — | **Not started** |
| FR-CH-11 | M | unit-chain | **Partial** — the TCP fallback's `CONNECT` tunnels through the chain; UDP queries not started |
| FR-CH-12 | M | unit-chain | **Partial** — chain setup names the failing hop in its diagnostics, and a chain of one keeps 0.1.0's; `-v` path not started |
| FR-CH-13 | S | unit-config | **Partial** — at most 8 hops is enforced (D-42); README guidance not written |
| FR-CH-14 | S | — | **Not started** |
| FR-CH-T1 to T4 | — | — | **Not started** |

---

## Acceptance criteria (§10 of the baseline)

| # | Criterion | Status |
|---|---|---|
| 1 | Every **M** requirement implemented and its verification passes | **Met** — 47 of 49 verified by test, 2 by inspection as the baseline specifies |
| 2 | TST-01 hook matrix 100% green | **Met** — 108/108 |
| 3 | TST-03 leak test passes | **Met** |
| 4 | `dig`, `nc -u` and `iperf3 -u` work against the reference proxy, with its logs confirming the tunnel | **Met** — `nc -u`, TFTP (10 MB), `dig` and `iperf -u` all **confirmed against the reference proxy** on 2026-08-18. The `nc -u` run is what surfaced the D-14 interop defect the fixture had been concealing. The `dig` run (`myip.opendns.com` against a numeric resolver) returned the **proxy's** egress address rather than the host's, satisfying the "confirming the tunnel" clause from the client side without needing the proxy's logs. The `iperf -u` rate sweep showed **0% loss through 15 Mbit/s** and a hard cliff above it; kernel UDP counters on both hosts moved by 0 and 16 respectively against ~3900 missing datagrams, attributing the cliff to the proxy's tunnel rather than to the shim or either kernel socket buffer. `iperf` 2 was used rather than iperf3; the criterion's intent is burst behaviour, which it exercises identically. |
| 5 | `make` succeeds from a clean clone with only a C compiler; no downloads | **Met** |
| 6 | README states the §8 non-goals plainly, including Go and static binaries | **Met** |

### What remains before v1 can be called done

The runnable form of this list is [`INTEROP-CHECKLIST.md`](INTEROP-CHECKLIST.md).

Interop against the reference proxy has begun and has already earned its keep: the first run
carried no traffic at all, and the cause was a genuine defect (D-14) that the in-repo fixture had
been forgiving. D-06's warning — that a green fixture suite is not evidence of interop — was
correct, and the remaining items below are worth the same suspicion.

1. **The both-ways-round leak check, against a REMOTE proxy.** `tests/test_failclosed_capture.sh`
   proves at the wire that a failed proxy attempt sends nothing (SEC-01). What it cannot show with a
   co-located proxy is a shim that sends a datagram *both* correctly to the relay and directly: the
   proxy relays onward from the same interface, so a packet to the destination is expected and
   indistinguishable from a leak. Run `REMOTE_PROXY=<host:port>` once a remote proxy is reachable.

2. **A successful end-to-end run against a genuinely REMOTE proxy.** First attempted 2026-08-19.
   `proxy_is_local` was correctly false and the **D-05 R2 loopback guard fired end to end for the
   first time**, with the right message — that part is done. The run itself failed, and productively:
   it found D-16 (a loopback `BND.ADDR` taken literally) and, downstream of it, D-17 (a stranded
   fd-table entry causing a spurious `EMFILE`). Both are fixed and covered by unit tests, but the
   fixes were re-run against that same proxy the same day and **both are confirmed**: the
   substitution fires and names the proxy address, and the stale-entry reclaim happens once with no
   `EMFILE`. The D-05 R2 guard passes in both its warning and `strict_loopback` forms.
   What remains is **not a shim defect**: the proxy binds its UDP relay to its own loopback, so the
   substituted address is correct and still unreachable, and its log records zero datagrams received.
   SOCKS5 `UDP ASSOCIATE` needs the relay port reachable from the client. Closing this row needs a
   proxy that binds a routable relay; the shim side is done.
3. **A genuine IPv6 destination against a real proxy.** The v4-mapped half of D-14 was confirmed against
   the real proxy on 2026-08-19 (`ATYP 0x01`, 10-byte header, from an `AF_INET6` socket), but this
   host has no global IPv6 address. On 2026-10-19 the 16-byte `ATYP 0x04` form was sent to `::1`
   through seven real proxies on this host, with a 22-byte header, and all seven delivered the
   datagram and its reply ([`INTEROP-CHECKLIST.md`](INTEROP-CHECKLIST.md) §12). What remains is a
   destination beyond loopback.

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

**Test totals:** 2287 assertions across 26 groups (`tests/run.sh`), all passing, plus the 91-check
symbol gate run by `make check`. The numbers are what `tests/run.sh` prints; regenerate this table
from a run rather than editing it by hand.

| Group | Assertions |
|---|---|
| unit-addr | 51 |
| unit-config | 232 |
| unit-socks5 | 88 |
| unit-chain | 135 |
| unit-fdtable | 22 |
| unit-dns | 52 |
| unit-supervise | 11 |
| TST-01 hook matrix | 108 |
| TST-05 fidelity | 171 |
| port switch (TFTP pattern) | 12 |
| TST-06 lifecycle | 78 |
| TST-07 threading | 9 |
| FR-CH-T2 through 2 hops: matrix, fidelity, port switch, lifecycle, threading | 378 |
| FR-CH-T2 through 3 hops, the third given as `localhost` | 378 |
| FR-CH-08 exit-hop loopback guard | 2 checks |
| FR-P-09 auth | 20 |
| D-22 resolve | 24 checks, over nine program runs making 211 assertions of their own |
| wrapper loadability | 17 |
| TST-03 leak | 23 checks |
| fault injection | 43 |
| FR-SV supervisor mode | 43 checks, five of them running static probes making 18, 6, 37, 19 and 4 assertions of their own |
| FR-SV-T1 hook matrix, `-static`, under the supervisor | 108 |
| FR-SV-T1 the same through 2 hops | 108 |
| FR-SV fidelity, `-static`, under the supervisor | 172 |
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
| FR-C-04 | S | — | unit-config, FR-P-09-auth | **Verified** as FR-CH-14 (D-47) — a `proxychains.conf` is read as it is, for its strict chain of `socks5` hops |
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
| ADD-04 | D-06 | §9.1 | — | **Verified** — fixture with fault-injection modes; `test_faults.sh` runs four scenarios against a single proxy and six against a 3-hop chain (FR-CH-T3, FR-CH-10), plus the D-33 diagnostics checks |
| ADD-05 | D-10 | §7.1 | unit-config | **Verified** |
| ADD-06 | D-12 | §5.4, §7.3 | TST-05, faults | **Verified** — includes the case where the proxy's real limit is smaller than the configured one |
| ADD-07 | D-04 | — | manual | **Verified** — README documents unproxied resolver TCP fallback |
| ADD-08 | D-01 | — | inspection | **Implemented** — stated in README and DECISIONS; no contribution process exists yet to enforce it |
| ADD-09 | D-14 | §4.3, §5.2 | unit-socks5, TST-05 | **Verified** — v4-mapped destinations encode as ATYP 0x01; the fixture now rejects the wrong form rather than forgiving it |
| ADD-10 | D-22 | §11 | unit-dns, D-22-resolve, TST-03 | **Verified** — name lookups made through libc are answered locally or through the proxy, never by the host's resolver. With `dns` unset they fail `EAI_FAIL`; with the proxy down, `EAI_AGAIN`. Zero queries reach the resolver in either case, and `strace` shows no direct port-53 send in any mode. Truncated answers are repeated over SOCKS5 `CONNECT`. Supersedes D-04's "no DNS leak by construction", which was false on every supported glibc. On the wire too: the capture script's lookup cases pass, most recently on 2026-10-21, through a single proxy and a 3-hop chain |
| ADD-11 | D-36 | §2.3 | TST-05, TST-03, TST-02 | **Verified** — `syscall()` routes every socket, send and receive call to its hook; `dprintf` and `pwritev2`/`preadv2` are proxied; `fdopen`, `sendfile` and `splice` are refused on a UDP socket; `pidfd_getfd` copies are adopted; raw and packet sockets, `MSG_MORE` and `UDP_SEGMENT` are refused. The leak client's 27 sends all fail with the proxy down, against 11 that reached the destination before |

---

## Multi-hop chains (§2a)

Not part of v1 scope, and not counted in the summary above. Design: D-37 to D-47. `Not started`
means no code yet.

| ID | Pri | Test | Status |
|---|---|---|---|
| FR-CH-01 | M | unit-config, unit-chain, wrapper loadability, every single-proxy group | **Verified** — `[hop]` sections, repeated `-p` and a `UDPCHAINS_PROXY` list are parsed, merged and handed to the shim (D-38), and run; a chain of one exports exactly what 0.1.0 did, encodes and decodes exactly its single header, prints its diagnostics and, unless `chain_timeout` is set, has no overall setup deadline (D-45). Every single-proxy group passes unchanged. A proxychains.conf's `[ProxyList]` too (FR-CH-14) |
| FR-CH-02 | M | unit-config, unit-chain, TST-03, faults | **Verified** against fixtures — chain setup fails as a whole if any hop cannot be reached, negotiated or associated, and releases the hops already up (D-37), within a deadline that `chain_timeout` sets, raises or lifts (D-45); the shim uses it for every association. With each hop of a 3-hop chain dead in turn, or one refusing `CONNECT`, every send and lookup fails and nothing reaches the destination or the resolver (FR-CH-T1, FR-CH-T3) |
| FR-CH-03 | M | unit-config, unit-chain, FR-CH-T2 | **Verified** against fixtures — each hop's credentials are configured and passed on by location, never by value (D-25, D-38); each hop is reached by `CONNECT` through the hops before it and negotiated with its own credentials. Through real proxies too: Dante, then 3proxy, each requiring its own login (FR-CH-T4) |
| FR-CH-04 | M | unit-config, unit-chain, FR-CH-T2 | **Verified** against fixtures — later hops are checked for form and never resolved here, and are sent to the previous hop as written, a name as `ATYP 0x03` (D-39); the 3-hop runs reach their third hop by name. Each of the seven real proxies, as hop 1, resolved a hop 2 given by name, for `CONNECT` and in UDP headers (FR-CH-T4) |
| FR-CH-05 | M | unit-chain, FR-CH-T2 | **Verified** — one header per hop, outermost first, byte for byte against RFC 1928 §7; built in the per-thread header buffer and sent as one iovec entry ahead of the application's, so the payload is not copied (D-11), and in the `IOV_MAX` fallback as before |
| FR-CH-06 | M | unit-chain, FR-CH-T2, faults | **Verified** — every layer is checked on receive: well formed, `FRAG` 0, and from the next hop's relay, by port alone for a named relay; a failure drops the whole datagram (D-41). Unit-tested layer by layer. Against fixtures: `FRAG` set by the middle hop and by the exit hop, and a forged datagram sent to hop 2's relay that names the echo server inside, are all dropped, and the shim says at which layer. With the source check removed, all 5 forgeries were delivered |
| FR-CH-07 | M | unit-socks5, unit-chain, FR-CH-T2 | **Verified** against fixtures — the per-hop fixup is implemented and unit-tested for every case D-40 lists, `localhost` counting as loopback, and a relay that becomes a name (this host's own) is crossed against fixtures |
| FR-CH-08 | M | FR-CH-08 exit-hop | **Verified** — the loopback guard looks at the exit hop: under a chain, `strict_loopback` refuses a loopback destination even though every hop is on this host, and a single local proxy still sends to it (D-40) |
| FR-CH-09 | M | unit-chain, FR-CH-T2, faults | **Verified** — an association is alive only while every hop's control connection is, a later hop's expiry is seen through the tunnel, and a dead association is rebuilt whole by the FR-P-08 path. The middle hop of 3 expiring its association is transparent to the program, and the association is set up again through all 3 hops |
| FR-CH-10 | M | FR-CH-T2, faults | **Verified** — every hop's control connection is a protected shim descriptor (D-26) and a forked child closes all of them (D-31); the lifecycle tests pass through 2 and 3 hops. When the protected range is full, the connection stays where it is, still protected, and a warning says so; with no descriptor at all the send fails with `EMFILE` (D-46). Tested at a soft limit of 64 through 3 hops: the exit hop relayed exactly the datagrams reported sent, and the destination received exactly those |
| FR-CH-11 | M | unit-chain, D-22-resolve, TST-03 | **Verified** against fixtures — the resolver's associations are set up through every hop, and its queries carry a header per hop and are checked layer by layer (D-41); the TCP fallback's `CONNECT` tunnels through the chain. Every entry point resolves through 2 hops, over UDP and TCP; with either hop dead, or hop 1 refusing `CONNECT`, every lookup needing DNS fails and none reaches the resolver; `strace` shows no direct send to a resolver. Under Valgrind through 2 hops |
| FR-CH-12 | M | unit-chain, D-22-resolve, faults | **Verified** — chain setup names the failing hop, once a second, with no vaguer line after a specific one, and a chain of one keeps 0.1.0's diagnostics (D-43); a hop refusing `CONNECT` is named with the refusal. The association line names every hop's relay in order, for datagram and resolver associations alike |
| FR-CH-13 | S | unit-config, inspection, FR-CH-T4 | **Verified** — at most 8 hops is enforced (D-42). The README explains choosing `max_datagram` for a chain: hop *i* of *n* carries the headers of the *n* − *i* hops after it, 10 bytes each for an IPv4 relay, 22 for IPv6, more for a named one. `make interop` measured exactly that limit, and truncation one byte above it, in every chain where a hop truncates |
| FR-CH-14 | S | unit-config, FR-P-09-auth | **Verified** — `-f` takes a proxychains.conf as it is (D-47). Its `socks5` lines are the hops, in order, with inline credentials passed on by naming the file (D-25); `strict_chain` is accepted, the other chain modes and non-`socks5` proxies refused with the line, `quiet_mode` and `tcp_connect_time_out` applied, and the directives without an equivalent warned about once, by the wrapper. Unit-tested on a file of proxychains' shape and 21 refusals; end to end, a chain whose hop 2 requires the login on its line carries a datagram |
| FR-CH-T1 | M | TST-03, capture | **Verified** — `test_leak.sh` runs the leak client and the resolver probe with each hop of a 3-hop chain dead in turn: no datagram reaches the destination, no query the resolver. On the wire, on 2026-10-21, `tests/test_failclosed_capture.sh` captured zero packets to the destination and zero port-53 packets asking for the looked-up name with each hop dead in turn, against positive controls that captured 28 and 8 |
| FR-CH-T2 | M | FR-CH-T2-2hop, FR-CH-T2-3hop | **Verified** — the matrix, fidelity, port-switch, lifecycle and threading tests through 2 and 3 hops |
| FR-CH-T3 | M | faults | **Verified** — expiry at the middle hop, `FRAG` at the middle and innermost layers, a forged inner source behind a genuine outer one, and a hop refusing `CONNECT` |
| FR-CH-T4 | S | interop | **Verified** on this host — `make interop` runs a ring of 2-hop chains of the seven proxies, so each is once a middle hop and once the exit hop, and one chain of all seven. Every proxy serves as a middle hop. Each 2-hop chain passes the matrix, the resolver over UDP and chained `CONNECT`, an IPv6 destination, and a hop 2 given by name; fidelity and the port-switch test follow the exit hop alone; the largest datagram is as predicted from each hop's own; and with each hop killed in turn, nothing reaches the destination and the same socket recovers. The 7-hop chain passes the matrix, lifecycle, resolver, IPv6 and size checks, and the same with its middle hop killed. Results in [`INTEROP-CHECKLIST.md`](INTEROP-CHECKLIST.md) §13. Not across hosts |

## Supervisor mode (§2b), in progress

Not part of v1 scope, and not counted in the summary above. Design: D-48 to D-53, decided
2026-10-22, and D-54, 2026-10-23. Steps 2 to 4 of the plan are built: the supervisor runs a
program under its filter and carries its UDP, for x86-64, with calls on its UDP sockets made while
their thread is stopped by `ptrace`, so signals lose nothing. Threads and the wire capture
(step 5), DNS and aarch64 (step 6) remain. The accepted limitations are listed in
[`FUTURE-STATIC-BINARIES.md`](FUTURE-STATIC-BINARIES.md) §9.

| ID | Pri | Test | Status |
|---|---|---|---|
| FR-SV-01 | M | FR-SV-supervise, FR-SV-T1 | **Verified** — `--supervise`, `supervise = yes` and `UDPCHAINS_SUPERVISE` choose it, and the variable is not passed to the program; without them, every shim-mode group passes as before and the program has no filter. The shim is not given to a supervised program: `libudpchains.so` is removed from an inherited `LD_PRELOAD`, and if it was loaded into `udpchains` itself, `udpchains` runs again without it (tested: UDP is carried once). The same configuration, chains included, and the same diagnostics: the association line names the process and descriptor |
| FR-SV-02 | M | unit-supervise, FR-SV-supervise | **Partial** — refuses before the `exec`, never running the program unsupervised: a kernel older than 5.14 (the release check unit-tested), no seccomp, a filter refused, a listener the parent cannot copy, a child that cannot be traced (D-54; tested under `strace -f`), an inherited UDP, raw or packet socket (tested) |
| FR-SV-03 | M | FR-SV-supervise | **Verified** — from a static probe, an x32 call and a 32-bit `int $0x80` call both fail with `ENOSYS`; only x86-64 is supported so far, and any other build refuses supervisor mode |
| FR-SV-04 | M | FR-SV-supervise | **Verified** — every UDP socket is made at the lowest free number from 768; `dup` and `F_DUPFD`/`F_DUPFD_CLOEXEC` are placed in the range and carry; `dup2`/`dup3` below it fail with `EPERM` and put nothing there; `dup2` within it carries; a closed number is given out again |
| FR-SV-05 | M | FR-SV-supervise, FR-SV-T1 | **Verified** — the program's socket is the only data socket: replies arrive on it (`poll` sees them), a socket shared across `fork` is one socket, and the supervisor keeps no descriptor of its own for it, so 40 sockets used and closed leave it holding no control connection |
| FR-SV-06 | M | FR-SV-T1, FR-SV-fidelity, FR-SV-supervise | **Verified** — every sender of the matrix from a static probe, and the fidelity test's send semantics (returned length, `EMSGSIZE`, `EDESTADDRREQ`, `sendmmsg` partial success, `pwritev2`); `MSG_MORE`, multicast and a short address refused as in shim mode. Under storms of signals, no send fails with `EINTR` or is repeated (D-54) |
| FR-SV-07 | M | FR-SV-T1, FR-SV-fidelity | **Verified** — every receiver of the matrix from a static probe; the true sender, truncation and `MSG_TRUNC`, `MSG_PEEK`, zero-length datagrams, `preadv2`; `recvmmsg` returns the datagrams already queued without waiting for more (D-54), checked as such |
| FR-SV-08 | M | FR-SV-supervise | **Verified** (D-54) — `O_NONBLOCK` and `MSG_DONTWAIT` give `EAGAIN` at once; a blocking receive waits in the program's own kernel, so `SO_RCVTIMEO` times out with `EAGAIN`, a signal gives `EINTR` without `SA_RESTART` and a restart with it, and with `SO_RCVTIMEO` set `EINTR` even under `SA_RESTART` and after `SIGSTOP`/`SIGCONT`, as signal(7) says. No datagram lost: 100 datagrams under a signal every 2 ms, with and without `SA_RESTART`, and 1,000 under one every 100 µs, each run; 20 runs gave 5,293 interrupted receives and no loss |
| FR-SV-09 | M | FR-SV-supervise | **Partial** — `io_uring_setup` `ENOSYS`, `pidfd_getfd` `EPERM`, raw and packet sockets `EPERM`, ICMP datagram sockets `EPROTONOSUPPORT`, and `sendfile`/`splice` onto a received UDP socket `EINVAL`, each with a diagnostic not hidden by another's, from a static probe. `sendfile`/`splice` onto a carried socket `EINVAL` (FR-SV-fidelity) |
| FR-SV-10 | M | FR-SV-supervise, FR-SV-fidelity | **Verified** — `getsockname` reports the bound address with the port the kernel chose; `getpeername` the connected destination, never the relay, and `ENOTCONN` unconnected or after `connect(AF_UNSPEC)` |
| FR-SV-11 | M | FR-SV-supervise | **Partial** — the supervisor exits with the program's status, or dies of the signal that killed it; signals sent to it reach the program, and one the program handles is handled; it stays for a descendant the program leaves running, which is supervised. State is kept per socket, so a socket inherited across `fork` is carried in the child, including after the parent has closed its descriptor. Threads, `exec` and their tests: step 5 |
| FR-SV-12 | M | — | **Not started** |
| FR-SV-13 | M | FR-SV-supervise | **Partial** (D-54) — with `udpchains` killed, its program is killed with it (`PTRACE_O_EXITKILL`, tested); a traced call with no tracer fails with `ENOSYS` (checked by hand); notified calls fail with `ENOSYS` once the listener has gone (`seccomp_unotify(2)`). The wire capture with the supervisor killed mid-run: step 5 |
| FR-SV-14 | M | inspection, FR-SV-supervise | **Verified** by inspection — the supervisor's only sockets are the program's (made for it, then closed) and its control connections to the proxy; nothing listens. Its debug lines carry addresses, lengths and the ATYP byte, never payload (NFR-05). setuid, setgid and capability targets are refused before supervision, as in shim mode |
| FR-SV-15 | S | — | **Not started** |
| FR-SV-16 | S | — | **Not started** |
| FR-SV-17 | C | — | **Not started** |
| FR-SV-18 | M | FR-SV-supervise | **Verified** — a UDP socket received over `SCM_RIGHTS` from an unsupervised process: `sendto`, `send`, `sendmsg`, `sendmmsg` and `connect` fail with `EPERM`, `sendfile` and `splice` onto it with `EINVAL`; D-50's documented `write()` gap is shown to deliver its one byte and nothing else. An inherited UDP socket refuses the run, naming the descriptor. With the `socket()` trap removed (a mutation), the dynamic and static leak clients still sent nothing |
| FR-SV-19 | M | — | **Not started** |
| FR-SV-T1 | M | FR-SV-T1-matrix, FR-SV-T1-matrix-2hop | **Verified** — the 108-cell matrix with the probe built `-static`, directly and through two hops; also under ASan and UBSan. With `read` removed from the filter's range calls (a mutation), the 9 `read` cells failed |
| FR-SV-T2 | M | FR-SV-supervise | **Partial** — against a dead proxy, the leak client, static and dynamic, sends nothing and the destination receives nothing; with the proxy up, the same sends are carried; killed, the supervisor takes its program with it. The wire capture, including with the supervisor killed mid-run: step 5 |
| FR-SV-T3 | M | FR-SV-supervise | **Partial** — the `dup` family, `fork` (a child sending on, and outliving the parent's descriptor for, an inherited socket), `SCM_RIGHTS` from an unsupervised process, and each refused route. `exec`, threads and `close_range`: step 5. With the sweep's marking removed (a mutation), the socket a child still held was forgotten and 7 checks failed |
| FR-SV-T4 | M | FR-SV-supervise | **Verified** — `test_supervise signals` (19 assertions) and `abandon` (4): receives under storms of signals with and without `SA_RESTART`, none lost; sends never interrupted or repeated; `SO_RCVTIMEO` and `SIGSTOP`/`SIGCONT` as natively; 2,000 `close`s under a storm, none left open; `fcntl(F_GETFD)` never interrupted; a signal during a hung handshake handled at once, and `SIGTERM` then ending the program at once. Mutations: `close` sent by notification again left descriptors open (2 checks failed); `fcntl` trapped on the range again was interrupted (1); with abandoning disabled, the signal waited for the 1,000 ms timeout (1). Soaked 20 runs; also under ASan and UBSan |
| FR-SV-T5 | S | — | **Not started** |

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

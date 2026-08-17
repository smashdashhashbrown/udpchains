# Traceability Matrix — `udpchains`

Every requirement in [`UDP-PRELOAD-REQUIREMENTS.md`](../UDP-PRELOAD-REQUIREMENTS.md) (baseline
`ba07249`), mapped to the design section that implements it and the test that demonstrates it.

This is the instrument for measuring the finished product against the original requirements. It is
maintained as work proceeds: **Status** is the only column expected to change. If a **Design** or
**Test** cell needs to change, that is a design change and belongs in
[`DECISIONS.md`](../DECISIONS.md) first.

**Design** references are sections of [`DESIGN.md`](DESIGN.md). **D-nn** references are decisions.

**Status values:** `Not started` · `In progress` · `Implemented` · `Verified` (test passes) ·
`Deferred` (out of v1, see D-08)

---

## Summary

| | Count | Verified |
|---|---|---|
| MUST | 49 | 0 |
| SHOULD — in v1 | 9 | 0 |
| SHOULD/COULD — deferred | 5 | — |
| **Total in v1 scope** | **58** | **0** |

Acceptance (§10 of the baseline) requires every **M** verified, the TST-01 matrix 100% green, TST-03
passing, and the three real-tool cases working against the reference proxy.

---

## §1 Interception

| ID | Pri | v1 | Design | Test | Status | Notes |
|---|---|---|---|---|---|---|
| FR-I-01 | M | ✓ | §2.1 | TST-04 | Not started | `dlsym(RTLD_NEXT)`, lazy resolution |
| FR-I-02 | M | ✓ | §2.3 | TST-01, TST-02 | Not started | Structural: all variants funnel through one send and one receive implementation |
| FR-I-03 | M | ✓ | §2.3 | TST-02 | Not started | 12 send/receive symbols |
| FR-I-04 | M | ✓ | §2.3, §3.3 | TST-02, TST-06 | Not started | `close_range` conditional per D-09 |
| FR-I-05 | M | ✓ | §2.3, §3.1 | TST-05 | Not started | Reports `app_dst`/`bound_addr`, never the relay |
| FR-I-06 | M | ✓ | §2.2 | TST-05 | Not started | Predicate also excludes the shim's own TCP control fds, with no special case |
| FR-I-07 | M | ✓ | §1, §4.1 | TST-01, TST-02 | Not started | No shadow socket; TST-02 also asserts `poll`/`select`/`epoll_wait` are **absent** from the export list |
| FR-I-08 | S | ✗ | — | — | **Deferred** | D-05: no bypass in v1. TST-03 gates any future implementation |
| FR-I-09 | C | ✗ | §6.2 | TST-05 | **Deferred** | D-05 R1: multicast/broadcast fail `ENETUNREACH` + diagnostic instead of bypassing |

## §2 SOCKS5 client

| ID | Pri | v1 | Design | Test | Status | Notes |
|---|---|---|---|---|---|---|
| FR-P-01 | M | ✓ | §4.1 | TST-04 | Not started | Method `0x00`, `UDP ASSOCIATE`, relay from `BND.ADDR`/`BND.PORT` |
| FR-P-02 | M | ✓ | §3.2, §4.1 | TST-06 | Not started | Lifetime tied to the application socket |
| FR-P-03 | M | ✓ | §4.3 | TST-05 | Not started | All three `ATYP` forms — M2 gate |
| FR-P-04 | M | ✓ | §4.3, §5.4 | TST-05 | Not started | Needs fixture `FRAG` injection (D-06) |
| FR-P-05 | M | ✓ | §4.1 | TST-04 | Not started | `0.0.0.0:0` unless `bind()`-ed to a concrete address |
| FR-P-06 | M | ✓ | §1, §4.1 | inspection | Not started | Automatic — the application's fd *is* the only data socket (FR-I-07) |
| FR-P-07 | M | ✓ | §4.3 | TST-05 | Not started | Hostname ⇒ `ATYP=0x03`, proxy-side resolution |
| FR-P-08 | S | ✓ | §4.4 | TST-05 | Not started | Needs fixture association expiry (D-06) |
| FR-P-09 | S | ✗ | — | — | **Deferred** | D-08: reference proxy offers only method `0x00`. SEC-03 plumbing built anyway |
| FR-P-10 | C | ✗ | — | — | **Deferred** | Already a §8 non-goal |

## §3 Syscall fidelity

| ID | Pri | v1 | Design | Test | Status | Notes |
|---|---|---|---|---|---|---|
| FR-F-01 | M | ✓ | §5.1 | TST-01, TST-05 | Not started | Return the application's byte count, never the wrapped length |
| FR-F-02 | M | ✓ | §5.2 | TST-05 | Not started | Source from the SOCKS reply header |
| FR-F-03 | M | ✓ | §5.4 | TST-01 | Not started | One datagram in, one datagram out |
| FR-F-04 | M | ✓ | §5.2 | TST-05 | Not started | `MSG_TRUNC` semantics; exact because the whole datagram is in scratch (D-11) |
| FR-F-05 | M | ✓ | §5.2 | TST-05 | Not started | `MSG_PEEK` non-consuming, repeatable |
| FR-F-06 | M | ✓ | §5.1, §5.2 | TST-05 | Not started | Zero-length distinct from "no datagram" |
| FR-F-07 | M | ✓ | §6.4 | TST-05 | Not started | `EMSGSIZE` against the configured limit (D-12), never a silent drop |
| FR-F-08 | M | ✓ | §5.1, §3.1 | TST-05 | Not started | `connect`, re-`connect`, `AF_UNSPEC` dissolve |
| FR-F-09 | M | ✓ | §5.3 | TST-01, TST-05 | Not started | Per-message independence, kernel-style partial success |
| FR-F-10 | M | ✓ | §5.1, §5.2 | TST-05 | Not started | Split-header case cannot arise on receive by construction (D-11) |
| FR-F-11 | S | ✓ | §5.2 | TST-05 | Not started | `msg_control` returned empty, `MSG_CTRUNC` not set |

## §4 State and lifecycle

| ID | Pri | v1 | Design | Test | Status | Notes |
|---|---|---|---|---|---|---|
| FR-L-01 | M | ✓ | §3.1, §3.5 | TST-07 | Not started | TST-07 is the only verification of this **M** requirement — see D-08 |
| FR-L-02 | M | ✓ | §3.1, §3.3 | TST-06 | Not started | Generation counter guards fd reuse |
| FR-L-03 | M | ✓ | §3.3 | TST-06 | Not started | Refcounted association shared across `dup` |
| FR-L-04 | M | ✓ | §3.4 | TST-06 | Not started | `pthread_atfork` child handler bumps a generation and defers all work |
| FR-L-05 | M | ✓ | §3.2, §4.1 | TST-06 | Not started | `FD_CLOEXEC` set at creation, not later |
| FR-L-06 | S | ✓ | §4.2, §6.4 | TST-03 | Not started | Failure surfaces on the application's send |

## §5 Configuration and UX

| ID | Pri | v1 | Design | Test | Status | Notes |
|---|---|---|---|---|---|---|
| FR-C-01 | M | ✓ | §7.2 | TST-04 | Not started | `udpchains [-f config] <program> [args…]` |
| FR-C-02 | M | ✓ | §7.1 | unit | Not started | Precedence: cmdline → env → file → default |
| FR-C-03 | M | ✓ | §7.1 | unit | Not started | D-10: no default proxy, so this is meaningful and testable |
| FR-C-04 | S | ✗ | — | — | **Deferred** | D-08: `[ProxyList]` is ergonomic, not functional |
| FR-C-05 | M | ✓ | §7.3 | manual | Not started | stderr, `udpchains:` prefix, `-q`/`-v` |
| FR-C-06 | S | ✓ | §7.3 | manual | Not started | One line per association; D-05 R2 depends on it |

## §6 Non-functional

| ID | Pri | v1 | Design | Test | Status | Notes |
|---|---|---|---|---|---|---|
| NFR-01 | M | ✓ | §10 | inspection | Not started | `make` + a C compiler, no third-party deps, no downloads |
| NFR-01a | M | ✓ | §10 | inspection | Not started | glibc ≥ 2.34; build fails loudly rather than dropping a hook |
| NFR-02 | M | ✓ | §3.1, §5 | inspection | Not started | No allocation on the datagram path — falls out of D-07 and D-11 |
| NFR-03 | M | ✓ | §3.1, §3.5 | inspection | Not started | D-07: signal-safe by construction, not by documented caveat |
| NFR-04 | S | ✓ | §10 | benchmark | Not started | Reported number, **not** a CI gate (D-08) |
| NFR-05 | M | ✓ | §7.3 | inspection | Not started | No payload bytes in any log at any verbosity |
| NFR-06 | S | ✓ | §10 | build | Not started | `-Wall -Wextra -Werror` from the first commit |

## §7 Security

| ID | Pri | v1 | Design | Test | Status | Notes |
|---|---|---|---|---|---|---|
| SEC-01 | M | ✓ | §4.2, §6 | TST-03 | Not started | **The core invariant.** No path from a failed proxy attempt to a direct send |
| SEC-02 | M | ✓ | §9.4 | TST-03 | Not started | Unqualified zero-packet assertion, no whitelist (D-05) |
| SEC-03 | M | ✓ | §7.2 | inspection | Not started | Credentials from file/env only; built in v1 though FR-P-09 is deferred |
| SEC-04 | S | ✓ | §7.2 | unit | Not started | Warn on group/world-writable config |
| SEC-05 | M | ✓ | §1, §4.1 | inspection | Not started | No listening socket: one outbound TCP control connection, and the application's own fd |
| SEC-06 | M | ✓ | §7.2 | unit | Not started | Wrapper refuses setuid/setgid targets rather than running them unproxied |

## §9 Testing

| ID | Pri | v1 | Design | Status | Notes |
|---|---|---|---|---|---|
| TST-01 | M | ✓ | §9.2 | Not started | 36-cell hook matrix × {connected, unconnected} × {IPv4, IPv6}. Primary regression gate |
| TST-02 | M | ✓ | §9.3 | Not started | `nm -D`; missing receive hook fails the **build** |
| TST-03 | M | ✓ | §9.4 | Not started | Leak test; gates any future bypass work (D-05 R3) |
| TST-04 | M | ✓ | §9.1 | Not started | `dig`, `nc -u`, `ntpdate`/`chronyd -Q`, `tftp`, `iperf3 -u` against the **real** proxy |
| TST-05 | M | ✓ | §5, §6 | Not started | Fidelity: FR-F-01…FR-F-10 |
| TST-06 | M | ✓ | §3.3, §3.4 | Not started | Lifecycle: `dup`, fd reuse, `fork`, `FD_CLOEXEC` |
| TST-07 | S | ✓ | §3.5 | Not started | Threaded stress; verifies the **M** requirement FR-L-01 |
| TST-08 | S | ✓ | §10 | Not started | ASan/UBSan/TSan/Valgrind |

---

## Requirements added by the decisions

Not in the baseline. Tracked here so the delta from `ba07249` is explicit and reviewable.

| ID | Source | Requirement | Design | Test | Status |
|---|---|---|---|---|---|
| ADD-01 | D-05 R1 | Multicast/broadcast destinations fail `ENETUNREACH` **and** emit a one-line diagnostic naming the reason | §6.2 | TST-05 | Not started |
| ADD-02 | D-05 R2 | Loopback destination + non-local proxy emits a diagnostic at association time; `strict_loopback` promotes it to an error | §6.3 | unit | Not started |
| ADD-03 | D-05 R4 | README states plainly that local UDP services and service discovery do not work, and why | — | manual | Not started |
| ADD-04 | D-06 | In-repo C fixture proxy with the eight fault-injection modes | §9.1 | — | Not started |
| ADD-05 | D-10 | No built-in default proxy address; unresolved configuration exits before `exec` | §7.1 | unit | Not started |
| ADD-06 | D-12 | Datagram limit is configured (default 8192) and reported on the association line | §5.4, §7.3 | TST-05 | Not started |
| ADD-07 | D-04 | README documents that resolver TCP fallback is unproxied, and that composing with `proxychains-ng` is the answer | — | manual | Not started |
| ADD-08 | D-01 | Contributions carry a statement that they are not derived from GPL-2.0 sources | — | inspection | Not started |

---

## Milestone mapping

From §12 of the baseline. §0.4 warns that if M3 is not reachable in the first day or two, the
architecture is wrong and later milestones will not rescue it.

| # | Deliverable | Requirements | Done when |
|---|---|---|---|
| M1 | Skeleton, `dlsym` plumbing, config, wrapper | FR-C-01/02/03/05, SEC-03/04/06, NFR-01/01a/06, ADD-05 | `udpchains /bin/true` runs; unknown config fails closed |
| M2 | SOCKS5 client, header codec | FR-P-01/02/03/04/07, ADD-04 | Unit tests pass for all three `ATYP` forms |
| M3 | Tier-1 path | FR-I-01/06/07, FR-F-01/02/03 | `dig @<server> -p <port>` works through the shim |
| M4 | Connected sockets | FR-I-05, FR-F-08, part of TST-01 | Hook matrix green for those cells |
| M5 | `msg`/`mmsg`, scatter/gather, `MSG_PEEK`, truncation | FR-F-04/05/06/09/10/11, FR-I-02/03 | TST-01 fully green; TST-05 passes |
| M6 | Lifecycle and threading | FR-I-04, FR-L-01…05, NFR-02/03 | TST-06, TST-07 pass |
| M7 | Fail-closed, leak test, IPv6 | SEC-01/02/05, FR-L-06, FR-P-05/08, ADD-01/02, FR-F-07 | SEC-01/02 verified; `nc -6 -u` works |
| M8 | Real-tool integration, README | TST-04, ADD-03/07, NFR-04/05 | Acceptance criteria met |

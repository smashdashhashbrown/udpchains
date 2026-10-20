# Requirements Specification — `udpchains`

**Project:** An `LD_PRELOAD` shim that routes a dynamically-linked program's **UDP** traffic through a
SOCKS5 proxy that supports `UDP ASSOCIATE`, transparently and without modifying the program.
**Status:** Draft for implementation · **Date:** 2026-08-17
**Working name:** `udpchains` — rename freely.

Priority: **M** = MUST (v1 is not done without it) · **S** = SHOULD (v1 unless it endangers the
schedule) · **C** = COULD (post-v1 if cheap).

Each requirement is testable. "Verify" states how it is demonstrated: `unit`, `integration`,
`inspection`, or `manual`.

> **This document is self-contained by design.** It is written to be handed to an implementer with no
> prior context. §0.3 records the evidence behind the design decisions, because two existing tools
> already attempt this and both fail in instructive ways. **§0.4 must be read before writing or
> reading any code** — it settles licensing, repository placement, and the effort baseline.

---

## 0. Context

### 0.1 Problem

`proxychains` is the standard tool for forcing an unmodified program through a proxy, and it is
**TCP-only**. Programs that use UDP get no proxying at all — and, critically, no error either: the
traffic silently goes direct. Any workflow that assumes "I ran it under proxychains, therefore it
went through the proxy" is wrong for UDP, including for DNS in some configurations.

The goal is a shim with the same ergonomics (`udpchains <program> <args>`) that actually carries UDP,
and that covers the socket-usage patterns real programs exhibit rather than only the textbook one.

### 0.2 Scope target — "tier 2"

Three levels of ambition were considered. This project targets the middle one.

| Tier | Coverage | Works for |
|---|---|---|
| 1 | `sendto`/`recvfrom`, unconnected IPv4, one association | `dig`, `nc -u`, textbook request/response |
| **2 (this project)** | **+ connected sockets, all send/recv variants, IPv6, threads, fd lifecycle** | **most dynamically-linked C/C++ tools** |
| 3 | + QUIC with GSO/GRO, ancillary-data fidelity | not attempted; see §8 |

### 0.3 Evidence behind the design (measured, not assumed)

1. **`proxychains-ng` 4.17 cannot proxy UDP.** Its exported hooks are `connect`, `close`,
   `close_range`, `sendto`, plus the DNS family (`getaddrinfo`, `gethostbyname`, `gethostbyaddr`,
   `getnameinfo`) — 40 dynamic symbols total, with **no `recvfrom`, `recv`, `read`, or `recvmsg`**.
   With no receive-side hook there is nowhere to strip a SOCKS reply header, so replies could never
   be delivered even if requests were wrapped.

   Demonstrated: with proxychains pointed at a dead proxy (`127.0.0.1:9`), TCP correctly fails
   (`Strict chain ... 127.0.0.1:9 ... timeout`) while UDP reaches the destination anyway. **The
   traffic leaks silently with no diagnostic.** This is the single most important failure to avoid;
   see SEC-01.

2. **`Proxando`** (github.com/NULLhere/Proxando, GPL-2.0, derivative of proxychains-ng) does
   implement SOCKS5 `UDP ASSOCIATE` correctly at the wire level, but its hook set is asymmetric:
   it hooks `sendto`, `send`, `write`, `socket`, `connect`, `close` — and on the receive side **only
   `recvfrom`**. A program using `connect()`+`send()`+`recv()`, or anything using `recvmsg`, sends
   correctly and then reads the reply **with the 10-byte SOCKS header still attached**. Silent data
   corruption, not an error. Avoiding exactly this is FR-I-02.

3. **Proxy-side TPROXY alternatives were ruled out.** Transparent UDP interception via Linux
   TPROXY needs the proxy to read `IP_RECVORIGDSTADDR` ancillary data, which cannot be assumed of
   an arbitrary proxy, and it ties the solution to one proxy rather than working with any. Hence a
   client-side shim, in C, with `LD_PRELOAD`.

### 0.4 Project setup decisions

Settle these before the first commit; each is cheap now and expensive later.

**Licensing — read this before opening any reference source.** The two tools cited in §0.3 are both
**GPL-2.0**: `proxychains-ng`, and `Proxando`, which is derived from it. §0.3 cites them as *evidence
about their behaviour*, which is fine. **Copying implementation from either makes this project a
derivative work bound by GPL-2.0**, and it is easy to do accidentally when the thing you need — a
SOCKS5 `UDP ASSOCIATE` client — is sitting right there in their source.

The default position for this project is **clean-room**: implement from RFC 1928 §7 and the relevant
man pages (`udp(7)`, `socket(7)`, `recvmsg(2)`), leaving the project free to carry whatever licence
its author prefers. If the author would rather derive from proxychains-ng deliberately, that is a
legitimate choice — but it must be a decision, taken up front, with GPL-2.0 adopted and attribution
given. Record the choice here before writing code.

**Repository placement.** This belongs in its **own repository**, not as a subdirectory of any proxy
it happens to be tested against. The shim speaks nothing but standard SOCKS5 and works with any proxy
supporting `UDP ASSOCIATE`, so coupling it to one implementation would misrepresent its scope. It is
also C, and folding it into a project with a different toolchain would break that project's build
story.

**Effort baseline**, so scope creep is visible when it happens: tier 1 (§0.2) is roughly 2 days and
~400 lines of C. Tier 2 — this project — is roughly **1–2 weeks**, with the bulk in §3 syscall
fidelity and §4 lifecycle rather than in anything proxy-related. Milestone M3 (§12) should be
reachable within the first day or two; if it is not, something about the architecture is wrong and
the remaining milestones will not rescue it.

### 0.5 Interoperability target

Any RFC 1928 SOCKS5 proxy offering `UDP ASSOCIATE`. The reference proxy used during development
has these relevant behaviours:

| Behaviour | Value |
|---|---|
| Auth methods offered | `0x00` (no authentication) only |
| Relay address returned | `127.0.0.1:<ephemeral>`, ATYP `0x01` |
| Relay binding | loopback only; refuses datagrams from other hosts |
| Peer locking | association pins to the **first sender's** address:port; datagrams from any other source are dropped |
| Association lifetime | tied to the TCP control connection — closing it tears the association down |
| Idle expiry | 60 s of silence in both directions |
| Max datagram | 8192 bytes payload; larger is dropped, never fragmented |
| `FRAG` | must be `0`; non-zero is dropped |
| Destination `ATYP` | `0x01`, `0x03` (domain, resolved proxy-side), `0x04` all accepted |

These are properties to interoperate with, not requirements on this project — except where called
out below (FR-P-05, FR-P-06).

---

## 1. Functional requirements — Interception

| ID | Pri | Requirement | Verify |
|---|---|---|---|
| FR-I-01 | M | The shim SHALL intercept UDP traffic of dynamically-linked programs via `LD_PRELOAD` and `dlsym(RTLD_NEXT, …)`, without modifying or recompiling the target program. | integration |
| FR-I-02 | M | **Send/receive hook symmetry.** For every send-path function hooked, its receive-path counterpart SHALL also be hooked. An implementation SHALL NOT ship a state in which a program can send successfully but receive unwrapped data. | inspection, unit |
| FR-I-03 | M | The following SHALL be hooked: **send** — `sendto`, `sendmsg`, `sendmmsg`, `send`, `write`, `writev`; **receive** — `recvfrom`, `recvmsg`, `recvmmsg`, `recv`, `read`, `readv`. | inspection (`nm -D`) |
| FR-I-04 | M | The following SHALL be hooked for lifecycle: `socket`, `connect`, `bind`, `close`, `close_range`, `dup`, `dup2`, `dup3`. | inspection |
| FR-I-05 | M | `getpeername` and `getsockname` SHALL be hooked and SHALL report the destination and local address the application believes it has, never the relay's. | unit |
| FR-I-06 | M | Only `SOCK_DGRAM` sockets in `AF_INET`/`AF_INET6` SHALL be intercepted. All other sockets (TCP, unix, netlink, raw) SHALL pass through untouched. | unit |
| FR-I-07 | M | **The application's own fd SHALL be redirected to the relay**; the shim SHALL NOT maintain a shadow socket. Consequence: `poll`, `select`, `epoll_wait` and friends need no hooking and SHALL NOT be hooked. | inspection, integration |
| FR-I-08 | S | Traffic to loopback destinations SHALL bypass the proxy by default, configurable. (An app talking to `127.0.0.1` almost never wants that tunnelled.) | unit |
| FR-I-09 | C | Multicast and broadcast destinations SHALL bypass the proxy, since SOCKS5 cannot express them. | unit |

## 2. Functional requirements — SOCKS5 client

| ID | Pri | Requirement | Verify |
|---|---|---|---|
| FR-P-01 | M | On first use of an intercepted socket the shim SHALL open a TCP control connection to the proxy, negotiate method `0x00`, and issue `UDP ASSOCIATE`, using the returned `BND.ADDR`/`BND.PORT` as the relay. | integration |
| FR-P-02 | M | The control connection SHALL remain open for the lifetime of the application socket and SHALL be closed when that socket is closed. | unit |
| FR-P-03 | M | Outbound datagrams SHALL be prefixed with `RSV(2)=0, FRAG(1)=0, ATYP, DST.ADDR, DST.PORT` per RFC 1928 §7. Inbound datagrams SHALL have that header parsed and stripped, honouring `ATYP` `0x01`/`0x03`/`0x04`. | unit |
| FR-P-04 | M | A datagram with `FRAG != 0` SHALL be discarded. The shim SHALL never emit `FRAG != 0`. | unit |
| FR-P-05 | M | The `UDP ASSOCIATE` request SHALL declare `0.0.0.0:0` unless the application has explicitly `bind()`-ed a concrete address, in which case that address SHALL be declared. (Proxies pin the association to the declared address when one is given; declaring an address the shim will not send from breaks the association.) | integration |
| FR-P-06 | M | All datagrams for one association SHALL be sent from a single, stable local socket, because proxies pin an association to its first sender. | inspection |
| FR-P-07 | M | When the application supplies a hostname the shim SHALL forward it as `ATYP=0x03` for proxy-side resolution rather than resolving locally. Where only an address is available (the normal UDP case) `ATYP=0x01`/`0x04` SHALL be used. | unit |
| FR-P-08 | S | If the proxy has expired an idle association, the next send SHALL transparently re-associate rather than failing. | integration |
| FR-P-09 | S | SOCKS5 username/password authentication (RFC 1929) SHALL be supported when configured. | unit |
| FR-P-10 | C | Multiple proxies in a chain, as proxychains offers. Not required for v1; UDP chaining is only meaningful hop-by-hop and the complexity is disproportionate. **Planned after 0.1.0:** draft requirements, design impact and estimate in [`docs/FUTURE-UDP-CHAINS.md`](docs/FUTURE-UDP-CHAINS.md). | — |

## 3. Functional requirements — Syscall fidelity

This section is where the project succeeds or fails. Every requirement here is about being
indistinguishable from an unhooked socket.

| ID | Pri | Requirement | Verify |
|---|---|---|---|
| FR-F-01 | M | A send call SHALL return the byte count **the application supplied**, never the wrapped length including the SOCKS header. | unit |
| FR-F-02 | M | `recvfrom`/`recvmsg` SHALL populate the source address from the SOCKS reply header, so the application sees the true origin. | unit |
| FR-F-03 | M | Datagram boundaries SHALL be preserved exactly. One application datagram is one relayed datagram. | unit |
| FR-F-04 | M | When the application's buffer is shorter than the unwrapped payload, the excess SHALL be discarded and `MSG_TRUNC` SHALL be set in `msg_flags` for `recvmsg`, matching kernel behaviour. `recvmsg` with `MSG_TRUNC` requested SHALL return the true payload length. | unit |
| FR-F-05 | M | `MSG_PEEK` SHALL return unwrapped payload without consuming the datagram, and a subsequent non-peek receive SHALL return the same payload. | unit |
| FR-F-06 | M | Zero-length datagrams SHALL round-trip as zero-length, distinct from "no datagram". | unit |
| FR-F-07 | M | `errno` SHALL be set as the unhooked call would set it. In particular a payload exceeding the proxy's datagram limit SHALL yield `EMSGSIZE`, not a silent drop. | unit |
| FR-F-08 | M | `connect()` on a `SOCK_DGRAM` socket SHALL record the intended destination and connect the fd to the relay instead; subsequent `send`/`write` SHALL use the recorded destination. A second `connect()` SHALL re-target. `connect()` to `AF_UNSPEC` SHALL dissolve the association per POSIX. | unit |
| FR-F-09 | M | `sendmmsg`/`recvmmsg` SHALL handle each message in the vector independently and return the count processed, with partial success reported as the kernel does. | unit |
| FR-F-10 | M | Scatter/gather (`writev`, `readv`, `msg_iov` with multiple entries) SHALL be handled correctly, including a header that spans the boundary between iovec entries on receive. | unit |
| FR-F-11 | S | Ancillary data requested by the application (`msg_control`) SHALL be returned empty rather than containing relay-derived values that would mislead. See §8. | unit |

## 4. Functional requirements — State and lifecycle

| ID | Pri | Requirement | Verify |
|---|---|---|---|
| FR-L-01 | M | Per-fd state SHALL be tracked in a table safe for concurrent access from multiple threads. | unit (threaded) |
| FR-L-02 | M | `close()` SHALL release the state and the control connection. A subsequent fd with the same number SHALL NOT inherit stale state. | unit |
| FR-L-03 | M | `dup`/`dup2`/`dup3` SHALL share one association between the duplicated descriptors; the association SHALL survive until the last one closes. | unit |
| FR-L-04 | M | After `fork()`, the child SHALL NOT share the parent's control connection. The child SHALL establish its own association on next use. | unit |
| FR-L-05 | M | Control-connection fds SHALL be marked `FD_CLOEXEC` so they do not leak into `exec`-ed programs. | unit |
| FR-L-06 | S | If the proxy is unreachable at association time the failure SHALL be reported on the application's *send* call, not deferred or swallowed. | unit |

## 5. Configuration and UX

| ID | Pri | Requirement | Verify |
|---|---|---|---|
| FR-C-01 | M | A wrapper executable SHALL provide `udpchains [-f config] <program> [args…]`, setting `LD_PRELOAD` and exec-ing the program. | integration |
| FR-C-02 | M | Configuration SHALL be read from, in precedence order: command line, environment (`UDPCHAINS_PROXY`, `UDPCHAINS_CONFIG`), config file, built-in default. | unit |
| FR-C-03 | M | An unparseable or missing configuration SHALL cause a clear diagnostic and refuse to run the program, rather than running it unproxied. | unit |
| FR-C-04 | S | The config file SHALL accept a `proxychains.conf`-like `[ProxyList]` stanza so existing muscle memory transfers. Deferred with FR-P-10, whose chains it would list (FR-CH-14 in [`docs/FUTURE-UDP-CHAINS.md`](docs/FUTURE-UDP-CHAINS.md)). | manual |
| FR-C-05 | M | Diagnostics SHALL go to stderr with a recognizable prefix, at a verbosity set by `UDPCHAINS_QUIET`/`-q` and `UDPCHAINS_DEBUG`/`-v`. | manual |
| FR-C-06 | S | At default verbosity the shim SHALL print one line per association established, naming the destination — so the operator can see that proxying is actually happening. | manual |

## 6. Non-functional

| ID | Pri | Requirement | Verify |
|---|---|---|---|
| NFR-01 | M | C11, glibc, Linux. Build with `make` + a C compiler and **no third-party dependencies**. | inspection |
| NFR-01a | M | The minimum supported glibc SHALL be **2.34**, set by `close_range` (`close_range@@GLIBC_2.34`; the syscall itself needs Linux 5.9). Every other hooked call is available far earlier — `recvmmsg` 2.12, `sendmmsg` 2.14, `dup3` 2.9, `sendmsg`/`recvmsg` 2.2.5 — so if an older target is required, the `close_range` hook SHALL be conditionally compiled rather than the floor being raised for everything else. The build SHALL fail with a clear message on an unsupported glibc rather than producing a shim with a silently missing hook (see FR-I-02). | inspection |
| NFR-02 | M | No dynamic allocation on the per-datagram path; header assembly SHALL use a thread-local scratch buffer sized to the configured maximum. | inspection |
| NFR-03 | M | The shim SHALL be async-signal-safe enough not to deadlock when an application sends from a signal handler, or SHALL document the limitation explicitly. | inspection |
| NFR-04 | S | Added latency SHALL be under 100 µs per datagram on loopback, excluding proxy and network time. | manual (benchmark) |
| NFR-05 | M | The shim SHALL NOT write payload bytes to any log at any verbosity. | inspection |
| NFR-06 | S | Source SHALL build warning-free under `-Wall -Wextra -Werror`. | inspection |

## 7. Security

| ID | Pri | Requirement | Verify |
|---|---|---|---|
| SEC-01 | M | **Fail closed.** If a datagram cannot be proxied for any reason — proxy unreachable, association refused, oversized payload — the call SHALL fail with an appropriate `errno`. The shim SHALL NEVER fall through to sending the datagram directly. This is the defect that motivates the project (§0.3.1). | unit, integration |
| SEC-02 | M | A "leak test" SHALL exist which, with the proxy stopped, asserts that **no** UDP packet reaches the destination by any path. | integration |
| SEC-03 | M | Proxy credentials SHALL be readable from a file or environment variable, never required on the command line (visible in `ps`). | inspection |
| SEC-04 | S | The shim SHALL warn if its config file is group- or world-writable, since that file directs where traffic goes. | unit |
| SEC-05 | M | The shim SHALL open no listening socket. | inspection |
| SEC-06 | M | Behaviour under setuid/setgid targets SHALL be documented: the loader ignores `LD_PRELOAD`, so such programs run **unproxied**. The wrapper SHALL detect this case and refuse rather than run them unproxied. | unit |

## 8. Explicit non-goals

Documenting these prevents scope creep and sets user expectations honestly.

| Non-goal | Rationale |
|---|---|
| Statically-linked binaries | No libc to interpose on. Unfixable by this approach. Not a permanent non-goal: a supervisor mode that does not use `LD_PRELOAD` is planned after 0.1.0, see [`docs/FUTURE-STATIC-BINARIES.md`](docs/FUTURE-STATIC-BINARIES.md). |
| Go binaries | Go issues raw syscalls, bypassing libc entirely. Unfixable by this approach. Planned with static binaries, see [`docs/FUTURE-STATIC-BINARIES.md`](docs/FUTURE-STATIC-BINARIES.md). |
| setuid/setgid binaries | The loader drops `LD_PRELOAD`. See SEC-06. |
| Direct `syscall()` users | Same reason. Only interception at the system-call boundary can see them; out of scope for v1. Planned with static binaries, see [`docs/FUTURE-STATIC-BINARIES.md`](docs/FUTURE-STATIC-BINARIES.md). |
| Faithful ancillary data (`IP_PKTINFO`, `IP_RECVERR`, ECN) | Describes a socket the application does not actually own; no honest emulation exists. Returned empty (FR-F-11). |
| GSO/GRO (`UDP_SEGMENT`, `UDP_GRO`) | Tier 3. Modern QUIC stacks use these; they will fall back or fail. |
| QUIC performance | Even when functional, a UDP flow through a TCP-based tunnel inherits retransmit-and-wait behaviour that fights QUIC's own loss recovery. |
| TCP proxying | `proxychains-ng` already does this well. Composing the two is acceptable; reimplementing is not. |
| Proxy chains (multi-hop UDP) | FR-P-10. Disproportionate complexity for v1. Not a permanent non-goal: planned after 0.1.0, see [`docs/FUTURE-UDP-CHAINS.md`](docs/FUTURE-UDP-CHAINS.md). |

## 9. Testing

| ID | Pri | Requirement |
|---|---|---|
| TST-01 | M | **The hook matrix.** A purpose-built probe SHALL exercise every send function × every receive function ({`sendto`, `send`, `write`, `writev`, `sendmsg`, `sendmmsg`} × {`recvfrom`, `recv`, `read`, `readv`, `recvmsg`, `recvmmsg`}) against an echo server, asserting byte-identical round-trips. This matrix is what distinguishes tier 2 from the existing tools; it SHALL be the primary regression gate. |
| TST-02 | M | An exported-symbol check (`nm -D`) SHALL assert every function named in FR-I-03/04/05 is present. A missing receive hook SHALL fail the build. |
| TST-03 | M | Leak test per SEC-02: proxy down, assert zero packets reach the destination. |
| TST-04 | M | Real-tool integration: `dig`, `nc -u`, `ntpdate` or `chronyd -Q`, `tftp`, and `iperf3 -u` SHALL each work through the shim against a live SOCKS5 proxy. |
| TST-05 | M | Fidelity tests for FR-F-01…FR-F-10: truncation, `MSG_PEEK`, zero-length, `errno` values, `connect`/re-`connect`/`AF_UNSPEC`, IPv6, scatter/gather with a split header. |
| TST-06 | M | Lifecycle tests: `dup` sharing, fd reuse after `close`, `fork` isolation, `FD_CLOEXEC`. |
| TST-07 | S | A threaded stress test: N threads on one fd and on separate fds, asserting no crashes, no cross-delivery, no leaked associations. |
| TST-08 | S | Run the whole suite under ASan/UBSan and Valgrind. |

## 10. Acceptance criteria

1. Every **M** requirement is implemented and its verification passes.
2. The TST-01 hook matrix is 100% green — no cell silently corrupts or drops data.
3. The TST-03 leak test passes: with the proxy down, nothing reaches the destination.
4. `dig`, `nc -u` and `iperf3 -u` work through the shim against the reference proxy, with the
   reference proxy's own logs confirming the traffic arrived via the tunnel.
5. `make` succeeds from a clean clone with only a C compiler present; no downloads.
6. The README states the §8 non-goals plainly, including the Go and static-binary limitation.

## 11. Risk register

| Risk | Impact | Mitigation |
|---|---|---|
| Silent corruption from a missed hook | High — the exact defect being fixed | TST-01 matrix + TST-02 symbol check as build gates |
| Silent direct-send leak | High — defeats the purpose, invisible | SEC-01 fail-closed, TST-03 leak test |
| fd-table races under threading | Medium — rare crashes, hard to reproduce | TST-07 stress test under ASan |
| Application uses `recvmsg` ancillary data | Medium — misbehaviour with no clear cause | FR-F-11 returns empty; document in README |
| Proxy expires an idle association | Low — flow stops working after a pause | FR-P-08 transparent re-association |
| Effort underestimated | Medium | Baseline recorded in §0.4 (~1–2 weeks); milestones below are ordered so something works on day one, making slippage visible early |
| Implementation accidentally derived from GPL-2.0 sources | Medium — relicensing after the fact is painful | §0.4 licensing stance: clean-room from RFC 1928 unless GPL-2.0 is adopted deliberately |

## 12. Implementation order

| # | Deliverable | Done when |
|---|---|---|
| M1 | Build skeleton, `dlsym(RTLD_NEXT)` plumbing, config parsing, wrapper executable | `udpchains /bin/true` runs; unknown config fails closed |
| M2 | SOCKS5 client: control connection, `UDP ASSOCIATE`, header encode/decode | Unit tests for all three `ATYP` forms pass |
| M3 | Tier-1 path: `socket`, `sendto`, `recvfrom`, `close` | `dig @<server> -p <port>` works through the shim |
| M4 | Connected sockets: `connect`, `send`, `recv`, `write`, `read`, `getpeername`, `getsockname` | Hook matrix green for those cells |
| M5 | `sendmsg`/`recvmsg`/`sendmmsg`/`recvmmsg`, scatter/gather, `MSG_PEEK`, truncation | TST-01 matrix fully green; TST-05 passes |
| M6 | Lifecycle: `dup`, fd reuse, `fork`, `FD_CLOEXEC`, threading | TST-06, TST-07 pass |
| M7 | Fail-closed guarantees, leak test, IPv6 | SEC-01/02 verified; `nc -6 -u` works |
| M8 | Real-tool integration, README, non-goals documented | TST-04 passes; acceptance criteria met |

Build M3 first and test against a live proxy before going further — a working `dig` on day one
validates the whole architecture, and every later milestone is an increment on a thing that runs.

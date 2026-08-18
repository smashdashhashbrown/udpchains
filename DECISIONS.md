# Decision Record — `udpchains`

Decisions taken before implementation began, against the baseline
[`UDP-PRELOAD-REQUIREMENTS.md`](UDP-PRELOAD-REQUIREMENTS.md) (commit `ba07249`).

The requirements document is the **baseline** and is not edited. This file records what was decided
where that document deferred a choice, contained an internal tension, or left a gap. Each entry
states what would cause it to be reopened, so that a later change is a visible amendment rather than
a silent drift.

**Date decided:** 2026-08-17 · **Status of all entries:** Accepted

| ID | Decision | Resolves |
|---|---|---|
| [D-01](#d-01) | Clean-room implementation, MIT licence | §0.4 (explicitly deferred) |
| [D-02](#d-02) | Own repository | §0.4 (confirmed) |
| [D-03](#d-03) | Name stays `udpchains` | §0.4 (deferred) |
| [D-04](#d-04) | DNS proxied as ordinary UDP | Gap — §0.1 raises DNS, no requirement covers it |
| [D-05](#d-05) | No bypass in v1, with four riders | Tension — FR-I-08/09 vs SEC-01 |
| [D-06](#d-06) | In-repo C test-proxy fixture | Gap — TST-01/03/05 need a peer |
| [D-07](#d-07) | Lock-free two-level fd table | NFR-03 (explicit either/or) |
| [D-08](#d-08) | v1 SHOULD scope | §0.2 scope control |
| [D-09](#d-09) | glibc floor 2.34, `close_range` conditional | NFR-01a (confirmed) |
| [D-10](#d-10) | No built-in default proxy | Tension — FR-C-02 vs FR-C-03 |
| [D-11](#d-11) | Asymmetric buffer strategy | NFR-02 (mechanism unspecified) |
| [D-12](#d-12) | Datagram limit configured, not discovered | Gap — FR-F-07 assumes the limit is known |
| [D-13](#d-13) | One association per app socket, shared on `dup` | Derived from FR-P-02 + FR-L-03 |
| [D-14](#d-14) | IPv4-mapped destinations are emitted as `ATYP 0x01` | Interop defect found against a real proxy |

---

## D-01
### Licensing: clean-room implementation, MIT licence

**Context.** §0.4 requires this be settled before the first commit and records no decision. Both
tools cited as evidence in §0.3 — `proxychains-ng` and `Proxando` — are GPL-2.0, and the thing this
project needs most (a SOCKS5 `UDP ASSOCIATE` client) sits in their source, making accidental
derivation easy.

**Decision.** Clean-room. The protocol is implemented from **RFC 1928 §7**, **RFC 1929** (if D-08 is
revisited), and the relevant man pages (`udp(7)`, `socket(7)`, `recvmsg(2)`, `sendmmsg(2)`,
`close_range(2)`). The project carries **MIT**.

**Working rule, binding on all contributors.** Do not open, read, copy from, or paste from
`proxychains-ng` or `Proxando` source at any point during implementation. Citing their *observed
behaviour* — as §0.3 does — is fine and remains fine. Reading their source to "check an approach" is
not, because it contaminates the clean-room claim retroactively and relicensing after the fact is
painful (§11).

**Consequences.**
- The SOCKS5 client is written from the RFC. Budget a little more time in M2 than copying would take.
- Any contribution must be accompanied by a statement that it is not derived from GPL-2.0 sources.
- The project is free to be vendored by MIT/Apache/BSD/proprietary consumers.

**Revisit if.** The author decides deliberately to derive from proxychains-ng. That is a legitimate
choice per §0.4, but it means adopting GPL-2.0 wholesale and giving attribution — and it cannot be
taken after clean-room code exists without auditing what came from where.

---

## D-02
### Repository placement: its own repository

**Context.** §0.4 states this; recorded here as confirmed rather than re-argued.

**Decision.** `udpchains` lives in its own repository. It is not a subdirectory of any proxy it is
tested against, including the reference `dtun-client`.

**Consequences.** The shim speaks only standard SOCKS5 and works with any RFC 1928 proxy offering
`UDP ASSOCIATE`; coupling it to one implementation would misrepresent its scope and would drag a C
toolchain into a project that may not have one.

**Revisit if.** Never expected to change.

---

## D-03
### Name

**Context.** §0.4 offers the working name for renaming.

**Decision.** Keep `udpchains`. Binary `udpchains`, shim `libudpchains.so`, env prefix
`UDPCHAINS_*`, config `udpchains.conf`.

**Consequences.** The name deliberately echoes `proxychains` to signal the ergonomic relationship
(FR-C-01, FR-C-04). Accept the mild risk of being mistaken for an official proxychains component;
the README should state the relationship plainly.

**Revisit if.** Before the first public release — renaming is cheap now, expensive once packaged.

---

## D-04
### DNS: proxied as ordinary UDP, with no special case

**Context.** §0.1 cites DNS leakage as part of the motivation, but no requirement in §1–§9 mentions
DNS. Unlike `proxychains-ng`, this project does **not** hook `getaddrinfo`/`gethostbyname`. It does
not need to: glibc's resolver sends over ordinary UDP sockets through libc, so resolver traffic is
intercepted by the existing hooks with no DNS-specific code.

**Decision.** No DNS special case. Resolver traffic is proxied exactly like any other UDP. No port-53
exemption, no `getaddrinfo` hook, no shared association for resolver sockets.

**Consequences.**
- No DNS leak by construction, consistent with SEC-01. This is the primary reason for the choice.
- **One association per resolution burst.** A program doing many lookups creates many short-lived
  TCP control connections to the proxy. Compounds with D-05; see the capacity note there.
- **Resolver TCP fallback is not proxied.** When an answer exceeds the UDP limit and glibc retries
  over TCP, that traffic is outside this project's scope — TCP proxying is a §8 non-goal. The README
  must say so; composing with `proxychains-ng` is the documented answer.
- **Interacts with D-05.** On a systemd-resolved host the stub resolver is `127.0.0.53:53`, a
  loopback destination. With no bypass, that query goes to the proxy and is resolved against the
  *proxy host's* `127.0.0.53`. Against a local proxy this works; against a remote proxy DNS breaks or
  answers from the wrong host. Rider R2 in D-05 exists specifically to make this visible.
- **Test consequence.** TST-04's `dig` case must use an explicit `@server`, or it will pass for the
  wrong reason on a systemd-resolved machine.

**Revisit if.** Association setup cost measurably dominates real workloads. The fallback is a shared
association pooled across resolver sockets, which was considered and rejected for v1 as a second
association model to get right alongside the per-fd one (D-13).

---

## D-05
### Bypass policy: none in v1

**Context.** FR-I-08 (**S**) wants loopback destinations to bypass the proxy by default and FR-I-09
(**C**) wants the same for multicast/broadcast. SEC-01 (**M**) says a datagram that cannot be proxied
must fail and the shim must *never* send it directly. A bypass **is** a direct send, so as written
these cannot both hold. SEC-01 is **M** and is the defect the project exists to fix; FR-I-08/09 are
**S** and **C**.

**Decision.** **v1 has no bypass path of any kind.** Every intercepted datagram is either proxied or
fails. There is no rule engine, no allowlist, no configuration to disable proxying for a destination.
FR-I-08 and FR-I-09 are **deferred, not dropped** (see D-08).

Four riders were adopted with this decision and are binding requirements on v1:

- **R1 — Specific diagnostics for the impossible cases.** Multicast and broadcast destinations
  (`224.0.0.0/4`, `ff00::/8`, `255.255.255.255`) fail with `ENETUNREACH` **and** a one-line stderr
  diagnostic naming the reason. SOCKS5 cannot express these destinations, so failure is the only
  honest outcome — but the user must not have to guess why.
- **R2 — Loopback-versus-remote-proxy guard.** When a destination is loopback (`127.0.0.0/8`, `::1`)
  and the configured proxy is **not** on this host, emit a diagnostic at association time. FR-C-06
  already prints one line per association, so this is nearly free. A config knob promotes it to a
  hard error.
- **R3 — Deferred, not dropped.** FR-I-08/FR-I-09 stay in the traceability matrix marked deferred,
  with TST-03 standing as the gate any future bypass implementation must pass unchanged.
- **R4 — Honest README.** The README states plainly that local UDP services and service discovery do
  not work under the shim, and why.

**Consequences.**
- **TST-03 becomes an unqualified assertion**: proxy down → zero UDP packets leave the host, with no
  whitelist of expected direct traffic. A bypass rule set would require the leak test to encode its
  own exceptions, and that exception list is exactly where a leak hides.
- **No rule engine** to write, configure, document, or test — removing the historically common leak
  source of an over-broad bypass rule.
- **Local UDP services break or misroute.** `127.0.0.1` is resolved *at the proxy*. statsd on 8125,
  syslog on 514, a local chrony, systemd-resolved — all reach the proxy host's loopback. With a local
  proxy this works and looks correct; with a remote proxy it fails or, worse, succeeds against a
  different machine's daemon. That silent-wrong-destination case is the same class of defect the
  project exists to eliminate, which is why R2 exists.
- **Service discovery hard-fails** rather than degrading: mDNS (5353), SSDP (1900), LLMNR, DHCP
  broadcast, NetBIOS. Note that `setsockopt` is not hooked, so `SO_BROADCAST` and
  `IP_ADD_MEMBERSHIP` still *succeed* and the subsequent send then fails. Odd-looking but not
  dishonest; R1 makes it legible.
- **The 8192-byte ceiling now applies to local traffic**, which loopback would otherwise carry at up
  to 64 KB. Large local datagrams get `EMSGSIZE` (FR-F-07).
- **Association cost.** Every UDP socket including short-lived local ones gets a control connection
  and an association, held ~60 s by the reference proxy's idle expiry. Compounds with D-04.

**Revisit if.** Users demand bypass. Adding it later is purely additive — a rule consulted *before*
the proxy path, never as a fallback after a proxy attempt fails. The known hazard is that it would
then be built under time pressure, which is when leak-causing rule bugs get written; TST-03 existing
from v1 is the mitigation.

---

## D-06
### Test proxy: minimal SOCKS5 server as an in-repo C fixture

**Context.** TST-01 (hook matrix), TST-03 (leak test) and TST-05 (fidelity) all need a live SOCKS5
peer supporting `UDP ASSOCIATE`. The reference `dtun-client` (§0.5) is Java, which would put a JDK on
the CI path, and its failure modes cannot be triggered on demand.

**Decision.** Write a minimal SOCKS5 `UDP ASSOCIATE` server as a test fixture in the repository,
in C, built by the same `make`. Paired with a trivial UDP echo server for the TST-01 matrix.

The fixture supports **fault injection**, which is the main reason it exists rather than being
borrowed:

| Mode | Exercises |
|---|---|
| refuse `UDP ASSOCIATE` | SEC-01, FR-L-06 |
| expire association after N seconds | FR-P-08 |
| drop every Nth datagram | fail-closed paths |
| inject `FRAG != 0` | FR-P-04 |
| enforce peer lock on first sender | FR-P-06 |
| configurable max datagram | FR-F-07 / `EMSGSIZE` |
| delay response by N ms | timeout handling |
| accept/reject specific `ATYP` | FR-P-03, FR-P-07 |

**Consequences.**
- `make && make test` stays dependency-free, honouring NFR-01 in spirit for the test path too.
- Interop against the real `dtun-client` remains a **separate, manual** acceptance step (TST-04,
  acceptance criterion 4). The fixture proves correctness against the RFC; it does not prove
  interop. Do not let a green fixture suite substitute for the real-proxy run.
- The fixture is test-only code and must never be linked into the shipped shim.

**Revisit if.** The fixture starts diverging from real proxy behaviour — at which point the bug is
in the fixture and the interop step is what will reveal it.

---

## D-07
### Concurrency: lock-free two-level fd table

**Context.** NFR-03 offers an explicit either/or: be async-signal-safe enough not to deadlock, or
document the limitation. FR-L-01 (**M**) requires the per-fd table be safe under concurrent access,
and NFR-02 (**M**) forbids dynamic allocation on the per-datagram path. These three are one design
problem, not three.

**Decision.** Signal-safe by construction, via a **two-level radix table** indexed by fd: a
fixed top-level array of atomic pointers to blocks of entries, blocks allocated on demand.

- Allocation happens only in `socket()`/`dup*()`, never on the datagram path — satisfying NFR-02
  without a fixed fd ceiling chosen at startup.
- The datagram path is atomic loads only: index → block → entry. No locks, no allocation, no
  syscalls beyond the real one. Satisfies NFR-03 without a documented caveat.
- Slot lifecycle uses an atomic state enum plus a generation counter, so an fd reused after `close()`
  cannot inherit stale state (FR-L-02).

**Consequences.**
- Memory ordering must be got right and reviewed deliberately; this is the part of the codebase most
  likely to harbour a rare, hard-to-reproduce bug (§11 names this risk).
- TST-07 (threaded stress under ASan/TSan) is promoted from **S** to effectively mandatory — it is
  the only thing that verifies the **M** requirement FR-L-01. See D-08.
- No fd ceiling, no `RLIMIT_NOFILE` snapshot at init, no failure mode when the app raises its own
  limit at runtime.

**Revisit if.** Never expected to weaken. If lock-freedom proves unworkable for some operation, the
fallback is a lock on the *mutation* path only (`socket`/`close`/`dup`) with the datagram path still
lock-free — not a global mutex, which would forfeit NFR-03.

---

## D-08
### v1 scope for SHOULD-priority requirements

**Context.** §0.4 asks that scope creep be visible. The **S** items needed a positive in/out call
each rather than drifting.

**In v1:**

| ID | Item | Note |
|---|---|---|
| FR-P-08 | Transparent re-association | The reference proxy expires at 60 s idle; without this, any flow with a pause dies permanently and presents as a shim bug |
| FR-F-11 | Ancillary data returned empty | Required for correctness; largely "return nothing" |
| FR-L-06 | Proxy-unreachable reported on send | Already implied by SEC-01 |
| FR-C-06 | One line per association | R2 in D-05 depends on it |
| SEC-04 | Warn on group/world-writable config | ~10 lines |
| NFR-06 | `-Wall -Wextra -Werror` | Trivial if done from the first commit, painful if retrofitted |
| NFR-04 | Latency benchmark | Included as a **reported number**, not a hard gate — a CI-enforced µs threshold is a flaky-test generator |
| TST-07 | Threaded stress test | Verifies the **M** requirement FR-L-01; effectively mandatory given D-07 |
| TST-08 | ASan/UBSan/Valgrind | Cheap in CI, and the only realistic way to catch D-07's failure modes |

**Deferred to post-v1:**

| ID | Item | Why deferred |
|---|---|---|
| FR-I-08 | Loopback bypass | D-05 |
| FR-I-09 | Multicast/broadcast bypass | D-05 — these fail with `ENETUNREACH` per rider R1 |
| FR-P-09 | RFC 1929 username/password auth | The reference proxy offers only method `0x00`, so v1 cannot exercise it end to end; the fixture (D-06) would have to grow auth support to test a path with no reference behaviour to validate against |
| FR-C-04 | `proxychains.conf`-style `[ProxyList]` | Ergonomic rather than functional; a second config syntax to test and document |
| FR-P-10 | Proxy chains | Already a §8 non-goal |

**Consequences.** Deferring FR-P-09 means SEC-03 (credentials never on the command line) has nothing
to guard in v1. Implement SEC-03's file/environment credential plumbing anyway so that adding
FR-P-09 later does not tempt anyone into a `--password` flag.

**Revisit if.** A target proxy requires authentication — FR-P-09 then becomes blocking, not
optional.

---

## D-09
### Toolchain floor: glibc 2.34, `close_range` conditionally compiled

**Context.** NFR-01a prescribes this; recorded as confirmed.

**Decision.** Minimum glibc **2.34**, set solely by `close_range@@GLIBC_2.34` (the syscall needs
Linux 5.9). Every other hooked call is available far earlier. If an older target is needed, the
`close_range` hook is conditionally compiled out rather than the floor being lowered for everything
else. The build fails with a clear message on an unsupported glibc.

**Consequences.** A shim with a silently missing hook is the FR-I-02 failure mode; a build that
fails loudly is not. TST-02's `nm -D` check must be aware of the conditional so it asserts the right
symbol set for the build configuration, rather than failing spuriously.

**Revisit if.** A required deployment target predates glibc 2.34.

---

## D-10
### Configuration: no built-in default proxy

**Context.** FR-C-02 lists a "built-in default" as the last precedence tier; FR-C-03 requires that
missing or unparseable configuration refuse to run the program rather than run it unproxied. Taken
literally, a built-in default would mean configuration is never truly missing, and FR-C-03 could
never fire.

**Decision.** Split the two. **There is no built-in default proxy address.** Built-in defaults exist
only for optional settings — maximum datagram size (D-12), verbosity, timeouts, the loopback-guard
knob (D-05 R2). If no proxy address is resolved from command line, environment, or config file, the
wrapper prints a diagnostic and **exits without exec-ing the target**.

**Consequences.**
- FR-C-03 is meaningful and testable: no proxy configured → non-zero exit, target never runs.
- Fail-closed extends to configuration, not just to the datagram path. A user who typos
  `UDPCHAINS_PROXY` gets an error, not an unproxied program.
- The wrapper must resolve configuration *before* `exec`, so the failure is attributable and not
  emitted from inside the target's address space.

**Revisit if.** Never expected to change; a default proxy address would reintroduce the silent-leak
class of failure at the configuration layer.

---

## D-11
### Buffers: zero-copy send, single-copy receive

**Context.** NFR-02 requires no per-datagram allocation and specifies a thread-local scratch buffer,
but the send and receive paths have different constraints and the same mechanism does not suit both.

**Decision.** Asymmetric, deliberately.

- **Send — zero copy.** The SOCKS5 header is assembled in a small thread-local buffer and passed to
  the real `sendmsg` as the **first `iovec` entry**, with the application's own buffers following.
  The payload is never copied. Scatter/gather (FR-F-10) falls out for free, and FR-F-01 is satisfied
  by returning the application's byte count rather than the wrapped length.
- **Receive — one copy into a thread-local scratch buffer.** The full wrapped datagram is read into
  scratch, the header parsed, and the payload copied into the application's iovecs. Scratch is sized
  `max_datagram + 262` (262 = largest possible header: 3 + 1 + 255 + 2 for a domain `ATYP`).

**Why receive does not use the same iovec trick.** Header length is not known until `ATYP` is read,
so reserving a worst-case 262-byte header slot would place the first bytes of payload inside the
reserved region and require a `memmove` to correct — the copy comes back, with an off-by-one hazard
attached. The scratch approach also makes three separate requirements straightforward rather than
delicate: FR-F-04 (true length known, so `MSG_TRUNC` and the true-length return are exact),
FR-F-05 (`MSG_PEEK` reads into scratch and leaves the datagram queued), and FR-F-10 (header split
across iovec boundaries cannot occur, because the header never lands in application buffers).

**Consequences.** One `memcpy` of at most 8 KB per received datagram — on the order of 200 ns,
against NFR-04's 100 µs budget. Not a concern; the asymmetry is documented so it is not later
"fixed" into a bug.

**Revisit if.** NFR-04 measurements show the receive copy is material, which is not expected.

---

## D-12
### Datagram size limit is configured, not discovered

**Context.** FR-F-07 requires `EMSGSIZE` for a payload exceeding "the proxy's datagram limit", but
SOCKS5 provides no way to learn that limit. The reference proxy's 8192 (§0.5) is a property of that
implementation.

**Decision.** The limit is a **configuration value**, defaulting to **8192** to match the reference
proxy. The shim checks the application's payload length against it before wrapping and returns
`EMSGSIZE` if exceeded. The shim never fragments and never emits `FRAG != 0` (FR-P-04).

**Consequences.**
- Configuring the limit too high produces silent drops at the proxy — the failure the requirement
  was written to prevent. FR-C-06's association line should report the configured limit so a
  mismatch is diagnosable.
- The check is against the *payload* length the application supplied, not the wrapped length, so the
  header does not eat into the application's usable budget in a way that would surprise.

**Revisit if.** A proxy is encountered that advertises its limit, or the limit needs to be per-proxy
once multiple proxies are configurable.

---

## D-13
### Association model: one per application socket, shared by refcount on `dup`

**Context.** Derived rather than chosen — FR-P-02 ties the control connection to the application
socket's lifetime, FR-P-06 requires all datagrams for one association to leave from one stable local
socket, and FR-L-03 requires duplicated descriptors to share one association. Recorded because the
combination is load-bearing and easy to violate later.

**Decision.** One association object per application socket, holding the TCP control connection and
the relay address. Duplicated descriptors (`dup`/`dup2`/`dup3`) share the object by **refcount**; it
is torn down when the last descriptor closes (FR-L-02, FR-L-03). Because FR-I-07 redirects the
application's own fd to the relay, the association owns no data socket of its own — which is what
makes FR-P-06 automatic.

Fork (FR-L-04) is handled by a generation counter: a `pthread_atfork` child handler bumps a global
generation and does nothing else — deferring all real work off the handler, where async-signal-safety
constraints bite. On next use, an association whose generation is stale is torn down (closing the
inherited control fd, which is safe: the parent holds its own reference, so no FIN is sent) and a
fresh association is established. Control-connection fds are `FD_CLOEXEC` (FR-L-05).

**Consequences.** Association count scales with concurrently-open UDP sockets, which is the capacity
concern noted in D-04 and D-05. Accepted for v1; pooling would mean a second association model.

**Revisit if.** Association count becomes a practical limit against real proxies.

---

## D-14
### IPv4-mapped destinations are emitted as `ATYP 0x01`, never `ATYP 0x04`

**Date:** 2026-08-18 · **Status:** Accepted · Recorded after v1 implementation, in response to an
interop failure against a real proxy.

**Context.** An application that opens an `AF_INET6` dual-stack socket and connects to an IPv4
destination ends up with `::ffff:a.b.c.d` as its destination address. This is not an edge case: it
is what `getaddrinfo`-based clients, `nc`, and most modern runtimes do by default on a dual-stack
host, without the application asking for it or being able to see it.

The original encoder branched on `sa_family` alone, so such a destination was written into the SOCKS5
header as `ATYP 0x04` with all sixteen bytes. That asks the proxy to reach an IPv6 address which, as
an IPv6 address, does not exist.

**How it presented.** Against a real SOCKS5 proxy: `UDP ASSOCIATE` succeeds, the association looks
healthy from both ends, the control connection stays open, and the datagram simply never arrives at
the destination. No error on either side. The proxy has no reason to log anything — it forwarded, or
declined to forward, an address it was given.

**Why the test suite missed it.** The in-repo fixture (D-06) uses a dual-stack relay socket. It
decoded the mapped address and sent it from that socket, where the kernel converted it back to IPv4
and delivered it. Two bugs cancelling: the shim sent the wrong form, the fixture forgave it, and the
108-cell hook matrix stayed green. The IPv6 tests all used genuine `::1` addresses on both ends, so
the mapped case was never exercised at all.

This is exactly the failure mode D-06 named — "a green fixture suite is not evidence of interop" —
arriving in precisely the shape predicted.

**Decision.**

- The header encoder normalises: an `AF_INET6` address that satisfies `IN6_IS_ADDR_V4MAPPED` is
  emitted as `ATYP 0x01` with the four embedded bytes. A genuine IPv6 address still uses `ATYP 0x04`.
  This applies to datagram headers and to the address declared in the `UDP ASSOCIATE` request.
- Symmetrically on receive, the source address is reported in the **socket's own** family: an
  `AF_INET6` socket that heard from an IPv4 peer is told `::ffff:a.b.c.d`, which is what the kernel
  would have told it. An `AF_INET` sockaddr is not something such an application has anywhere to put.
- **The fixture is now strict about this**: `ATYP 0x04` carrying a v4-mapped address is rejected and
  logged rather than quietly forwarded, so the fixture can no longer conceal this class of defect.

**Consequences.**
- The dual-stack-to-IPv4 path is now covered by a byte-level unit test and an end-to-end test, both
  of which fail against the old encoder.
- The fixture became less forgiving than a permissive real proxy. That is the right direction: a test
  double should be stricter than production, not more lenient, or it certifies nothing.

**Revisit if.** A proxy is found that requires the mapped form. None should — RFC 1928 has a
dedicated IPv4 address type, and a v4-mapped address in an IPv6 field is a client bug.

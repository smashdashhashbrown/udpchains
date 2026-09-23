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
| [D-15](#d-15) | A connected socket receives only from its connected peer | Fidelity gap vs. an unhooked socket |

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

**Outcome.** The premise was false for every supported glibc. Since 2.34 — this project's floor —
the resolver lives inside libc and creates, connects and sends on its sockets through internal
aliases, so no hook fires. With the proxy down, `getaddrinfo()` still resolved, and the raw query
went to `127.0.0.53`. "No DNS leak by construction" did not hold for any program that resolves
names through libc; `dig` passed interop only because it carries its own resolver. Superseded by
**D-22**.

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
| FR-P-09 | RFC 1929 username/password auth | **Superseded by D-20 — implemented before release.** Originally deferred because the reference proxy offered only method `0x00` |
| FR-C-04 | `proxychains.conf`-style `[ProxyList]` | Ergonomic rather than functional; a second config syntax to test and document |
| FR-P-10 | Proxy chains | Already a §8 non-goal |

**Consequences.** Deferring FR-P-09 means SEC-03 (credentials never on the command line) has nothing
to guard in v1. Implement SEC-03's file/environment credential plumbing anyway so that adding
FR-P-09 later does not tempt anyone into a `--password` flag.

**Revisit if.** A target proxy requires authentication — FR-P-09 then becomes blocking, not
optional.

**Outcome.** FR-P-09 was implemented before release; see **D-20**. The plumbing decision above is
what made that a small change rather than a redesign: the credential path already existed and had
nowhere to leak to.

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

---

## D-15
### A connected socket receives only from its connected peer

**Date:** 2026-08-18 · **Status:** Accepted · Recorded after v1 implementation, prompted by a
question about how TFTP behaves under the shim.

**Context.** An unhooked connected UDP socket receives only from the peer it is connected to; the
kernel drops everything else before the application sees it. That is why TFTP clients use an
*unconnected* socket — a TFTP server replies from a different port than the one addressed, and a
connected socket would discard the reply.

Under the shim, every datagram arrives from the relay, so the kernel's filter can never fire. The
receive path discarded only oversized, malformed and `FRAG != 0` datagrams, and delivered everything
else.

**The gap.** The shim was **more permissive** than a real socket. A program that had called
`connect()` would receive datagrams a real socket would have dropped. That is the wrong direction for
§3's mandate that the shim be indistinguishable from an unhooked socket, and it silently removes a
source filter some programs rely on. It also meant a TFTP client that (incorrectly) connected to port
69 would work under the shim and fail without it — the shim masking a difference rather than
preserving one.

**Decision.** The receive path reimplements the filter against the true origin in the SOCKS header.
When the socket is connected and the reply carries a usable address, a datagram whose origin is not
the connected peer is discarded and the receive continues, exactly as the kernel would.

Two deliberate exceptions:

- **Domain-form replies** (`ATYP 0x03`) carry no address to compare. They are delivered, because the
  alternative is resolving a name on the receive path, which would both leak a lookup and be a lie.
- **Both addresses are normalised to the socket's family before comparing.** An `AF_INET6` socket
  connected to `::ffff:a.b.c.d` whose proxy reports the origin as plain IPv4 is talking to the same
  peer; comparing raw forms would reject every datagram. This is the D-14 v4-mapped trap in the
  opposite direction, and it would have been easy to introduce while fixing this.

**Consequences.** TFTP, which uses an unconnected socket, is unaffected and still works. A program
using `connect()` as a source filter keeps that filter. The cost is one address comparison per
received datagram, off the allocation path.

**Revisit if.** A proxy is found that reports origins in a form that cannot be normalised to the
socket's family, which would cause every datagram to be dropped. The `-v` output names the rejected
origin, so this would be diagnosable rather than mysterious.

---

## D-16
### A loopback or wildcard `BND.ADDR` is replaced by the proxy's own address

**Date:** 2026-08-19 · **Status:** Accepted · Recorded after the first run against a genuinely
**remote** proxy.

**Context.** RFC 1928 §7 says the `UDP ASSOCIATE` reply's `BND.ADDR`/`BND.PORT` is where the client
must send its datagrams. The shim already substituted the configured proxy address when `BND.ADDR`
was a wildcard (`0.0.0.0` / `::`), on the standard reading that a wildcard means "the address you
already reached me on".

**The gap.** A proxy may equally return a **loopback** address, because that is genuinely what it
sees: it binds a relay socket and reports the address it bound. That is correct information about the
proxy's own host and useless to a client anywhere else. Taken literally it pointed the application's
socket at *this* host's loopback, where nothing is listening.

The failure was silent and its symptoms pointed away from the cause. Datagrams left successfully.
The association looked healthy at both ends. Nothing arrived, and the ICMP port-unreachable that came
back surfaced as `ECONNREFUSED` on the next receive — which FR-P-08 reads as an expired association,
so the shim re-associated, got another loopback relay, and repeated.

**Decision.** A loopback `BND.ADDR` is replaced by the configured proxy address, keeping the relay
port, **when and only when the proxy is not on this host**. `proxy_is_local` already exists for D-05
R2 and is reused here.

The gate matters in both directions. With a local proxy a loopback relay is correct and must survive
untouched — that is every test run before this one. With a remote proxy it is unusable by
construction, so substituting cannot lose information the client could otherwise have used.

A **routable** `BND.ADDR` that differs from the proxy address is left alone: a proxy that relays from
a different host than it accepts control connections on is legitimate, and second-guessing it would
break a valid deployment to fix an invalid one.

**Why the test suite missed it.** The fixture (D-06) runs on the same host as its clients, so
`proxy_is_local` was true in every automated run and the loopback relay it advertises was always
correct. No fixture run could reach this. The fixture gained `--dead-relay` to reproduce the
downstream symptom, and the substitution itself is unit-tested with a synthetic non-local
configuration, since a single host cannot produce one.

**Revisit if:** a proxy is found that returns a loopback `BND.ADDR` and genuinely means it — which
would require the client to be in the same network namespace while the proxy is not considered local.

---

## D-17
### A non-`FREE` fd-table entry at claim time is stale, and is recycled

**Date:** 2026-08-19 · **Status:** Accepted · Found while investigating D-16's downstream symptoms.

**Context.** The fd table is populated in the `socket()` hook and released in the `close()` hook.
`udpc_fd_claim` treated an entry that was not `FREE` (or a stale `DYING`) as a conflict, logged
`already claimed`, and returned `NULL`. The `socket()` hook turns that into `EMFILE`, because an
untrackable descriptor must fail rather than pass through unproxied (SEC-01).

**The gap.** Release depends on interposing `close()`, and **not every program's closes reach it**.
`dig` closes descriptors through libuv: of its 64 `close` syscalls, 4 reach the shim's hook. The rest
are invisible, so those entries are stranded `ACTIVE` for descriptors the kernel has already freed.

Two consequences, neither of which is the application's fault:

- When the kernel later hands the same descriptor number to a new socket, the claim was refused and
  the program got `EMFILE` while nowhere near any descriptor limit.
- The stranded entry still held a reference to its association, so the control connection leaked and
  the association was never released at the proxy (against FR-P-02).

**Decision.** Every caller of `udpc_fd_claim` passes a descriptor the kernel has *just* allocated —
from `socket()`, or as a dup target. The kernel does not hand out a descriptor number that is
already live. Therefore a non-`FREE` entry at claim time is **proof that the entry is stale**, not
evidence of a conflict. The slot is released and re-claimed rather than refused.

`udpc_fd_release` does the right work already: it drops the association reference (closing the
control connection and releasing the association at the proxy) and bumps the generation counter, so
anything still holding the old entry is rejected under FR-L-02.

**Residual limitation.** A stale entry is reclaimed when its descriptor *number* is reused. A program
that closes a proxied socket by an uninterposed route and never reuses the number keeps that
association open until it exits. The control connection is bounded by the number of UDP sockets the
program opens, so this cannot grow without bound, but it is not zero. Documented in the README.

**Why the test suite missed it.** Every test client closes through libc, so every close reached the
hook. The condition needs a program whose runtime does not — which is a property of the *client*, not
of the proxy or the protocol, and so was invisible to a suite that supplies its own clients.

---

## D-18
### Raw sockets are not intercepted, and v1 documents that rather than refusing

**Date:** 2026-08-19 · **Status:** Accepted for v1, with a named successor · Prompted by trying
`nmap` under the shim.

**Context.** `is_intercepted_kind` claims `SOCK_DGRAM` in `AF_INET`/`AF_INET6` and nothing else. A
`SOCK_RAW` socket is therefore never claimed, so its traffic goes direct.

**Why this is a real gap and not just a limitation.** SEC-01 and the README both state that traffic
is either proxied or fails, and that there is no bypass. Raw sockets are a bypass. Unlike the
statically-linked and Go cases — where the shim is never loaded and cannot be expected to do anything
— here the shim **is** loaded, sees the `socket()` call, and lets it through. That is the leak class
D-05 rejected a bypass list to avoid, arriving by a different route.

**Why v1 does not refuse.** Refusing `SOCK_RAW` creation is a behaviour change reaching well beyond
the tool that exposed it. Raw sockets require `CAP_NET_RAW`, so nothing an ordinary unprivileged
program does is affected; but a privileged program that opens one for a purpose unrelated to the
traffic being proxied would start failing, and v1 has no interop evidence about what those programs
are. Shipping a refusal on the strength of one `nmap` run would be guessing.

The severity is also bounded in a specific way: the capability requirement means this is not
reachable by the threat model most users have in mind. It matters when the guarantee being sought is
"this privileged process cannot reach the network directly", and v1 does not provide that.

**Decision.** v1 documents it prominently — in the "cannot help" table and as an explicit exception
beside the no-bypass claim, in the same terms used here. No code change.

**v2 should refuse `SOCK_RAW` creation** with a diagnostic naming the reason, exactly as multicast
and broadcast sends fail with `ENETUNREACH` under D-05 R1. That is the consistent position: SOCKS5
cannot express a raw IP packet, and "cannot proxy" should mean "refuse", not "pass through".

**Note on `nmap` specifically.** It would not work even with raw sockets refused. It reads responses
with libpcap rather than through the socket API, and a UDP scan classifies a closed port from an
ICMP type 3 code 3 that RFC 1928 has no way to convey. `nmap -sU --unprivileged` uses ordinary
datagram sockets and is intercepted, but can only ever report `open|filtered`.

**Revisit if:** a refusal is implemented (v2), or a program is found that legitimately needs raw
sockets alongside proxied UDP — which would argue for a narrow opt-out rather than the current
silent pass-through.

---

## D-19
### The wrapper proves the shim is loadable, not merely readable

**Date:** 2026-08-20 · **Status:** Accepted · Found when the shim failed to preload on a VPS.

**Context.** `find_shim()` located the shim and checked `access(path, R_OK)`. Readable is not the same
as loadable, and the gap is not academic:

```
ERROR: ld.so: object '/root/udpchains/libudpchains.so' from LD_PRELOAD
cannot be preloaded (failed to map segment from shared object): ignored.
```

Note the last word. The loader prints a warning and **runs the program anyway**, with no
interposition. The traffic went direct.

**Why this is the same defect as SEC-06.** SEC-06 already refuses to run setuid, setgid and
capability-endowed binaries, on the reasoning that the loader ignores `LD_PRELOAD` for them, so
running them would mean running them unproxied. An unmappable shim produces exactly that outcome by a
different route, and was not covered. For a tool whose distinguishing claim over `proxychains` is
that it fails closed, silently proxying nothing is the worst failure mode available: the only
evidence is one line on stderr that a scripted run will not notice.

**Decision.** Before `exec`, the wrapper verifies the shim can actually be mapped:

1. **A valid ELF header**, catching truncated or interrupted copies.
2. **Matching ELF class and machine**, compared against `/proc/self/exe` rather than a compile-time
   `#ifdef` ladder — the wrapper is by definition the right answer. Catches a build copied between
   hosts instead of rebuilt.
3. **A `PROT_READ|PROT_EXEC` mapping of the first page**, which is the same mapping the loader will
   attempt for the text segment. Catches a `noexec` mount and a security policy (SELinux, AppArmor)
   that forbids mapping the file executable.

Any failure refuses to exec, with a diagnostic naming the specific cause and, for the `EACCES`/
`EPERM` case, the `findmnt` command that confirms it.

**Why a `PROT_EXEC` probe rather than `dlopen`.** `dlopen` would be a more faithful test, but it
would load the shim into the *wrapper's* address space and run its constructor — which resolves
configuration and logs. The probe is side-effect free and tests the condition that actually fails.

**Testing.** `tests/test_wrapper.sh` asserts two things per case, and the second matters more: the
wrapper exits non-zero, **and the target program never ran**. A diagnostic followed by an unproxied
execution would still be a leak. The `noexec` case is verified by hand rather than in the suite,
because creating such a mount needs root or unprivileged user namespaces and a test run can assume
neither; the script records the manual procedure.

**Residual, and narrower than it first appears.**

1. This closes the wrapper path only. A user who sets `LD_PRELOAD` by hand still gets the loader's
   silent fallback — nothing in the shim can run to prevent it, because the failure is that the shim
   did not run.

2. **LSM coverage is conditional on the wrapper and the target sharing a security domain.** The probe
   runs in the *wrapper's* process; the loader's mapping happens in the *target's*. If the target
   transitions into a confined SELinux or AppArmor domain on `exec`, the wrapper can be permitted
   while the target is denied — the probe passes, the wrapper execs, and the program runs unproxied
   exactly as before.

   Not hypothetical: it is how the failure that prompted this decision behaved. On one VPS
   `mmap(..., PROT_READ|PROT_EXEC, ..., 0x3000)` returned **`EACCES`**, which is the LSM hook rather
   than the mount — a `noexec` mount returns `EPERM` from `do_mmap`, and `findmnt` confirmed no
   `noexec`. A `/bin/true` target loaded the shim successfully while an `nc` target did not.

   The checks therefore rank by reliability: ELF-header and architecture are unconditional, `noexec`
   is caught because mount flags are not domain-specific, and LSM denials are caught only when
   wrapper and target are confined alike.

**Revisit if:** a way is found to test the target's own domain before `exec`. That would mean probing
after the domain transition — i.e. from inside the target, which is exactly where nothing of ours can
run. The honest framing may be that this class is uncatchable from the wrapper, in which case it
belongs in the README beside the other things the shim cannot promise.


---

## D-20
### RFC 1929 username/password authentication, implemented before release

**Date:** 2026-08-20 · **Status:** Accepted · Supersedes the FR-P-09 deferral in D-08.

**Context.** D-08 deferred FR-P-09 on the grounds that the reference proxy offered only method
`0x00`, so there was no reference behaviour to validate against and the fixture would have to grow
auth support to test it. That reasoning was sound at the time and expired for a simple reason: a
release that cannot talk to an authenticated proxy has a usability ceiling its version number does
not hint at, and D-08's own revisit condition was "a target proxy requires authentication".

**Decision.** Implemented, in the shape D-08's consequences paragraph anticipated.

- `0x02` is offered **only when credentials are configured.** A proxy that accepts either method is
  not pushed into an authenticated exchange the user did not ask for, and the "no credentials are
  configured" diagnostic stays accurate rather than becoming a lie about what was offered.
- The sub-negotiation version byte is `0x01`, RFC 1929's own, **not** SOCKS5's `0x05`. This is the
  classic bug in this exchange: a proxy reads `0x05` as an unknown auth version and closes the
  connection, which presents as a network fault rather than a protocol error. The unit test asserts
  this byte specifically, and the fixture rejects anything else.
- An empty username is refused at encode time. RFC 1929 gives `ULEN` the range 1 to 255, and a
  zero-length name encodes as a well-formed message no proxy can match to an account — failing
  later, and less clearly. An empty *password* is legal and is encoded as `PLEN 0`.
- A proxy selecting `0x02` when it was never offered is reported as `EPROTO`, not as an
  authentication failure: it is a protocol violation and deserves its own diagnostic.
- The request buffer is zeroed with `explicit_bzero` after the write, which the compiler may not
  elide.

**SEC-03 and NFR-05.** Credentials are still never accepted on the command line, because `argv` is
world-readable via `ps`. The debug log records the username's *length* and the outcome, never the
password; the fixture logs the username and outcome, never the password. A test asserts the password
appears in no log on either side, which is the only form of that guarantee worth having.

**Testing.** Byte layout is asserted against the RFC directly, written out literally rather than
computed by the code under test. The exchange is asserted end to end against a fixture that performs
real authentication and is deliberately strict about the version byte — a forgiving fixture is
exactly how D-14 survived 108 green cells. The negative cases carry the weight: a wrong password, and
no credentials at all, must each deliver **nothing**, because a failure that falls through to a
direct send would be an SEC-01 violation wearing an authentication error as a disguise.

**Still not implemented:** GSSAPI (method `0x01`), and any method beyond `0x00` and `0x02`. A proxy
selecting one is refused with a diagnostic naming what is supported.

---

## D-21
### Every route by which a UDP socket enters the process is hooked, and an untrackable one is refused

**Date:** 2026-09-23 · **Status:** Accepted · Found in a pre-release review, and reproduced before
being fixed.

**Context.** SEC-01's guarantee is only as good as the fd table's coverage. A UDP socket the table
does not know about is not intercepted at all, so its traffic goes direct. The same is true of a
receive path that is not hooked: it delivers the SOCKS header as payload. The table was populated
from `socket()`, `dup`, `dup2`, `dup3` and the start-up scan. The receive path was entered through
the twelve symbols FR-I-03 names. Both lists were complete against the requirements and incomplete
against libc.

**The gaps.** Four were found. Each reproduced with a test program, three of them with the proxy down:

- **`fcntl(F_DUPFD)` / `F_DUPFD_CLOEXEC`** duplicates a descriptor exactly as `dup` does, and was
  not hooked. With the proxy down, the original socket failed closed while the copy sent straight to
  the destination. Python's `socket.dup()` and `os.dup()` duplicate this way, so this was not
  exotic.
- **`SCM_RIGHTS`.** A UDP socket received from another process arrives as a new descriptor that
  never went through `socket()`, and so was untracked.
- **A failed `dup2`/`dup3`.** The hook released the target's entry *before* the call, mirroring the
  kernel's implicit close. When the call failed — `EBADF` on the source, say — the kernel closed
  nothing, and the target was left open, still a UDP socket, and untracked. Its next send went
  direct.
- **Fortified receive calls.** A `_FORTIFY_SOURCE` build — the default for distribution packages —
  calls `__recvfrom_chk`, `__recv_chk` and `__read_chk` when the buffer's size is known at compile
  time and the length is not. glibc implements them by calling its own internal receive functions,
  which a preload cannot interpose on. The application received the 10-byte SOCKS header followed by
  the payload. That is the Proxando failure (baseline §0.3.2), arriving by a door the hook matrix
  never opened. libtirpc, net-snmp and libnorm all import `__recvfrom_chk`.

A fifth hole was related: the start-up scan of inherited descriptors gave up silently if
`/proc/self/fd` could not be opened, and skipped any inherited UDP socket it could not claim.

**Decision.**

- `fcntl` and `fcntl64` are hooked. glibc exports one implementation under both names, and a
  `_FILE_OFFSET_BITS=64` build calls the latter. Only `F_DUPFD` and `F_DUPFD_CLOEXEC` are acted on.
- `recvmsg` and `recvmmsg` on a non-intercepted descriptor adopt any UDP socket found in
  `SCM_RIGHTS` ancillary data before returning.
- Every duplication route updates the table only **after** the call succeeds. If the source is
  intercepted, the new descriptor shares its association (FR-L-03). Otherwise any stale entry at the
  new number is released.
- The three fortified variants are hooked. Each makes glibc's own bounds check and then calls the
  ordinary hook, so there is still exactly one receive path.
- Without `/proc`, the inherited-descriptor scan probes the table with `poll()`, a batch of numbers
  per call.
- **An intercepted socket the table cannot track is refused, on every route.** A duplicate is closed
  and the call fails with `EMFILE`, as `socket()` already did. Previously a failed `dup` claim was
  logged ("its traffic would be unproxied") and the descriptor left open. An inherited or received
  socket is closed with a diagnostic.

**Why the suite missed them.** Every test client created its sockets with `socket()` and duplicated
them with `dup`, and was compiled from this repository's Makefile without calling the fortified
variants. The TST-02 symbol gate checked the symbols the requirements named, which is the list that
was wrong. The new assertions each fail against the 1.0.0 shim: the leak test sends through all three
new descriptor routes, the fidelity test calls the fortified variants directly, and the lifecycle
test proves the new descriptors are *proxied* by counting control connections. A round trip alone
would not prove that, since an untracked socket round-trips directly.

**Residual.**

- Other glibc-internal paths still bypass the hooks: stdio (`fdopen` on a UDP socket), and glibc's
  own DNS resolver, which since 2.34 lives inside libc and creates, connects and sends on its sockets
  through internal aliases. The resolver case is a DNS leak and is recorded separately. The shim
  cannot see `io_uring` or `sendfile`/`splice` either.
- An adopted socket that another process also still holds is re-pointed at this process's relay
  when first used, which also affects the other holder. That is the same shared-file-description
  problem FR-L-04 solves for `fork`, and it is not solved here.

**Revisit if:** another libc entry point is found that creates, duplicates or receives on a socket
without going through a hooked symbol. The symbol gate should grow with each one.

---

## D-22
### Name resolution is done by the shim, through the proxy, and never by the host

**Date:** 2026-09-23 · **Status:** Accepted — **not yet implemented** · Supersedes D-04.

**Context.** D-04 assumed glibc's resolver sends through the hooked socket calls. It does not, and
on no supported glibc: since 2.34 the resolver is part of libc, and its `socket`, `connect`,
`sendmmsg` and `recvfrom` calls are internal aliases no preload can interpose on. The NSS modules
ahead of it in a typical `hosts:` line (`mdns4_minimal`, `resolve`) are no better: each hands the
name to a local daemon over a unix socket, and the daemon resolves it unproxied. Found in the
pre-release review; reproduced with the proxy down, where `getaddrinfo()` resolved successfully and
`strace` showed the raw query sent to `127.0.0.53`.

A shim that fails closed for every datagram but resolves every name directly still tells the local
network, and the resolver's operator, where the program is going. For many users that is the
information they were trying to protect.

**Decision.** The shim answers name lookups itself, **before NSS runs**. Each lookup is answered
locally or by a DNS query sent through the proxy. The host's resolver is never consulted, and if
the proxy route fails, the lookup fails.

*Hooked:* `getaddrinfo`; `getnameinfo`; `gethostbyname`, `gethostbyname2` and `gethostbyaddr` with
their `_r` forms; and the `res_*` query API — `res_query`, `res_search`, `res_querydomain`,
`res_send` and their `res_n*` forms — under both the plain and the `__res_*` names, since libc
exports both. `getaddrinfo_a` **fails closed** with a diagnostic; asynchronous support is later
work.

*Not hooked, deliberately:* `freeaddrinfo` (results are built by glibc itself, below); `gethostent`
(files only); `getnetby*` (`networks:` is `files` on common configurations — revisit if a user
configures `dns` there); `rcmd`/`rexec` (TCP, out of scope).

*Lookup order:*

1. A numeric address goes to the real `getaddrinfo` with `AI_NUMERICHOST` forced, which cannot
   touch the network.
2. `localhost` and `*.localhost` answer with loopback (RFC 6761).
3. `/etc/hosts`, read by the shim's own parser.
4. DNS through the proxy.

A non-numeric name with `AI_NUMERICHOST` set fails with `EAI_NONAME`, as in glibc.

*Configuration.* `dns = <ip>[:port]` (env `UDPCHAINS_DNS`), numeric only: a named resolver would
need resolving first. **There is no default resolver.** With `dns` unset, a lookup that reaches
step 4 fails with `EAI_FAIL` and one diagnostic naming the setting — the same reasoning as D-10's
refusal to pick a proxy. Numeric addresses and `/etc/hosts` still work. `dns_timeout` (ms, default
5000, spread over 2 attempts). `dns_search = <domain> ...` opts in to a search list.

*Search domains are not applied by default.* Names are looked up as given, and `/etc/resolv.conf`
is not read at all. Local search domains (`localdomain`, a corporate suffix) are usually
meaningless to a remote resolver, and appending them sends internal names to it. The cost:
single-label names such as `printer` fail unless `dns_search` is set.

*Transport.* UDP over `UDP ASSOCIATE`, through associations the shim owns, kept in a small pool
with one lookup per association at a time. A pool, not one shared association, because a proxy
pins an association to a single local socket (§0.5), so concurrent lookups could share one only
through a reply demultiplexer. A and AAAA are queried together. A reply is accepted only if its
ID, question and SOCKS-header source all match; IDs are random. An EDNS0 buffer of 1232 bytes makes
truncation rare. **On a truncated answer, the query is retried over TCP, using SOCKS5 `CONNECT` to
the resolver through the proxy**; if the proxy refuses `CONNECT`, the lookup fails. This also
retires D-04's "resolver TCP fallback is not proxied" for libc lookups.

*Results.* For each resolved address, the real `getaddrinfo(ip, service, hints | AI_NUMERICHOST)`
is called and the results chained. glibc then handles service names, socket-type expansion and
`AI_V4MAPPED`/`AI_ALL`, and glibc's own `freeaddrinfo` frees the list — which is why it needs no
hook. `AI_CANONNAME` reports the end of the CNAME chain. `res_send` carries the caller's message
unchanged.

**Consequences.**

- Address ordering is no longer glibc's RFC 6724 sort. The shim honours `AI_ADDRCONFIG`, and puts
  IPv6 first only when the host has a global IPv6 address.
- Every NSS source for `hosts` other than `files` is bypassed: `.local` mDNS names stop resolving,
  and the host's own name resolves only if it is in `/etc/hosts`.
- Non-ASCII names (`AI_IDN`) are not converted; they fail with `EAI_IDN_ENCODE`.
- `_res` options (`RES_USEVC`, `RES_ROTATE` and others) are ignored.
- Programs with their own resolvers — `dig`, c-ares (curl), Node, the BIND libraries — are
  unaffected. They already send DNS over ordinary intercepted UDP, and their queries to
  `127.0.0.53` are resolved at the proxy host (D-05 R2). Redirecting loopback port 53 to `dns` is a
  possible later option, not part of this decision.
- The resolver path takes locks — for the pool — and allocates. NFR-03 does not apply:
  `getaddrinfo` is not async-signal-safe in POSIX either.
- Inside the shim, with the re-entry guard held, the hooks pass straight through to libc, so the
  shim's own lookup of a *named* proxy stays direct. That is already documented, and M5 (export the
  resolved proxy address) removes it from exec'd descendants.
- DNS answers inherit the relay leg's lack of authentication (review item D3): an attacker able to
  spoof the relay's address must also guess a 16-bit query ID.

**Testing.**

- A DNS fixture, `tests/fixtures/dnsd.c`, answering A, AAAA, CNAME, PTR, NXDOMAIN and truncated
  responses.
- `CONNECT` support in `socks5d`, for the TCP fallback.
- Unit tests for the decoder against hostile input: compression loops, truncated messages, answers
  to a different question.
- Integration tests for each hooked function.
- A leak-test case: with the proxy down, every lookup fails and nothing reaches the host's
  resolver. The wire-level capture script gains the same case.

**Revisit if:** a program is found that needs `getaddrinfo_a`, IDN, or glibc's address sorting; or a
proxy commonly paired with this tool lacks `CONNECT`, which would make the truncation fallback
unreliable.

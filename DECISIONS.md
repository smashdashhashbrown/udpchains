# Decision Record — `udpchains`

Decisions taken before implementation began, against the baseline
[`UDP-PRELOAD-REQUIREMENTS.md`](UDP-PRELOAD-REQUIREMENTS.md) (commit `ba07249`).

The requirements document is the **baseline**, and its requirements are not edited. This file
records what was decided where that document deferred a choice, contained an internal tension, or
left a gap. Each entry states what would cause it to be reopened, so that a later change is a
visible amendment rather than a silent drift.

**Date decided:** 2026-08-17 for D-01 to D-15; later entries carry their own dates. **Status of all
entries:** Accepted. "Review" items are from the pre-release review, tracked in
[`docs/REVIEW-BACKLOG.md`](docs/REVIEW-BACKLOG.md).

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
| [D-16](#d-16) | A loopback or wildcard `BND.ADDR` is replaced by the proxy's address | Interop defect found against a remote proxy |
| [D-17](#d-17) | A non-`FREE` fd-table entry at claim time is stale, and recycled | Defect: closes that bypass the hook (libuv) |
| [D-18](#d-18) | Raw sockets are not intercepted; documented, not refused (superseded by D-36) | Gap — SEC-01 vs. `SOCK_RAW` |
| [D-19](#d-19) | The wrapper proves the shim is loadable, not merely readable | Defect found on a VPS |
| [D-20](#d-20) | RFC 1929 username/password authentication | Supersedes the FR-P-09 deferral in D-08 |
| [D-21](#d-21) | Every route a UDP socket enters by is hooked; an untrackable one is refused | Review C1–C3 |
| [D-22](#d-22) | Name resolution by the shim, through the proxy | Review C4 |
| [D-23](#d-23) | Every intercepted call confirms its descriptor by socket cookie | Review H1 |
| [D-24](#d-24) | Type-stable associations, read through a counted reference | Review H2 |
| [D-25](#d-25) | The wrapper passes where the password is, never the password | Review H3 |
| [D-26](#d-26) | The shim's own descriptors are moved out of the way and protected | Review H4, L3 |
| [D-27](#d-27) | Configuration reaches the shim resolved, once | Review M4, M5 |
| [D-28](#d-28) | The wrapper runs the file it checked | Review M6 |
| [D-29](#d-29) | Datagram sockets the proxy cannot carry are refused | Review M7 |
| [D-30](#d-30) | The fd-table generation counter is removed | Review M8 |
| [D-31](#d-31) | A forked child lets go of the parent's control connections | Review M9 (ii) |
| [D-32](#d-32) | Limitations accepted for 0.1.0, and documented | Review M1–M3, M9 (i) |
| [D-33](#d-33) | Diagnostics: rate-limited, errors-only under `-q`, never into a reused fd 2 | Review L4, L5 |
| [D-34](#d-34) | A forked child binds its private socket again | Review L6 |
| [D-35](#d-35) | Hidden symbols and hardening; the proxy name uses its first address | Review L7 |
| [D-36](#d-36) | Routes around the hooks are proxied, refused or adopted; raw sockets are refused | D-18's successor, D-21's residual |
| [D-37](#d-37) | Chains are strict: a dead hop fails the call | FR-CH-02 |
| [D-38](#d-38) | A chain is configured as `[hop]` sections, repeated `-p`, or a list in `UDPCHAINS_PROXY` | FR-CH-01, FR-CH-03 |
| [D-39](#d-39) | Hops after the first are resolved by the hop before them, never here | FR-CH-04; amends D-27 |
| [D-40](#d-40) | The relay fixup applies per hop; the loopback guard looks at the exit hop | FR-CH-07, FR-CH-08; amends D-16, D-05 R2 |
| [D-41](#d-41) | Every layer of a received datagram is checked, or the datagram is dropped | FR-CH-06 |
| [D-42](#d-42) | At most 8 hops; `max_datagram` stays the program's payload | FR-CH-13 |
| [D-43](#d-43) | A chain's setup failures name the hop, once a second | FR-CH-12; extends D-33 |
| [D-44](#d-44) | Later hops are declared the unspecified address, in the family they see | FR-P-05 per hop |
| [D-45](#d-45) | Setup has an overall deadline, `chain_timeout`: by default `connect_timeout` per hop of a chain | FR-CH-02; settles a FUTURE-UDP-CHAINS §8 question |
| [D-46](#d-46) | When the shim's descriptor range is full, its connection stays where it is, protected, and that is reported | FR-CH-10; extends D-26 |
| [D-47](#d-47) | A proxychains.conf is read as it is, for the strict chain of `socks5` hops it shares | FR-CH-14, FR-C-04 |
| [D-48](#d-48) | Supervisor mode intercepts system calls with seccomp user notification (revised by D-54) | FR-SV-02, FR-SV-03, FR-SV-13; revisits FR-I-01 |
| [D-49](#d-49) | Supervisor mode is chosen explicitly, and never combined with the shim | FR-SV-01, FR-SV-17 |
| [D-50](#d-50) | UDP sockets live in a reserved range; outside it, UDP sends and connects are refused | FR-SV-04, FR-SV-18 |
| [D-51](#d-51) | A supervised receive peeks, delivers, and consumes only once the program has the datagram (superseded by D-54) | FR-SV-07, FR-SV-08 |
| [D-52](#d-52) | Queries to the system resolver are redirected to `dns`, through the proxy | FR-SV-12; revisits D-22 |
| [D-53](#d-53) | What supervisor mode refuses, and Linux 5.14 as its floor | FR-SV-02, FR-SV-09; revisits D-29, D-36, NFR-01a |
| [D-54](#d-54) | A supervised program's calls are handled while it is stopped, through `ptrace`; notification only installs descriptors | FR-SV-06, FR-SV-07, FR-SV-08, FR-SV-13; revises D-48, D-51 |

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
tested against, including the reference proxy.

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
peer supporting `UDP ASSOCIATE`. The reference proxy (§0.5) is a separate program, which would add a
dependency to the test path, and its failure modes cannot be triggered on demand.

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
- Interop against a real proxy remains a **separate, manual** acceptance step (TST-04,
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

**Date:** 2026-08-19 · **Status:** Superseded by [D-36](#d-36), which refuses raw sockets as the
"v2 should refuse" paragraph below proposed · Prompted by trying `nmap` under the shim.

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
was wrong. The new assertions each fail against the pre-review shim: the leak test sends through all three
new descriptor routes, the fidelity test calls the fortified variants directly, and the lifecycle
test proves the new descriptors are *proxied* by counting control connections. A round trip alone
would not prove that, since an untracked socket round-trips directly.

**Residual.**

- Other glibc-internal paths still bypass the hooks: stdio (`fdopen` on a UDP socket), and glibc's
  own DNS resolver, which since 2.34 lives inside libc and creates, connects and sends on its sockets
  through internal aliases. The resolver case is a DNS leak and is recorded separately. The shim
  cannot see `io_uring` or `sendfile`/`splice` either. *(D-22 closed the resolver case; D-36 closed
  stdio, `sendfile`, `splice` and `pidfd_getfd`. `io_uring` remains.)*
- An adopted socket that another process also still holds is re-pointed at this process's relay
  when first used, which also affects the other holder. That is the same shared-file-description
  problem FR-L-04 solves for `fork`, and it is not solved here.

**Revisit if:** another libc entry point is found that creates, duplicates or receives on a socket
without going through a hooked symbol. The symbol gate should grow with each one.

---

## D-22
### Name resolution is done by the shim, through the proxy, and never by the host

**Date:** 2026-09-23 · **Status:** Accepted, implemented · Supersedes D-04.

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

**Implementation notes.** Where the implementation settled something this record left open:

- `hosts_file` (env `UDPCHAINS_HOSTS_FILE`) was added. The tests need a controlled hosts file, and a
  container may keep its own; a documented setting was preferred to an undocumented test hook.
- Addresses per answer are capped at 256, and at 512 per lookup. glibc has no fixed cap. The first
  cap tried, 32, silently dropped addresses from a 100-record answer, which the integration test
  caught.
- Replies are accepted only if the SOCKS source is the resolver, `FRAG` is 0, and the ID, opcode,
  name, type and class all match the query. Name decompression is libc's `dn_expand`; CNAME chains
  are followed for at most 16 hops.
- `getnameinfo` ignores `NI_NOFQDN`, and the `gethostby*` functions return no aliases.
- The resolver's associations log one `resolver association up` line each at default verbosity,
  as FR-C-06 asks of every association.

**Revisit if:** a program is found that needs `getaddrinfo_a`, IDN, or glibc's address sorting; or a
proxy commonly paired with this tool lacks `CONNECT`, which would make the truncation fallback
unreliable.

---

## D-23
### Every intercepted call confirms its descriptor is still the socket it was

**Date:** 2026-09-23 · **Status:** Accepted · Review item H1; completes D-17.

**Context.** D-17 recycles a stale entry — one left behind when a descriptor was closed by a route
no hook sees — but only when a UDP `socket()` or a dup lands on the same number. Every other way
the kernel can reuse the number — `open`, `pipe`, `accept`, `socketpair`, a TCP `socket()` — left
the entry in place. Whatever arrived there was then treated as the old UDP socket. Reproduced two
ways. A Unix stream socket's `write()` failed. A TCP socket's `connect()` was swallowed by the
connect hook, which recorded a UDP destination and never connected, so the peer's `accept()`
waited forever. A connected TCP stream would have had SOCKS headers injected into its bytes, and
its reads would have discarded data as malformed datagrams.

The routes that strand entries are ordinary. libuv (and so `dig`) closes through `syscall()`.
glibc's `closefrom()` calls its internal `close_range`. `fclose()` on an `fdopen()`ed socket calls
glibc's internal `close`.

**Decision.** Two layers.

- **Identity.** Each entry records the socket's kernel cookie (`SO_COOKIE`: 64 bits, never reused)
  when it is claimed. Every intercepted call confirms it with one `getsockopt` before trusting the
  entry. On a mismatch, the entry is released — which also releases the association D-17 said
  would otherwise be held until exit — and whatever now holds the number is adopted if it is a
  UDP socket, or passed through if not. Exactly one thread recovers an entry: the cookie field
  doubles as the lock, and other threads wait for it.
- **Fewer strandings.** `closefrom()` is hooked. `syscall()` is hooked for the descriptor-lifecycle
  numbers — `close`, `close_range`, `dup`, `dup2`, `dup3`, `fcntl`, `socket` — which are routed to
  the ordinary hooks. So libuv's closes release their entries at once, and a socket created or
  duplicated through `syscall()` is tracked like any other. Data calls through `syscall()` remain
  unsupported, as the README says.

The shim's own replacement of a socket after `fork` (FR-L-04) re-records the cookie. Without that,
the first run of this change mistook the fork fix for a stale entry and hung the lifecycle test.

**Consequences.**

- **Cost:** one `getsockopt` per intercepted call, about 0.6 µs on the review host. Descriptors the
  shim does not track still cost two loads and no syscall. A `send()` in a tight loop went from
  5.1 to 5.9 µs, averaged over six alternating runs against the old shim. The effect on a round
  trip through the proxy is a few microseconds at most, inside run-to-run noise. The first
  measurement, taken while the host was busy, suggested 6–15 µs per round trip; alternating runs
  on a quieter host showed that was noise. The check does retire the claim of "no syscalls on the
  datagram path" (review item D7).
- **Residual:** while one thread recovers a stale entry, another thread's call on that same number
  finds no entry and passes through. That matters only if the number now holds a UDP socket that
  arrived by a route no hook saw. Before this record such a socket was misattributed rather than
  passed through, so this is not a regression.
- A stale entry whose number is never used again still holds its association until exit, as D-17
  said. It is now released on the first call of any kind that touches the number, not only on the
  next UDP `socket()`.

**Revisit if:** the per-call cost matters for a real workload. The only cheaper check would be one
the kernel does not offer.

---

## D-24
### Associations are type-stable, and read only through a counted reference

**Date:** 2026-09-23 · **Status:** Accepted · Review item H2.

**Context.** The datagram path read an association's relay address, idle time and fork generation
through a bare pointer loaded from the fd-table entry. Another thread could drop the last
reference at the same moment — most simply by noticing that the proxy had expired an idle
association — and `free()` the object between the load and the read. Threads sharing one socket is
legal, and TST-07 does it, but it never combined sharing with expiry. A TSan test of exactly that
race reports 15 warnings against the old code, including a heap use-after-free in
`udpc_assoc_relay`.

**Decision.** Keep the datagram path lock-free (D-07) and make the pointer safe to have loaded.

- **Type-stable memory.** An association is never returned to the allocator. On its last
  reference it goes onto a free list for reuse, so a stale pointer always points at a valid
  object, even if a recycled one. Pushes are a lock-free Treiber stack. Pops are serialised by a
  mutex that is only ever *tried*, which rules out ABA without letting a signal handler, or a
  forked child, wait on it; a failed try just allocates.
- **Counted access.** `udpc_assoc_get()` takes a reference only while the count is non-zero, then
  checks the entry still points at the same object; otherwise it lets go and reloads.
- **One reference per datagram.** The datagram path takes its reference once, through
  `udpc_assoc_hold()`, which also makes sure the association exists and does the FR-P-08 idle
  check. The send then uses it for the relay address and the activity stamp, and on a failure
  detaches that same association with `udpc_assoc_drop()`, never one another thread may have put
  in its place. The first version took a fresh reference for each of those reads — four per send
  — and alternating runs put that at about 0.5 µs per call. Consolidating them recovered it. A
  receive holds one reference for its whole duration.

**Consequences.** Readers never block and teardown never waits. The price is one reference —
two atomic read-modify-writes — per datagram, on a cache line shared by threads using one socket.
Memory for associations is bounded by the peak number alive at once, rather than returned. The same
race, rewritten against the new interface, is clean under TSan.

**Revisit if:** association churn makes the peak-sized pool material, which would argue for
returning memory under a grace-period scheme instead.

---

## D-25
### The wrapper passes where the password is, never the password

**Date:** 2026-09-23 · **Status:** Accepted · Review item H3.

**Context.** The wrapper resolved the password — from a password file, or from `password =` in a
config file — and exported it to the target as `UDPCHAINS_PASSWORD=<secret>`. Every process the
target started inherited it. Anything that dumps an environment — a crash reporter, a CI log, a
stray `env`, `ps e` — would print it. A user who chose a password file to keep the secret out of
the environment got the opposite, silently.

**Decision.** The wrapper exports the password's *location*, and each shim reads it from there.

- From a password file: `UDPCHAINS_PASSWORD_FILE=<absolute path>`. Absolute, because the target
  or a descendant may change directory before its first datagram; a test covers exactly that.
- From `password =` in a config file: `UDPCHAINS_PASSWORD_CONFIG=<absolute path of that file>`. The
  shim reads only the password from it; everything else arrives resolved, as before.
- Supplied by the user as `UDPCHAINS_PASSWORD`: already in the environment by their choice, and
  left as it is. The wrapper never creates that variable.

The wrapper clears its own copy with `explicit_bzero` once exported.

**Consequences.** The secret stays in the file the user protected. A process running as the same
user could read that file anyway, so the threat this removes is accidental disclosure through the
environment, not a same-user attacker. A password file deleted or changed after launch now affects
descendants started afterwards — which is arguably what a user rotating a password wants.

**Revisit if:** a deployment needs the password to outlive its file.

---

## D-26
### The shim's own descriptors are moved out of the way and protected

**Date:** 2026-09-23 · **Status:** Accepted · Review item H4.

**Context.** Control connections, and the resolver's sockets (D-22), are ordinary descriptors in
the application's descriptor space, at whatever low number the kernel handed out. A daemon's
close-all loop, a `close_range(3, ~0U)`, or a `dup2` onto the number took one away without the
shim knowing. After that, the association polled whatever the application had put at that number,
and on teardown closed it — the application's pipe, file or socket.

**Decision.**

- **Moved.** Each shim-owned descriptor is moved with `F_DUPFD_CLOEXEC` into a band starting at
  768 (half the soft limit if that is below 1024), clear of the lowest-free numbers applications
  are given. The band does not follow a larger soft limit upward: the kernel sizes a process's
  descriptor table to the highest number in use, and a table grown to a million entries costs
  megabytes per process.
- **Marked.** The fd table records these numbers in a new `SHIM` state, with the socket's cookie
  (D-23).
- **Protected.** `close()` on one returns `EBADF` — the application never opened it, so to the
  application it is not open. `close_range` and `closefrom` close *around* them. `dup2`/`dup3`
  onto one fails with `EBUSY`, the error `dup2` already has for "that number cannot be used right
  now". A mark whose cookie no longer matches — the descriptor was closed by a route no hook sees,
  and the number reused — is cleared, never enforced, so an application is never refused its own
  descriptor.

**Consequences.** A close-all loop, and `close_range` over the whole band, leave every association
working with no re-association, and tearing an association down closes nothing of the
application's. Both are tested. The visible changes are the two errno values above, for
descriptors the application did not open, and the shim's descriptors appearing in the 768+ band of
`/proc/self/fd`. The range release this needed now visits only allocated blocks, so
`close_range(3, ~0U)` no longer walks a million entries (review item L3).

**Revisit if:** a program is found that `dup2`s onto a specific number in the band. Relocating the
shim's descriptor there, rather than refusing, would need an owner back-reference in the table.

---

## D-27
### Configuration reaches the shim resolved, once

**Date:** 2026-09-24 · **Status:** Accepted · Review items M4 and M5.

**Context.** Two gaps between what the wrapper resolved and what the shim used.

- **M4.** The shim still read `~/.udpchains.conf` and `/etc/udpchains.conf`, contradicting the
  wrapper's own comment that it must not. With `-f a.conf`, credentials in the home file reached the
  shim anyway. A broken home file made the shim report itself unconfigured — after the wrapper had
  reported success — so every send failed inside a program that had apparently started fine.
- **M5.** The wrapper exported the proxy as the user wrote it, so a hostname was looked up again in
  every process started under the shim. That lookup must bypass the proxy it is trying to find, so
  it went directly, once per process, and could return a different address from the one the wrapper
  had checked.

**Decision.** The wrapper exports `UDPCHAINS_RESOLVED=1`, and a shim that sees it reads the
environment only. A bare `LD_PRELOAD`, without the wrapper, still reads the config files — they are
then the only configuration there is. The proxy is exported as the numeric address the wrapper
resolved: `a.b.c.d:port`, or `[v6]:port` with any scope kept.

**Consequences.** What the wrapper checked is exactly what every process uses. Diagnostics from
processes under the shim name the proxy by address, not by name. A proxy whose address changes while
the program runs is not followed; the wrapper's resolution stands for the whole run, which is also
what makes it checkable.

---

## D-28
### The wrapper runs the file it checked

**Date:** 2026-09-24 · **Status:** Accepted · Review item M6.

**Context.** SEC-06 refuses setuid, setgid and capability-endowed targets, by inspecting the file
`resolve_program()` finds on `PATH`. The wrapper then called `execvp()`, which searches `PATH` again.
A file swapped in between, or a `PATH` directory that changed, meant the file inspected need not
be the file run.

**Decision.** `execv()` of the resolved path. `argv[0]` stays as the user typed it. `execvp`'s one
extra is kept: a file with neither an ELF header nor a `#!` line is run by `/bin/sh`, still naming
the checked path.

**Consequences.** The check and the exec now name one file. A race on the file's *contents* between
check and exec remains, as it does for any check followed by an exec; SEC-06 was about which file,
not about that.

---

## D-29
### Datagram sockets the proxy cannot carry are refused

**Date:** 2026-09-24 · **Status:** Accepted · Review item M7.

**Context.** Interception keyed on `SOCK_DGRAM` in `AF_INET`/`AF_INET6` and ignored the protocol.
An ICMP "ping" socket — `SOCK_DGRAM`/`IPPROTO_ICMP`, which is how unprivileged `ping` works — and a
UDP-Lite socket were taken for UDP, wrapped in SOCKS headers, and sent to the proxy's relay.

**Decision.** Refused, in the terms D-18 set out for raw sockets: SOCKS5 carries only UDP, and
"cannot proxy" means "refuse", not "pass through". `socket()` for any protocol other than `0` or
`IPPROTO_UDP` fails with `EPROTONOSUPPORT` and a diagnostic. Such a socket inherited across `exec`
or received over `SCM_RIGHTS` is closed, with a diagnostic.

**Consequences.** `ping` fails under the shim instead of misbehaving. Raw sockets (D-18) are
unchanged: still not intercepted, and still the one documented exception to the no-bypass claim.

---

## D-30
### The fd-table generation counter is removed, not implemented

**Date:** 2026-09-24 · **Status:** Accepted · Review item M8.

**Context.** Each entry carried a generation counter, bumped on release and described in DESIGN.md
and the FR-L-02 notes as the guard against descriptor reuse: a thread that looked an entry up just
before another thread closed and reused the number would see the generation change and reject the
entry. Nothing ever compared it. A `redirected` flag was likewise written and never read.

**Decision.** Both fields are removed, and the documentation points at what does the job:

- The scenario is the application racing its own close. A thread using a descriptor another thread
  is closing reaches whatever the number refers to next — in the kernel as well — so the shim
  matching that is not a defect.
- Memory safety in that race is already guaranteed: table blocks are never freed, and associations
  are type-stable and counted (D-24).
- Treating the wrong socket as tracked is what D-23's per-call cookie check catches, and it does so
  on every call rather than only mid-call.

`redirected` was redundant: an entry has an association exactly when its socket has been pointed at
a relay.

**Consequences.** Two fewer atomic stores per release and per association. The unit test's
generation assertions now check that released state does not survive, which is what FR-L-02
asks.

---

## D-31
### A forked child lets go of the parent's control connections

**Date:** 2026-09-24 · **Status:** Accepted · Review item M9, part (ii); part (i) is D-32.

**Context.** A forked child inherited copies of the parent's control connections and kept them
until it exited or exec'd. A TCP connection is closed — its FIN sent — only when the last process
holding it closes it, so each parent association stayed alive at the proxy for as long as any child
lived: a pre-forked worker pool kept every one of its parent's associations open indefinitely.

**Decision.** The fork child handler closes the child's copies at once and marks the inherited
associations as having none; the resolver pool does the same for its own. The work is a walk of the
table with atomic loads, `close()`, and stores to memory the child alone owns — all allowed in the
child of a multithreaded parent. The associations themselves are still dropped on first use, when
their fork generation is found stale, as before.

While there, a second fork hazard is fixed. A parent thread in the middle of establishing an
association leaves an "establishing" marker that, in the child, no surviving thread would ever
clear, so the child's first send on that socket would have waited forever. The handler resets it.

**Consequences.** Closing a socket in the parent releases its association at the proxy, whatever
children exist. The cost is one `close` per live association on each `fork`.

---

## D-32
### Limitations accepted for 0.1.0, and documented

**Date:** 2026-09-24 · **Status:** Accepted · Review items M1, M2, M3, and M9 part (i).

Reviewed, and kept as documented limitations rather than fixed before 1.0. Each is in the README's
"What does not work".

- **M1 — `strict_loopback` is checked once per association,** when it is set up, and only for a
  connected socket. An unconnected `sendto()` to loopback, or a `connect()` to loopback after setup,
  goes to the proxy host's loopback unwarned. *Fix when revisited:* check on every send; it is two
  comparisons.
- **M2 — `MSG_MORE`, `UDP_CORK` and GSO/GRO corrupt data** rather than failing: each call gets its
  own header, so a corked datagram carries a header in its middle. *Fix when revisited:* refuse
  `MSG_MORE` per call, and check the three socket options when the association is set up.
- **M3 — the first send or receive blocks, even on a non-blocking socket,** while the proxy
  handshake completes. Its timeout applies to each handshake step rather than overall, and a send
  whose association cannot be set up makes a second full attempt. *Fix when revisited:* one overall
  deadline, and no retry when the failure was the setup itself; truly non-blocking setup needs its
  own design.
- **M9 (i) — a socket shared with another process is re-pointed.** When a socket inherited across
  `exec`, or received over `SCM_RIGHTS`, is also still held elsewhere, the shim's first use points
  it at a new relay, which redirects the other holder too. There is no safe general fix. Replacing
  the socket with a private one breaks sockets whose local port matters — systemd socket activation,
  a server socket handed to a worker — and a socket that has been used has a local port whether or
  not it was bound, so the two cases cannot be told apart. Nor does Linux tell a process who else
  holds a socket.

**Revisit if:** any of these is met in real use; the first three have a known fix.

---

## D-33
### Diagnostics: rate-limited, errors-only under `-q`, and never into a reused fd 2

**Date:** 2026-09-24 · **Status:** Accepted · Review items L4 and, for the permission warnings, L5.

**Context.** Three things were wrong with how the shim reported problems:

- **It warned once per datagram.** Warnings about a refused multicast or broadcast send, or an
  inbound datagram over `max_datagram`, printed a line for every datagram. A program retrying in a
  loop filled the terminal or the journal.
- **It wrote to whatever descriptor 2 was.** A daemon that closes stderr and then opens its log
  file is given descriptor 2 for that file, and the shim's warnings were written into it. The same
  happens to a socket that lands at 2, where the warning would be sent to its peer.
- **`-q` still printed warnings,** though the help text and man page say "errors only". Separately,
  a group- or world-readable password file was warned about twice: once by the wrapper and again
  by the shim in the program.

**Decision.**

- **Repeated warnings are rate-limited:** at most one per second for each kind. The next one that
  prints says how many were held back.
- **The shim checks descriptor 2 is still the stderr it started with.** Its constructor records
  fd 2's device and inode, and each message first compares them with `fstat`. If fd 2 was closed,
  or now refers to something else, the message is dropped. A program that redirects its own stderr
  with `dup2` after start-up loses the shim's messages as a result. That is the safer way to be
  wrong.
- **`-q` means errors only.** Warnings are suppressed under it, as the documentation already said.
- **The wrapper checks file permissions; the shim does not repeat them.** A shim launched by the
  wrapper (the resolved-environment marker, D-27) skips the permission warnings. A shim started
  with `LD_PRELOAD` directly still gives them.

**Consequences.** One `fstat` per message, not per datagram, so there is no cost on the datagram
path. A burst of 50 refused multicast sends prints one line where it printed 50. The fault test
checks the burst, `-q`, and a file opened at descriptor 2; the auth test checks each permission
warning appears once.

---

## D-34
### A forked child binds its private socket again, and stops declaring an address it cannot own

**Date:** 2026-09-24 · **Status:** Accepted · Review item L6.

**Context.** After `fork()`, a child that uses an inherited UDP socket is given a private
replacement (FR-L-04). The replacement was bound again only when the original had a concrete
address, so a wildcard-with-port binding (`0.0.0.0:5000`) was dropped. When that `bind()` failed
— normally because the parent still holds the port — the failure was ignored. The child then went
on declaring the parent's address in `UDP ASSOCIATE` while sending from an ephemeral port. A proxy
that honours the declared address accepts only datagrams from it, so every one of the child's
datagrams was dropped, and the child waited for replies that never came.

**Decision.** The shim now records whether a socket was bound to a concrete address *or* to a port,
and the child binds its replacement again in both cases. If that `bind()` fails, the child clears
the recorded address and warns once. Its later associations declare nothing, so the proxy uses the
source it actually sees.

**Consequences.** The child's datagrams leave from an ephemeral port whenever the parent still
holds the original, which is unavoidable, since two sockets cannot bind one port without
`SO_REUSEPORT`. The warning says so. The proxy fixture gained `--pin-declared`, which enforces the
declared address. The fault test forks a child from a bound socket under it: the child's round
trip, and the parent's afterwards, both succeed. The previous shim times out there.

---

## D-35
### Hidden symbols and standard hardening; the proxy name uses its first address

**Date:** 2026-09-24 · **Status:** Accepted · Review item L7.

**Context.** The library exported every internal `udpc_*` function, so a program with a function
of the same name could interpose on the shim's internals, or the shim on the program's. It was
built without the stack protector, RELRO or immediate binding. And `udpc_addr_parse` uses only the
first address `getaddrinfo` returns for a proxy hostname.

**Decision.**

- **Only the hooks are exported.** The library is built with `-fvisibility=hidden`, and the two
  files that define hooks mark them visible with `#pragma GCC visibility push(default)`. The symbol
  gate checks that no `udpc_*` symbol is exported.
- **The standard hardening flags are always on.** They are `-fstack-protector-strong`,
  `-Wl,-z,relro` and `-Wl,-z,now`. `-D_FORTIFY_SOURCE=2` is added only in optimised builds without
  a sanitizer, since it needs optimisation and conflicts with ASan's own checks. The symbol gate
  checks for the RELRO segment, `BIND_NOW` and the stack protector.
- **First-address-only is kept and documented.** Failing over between a proxy's addresses would
  mean retrying the handshake per address inside the send path, which lengthens a send that
  already blocks (D-32, M3). To choose the address, configure it numerically.

**Consequences.** 54 exported symbols, all hooks. `-z now` binds the library's own imports when it
loads rather than on first call, which moves a few microseconds to start-up; the hooks' `RTLD_NEXT`
lookups are unaffected. The stack protector costs a comparison on return from functions with local
arrays. The performance group stays within the NFR-04 budget.

---

## D-36
### The routes around the hooks are proxied, refused or adopted; raw sockets are refused

**Date:** 2026-10-20 · **Status:** Accepted · Successor to D-18, and closes most of D-21's residual.
Amends FR-I-06, which let raw sockets pass through.

**Context.** D-18 documented raw sockets rather than refusing them, and named refusal as the next
step. D-21 listed routes that send on a UDP socket without passing through a send hook: stdio,
`sendfile`, `splice`, `pidfd_getfd`, `io_uring`. Running each under the shim with the proxy stopped
showed a more precise picture than the README gave:

- On a socket connected through the `connect()` hook, `sendfile`, `splice`, stdio and `dprintf`
  failed with `EDESTADDRREQ` rather than leaking. The kernel socket has no destination of its own
  until its association is up, and after that it points at the relay, where data without a header
  is discarded.
- They **did** leak on a socket whose kernel socket had a destination of its own: one connected
  with `syscall(SYS_connect)`, which went straight to the kernel.
- `syscall(SYS_sendto)` and `syscall(SYS_sendmsg)` with an explicit destination leaked on any
  socket.
- A socket copied with `pidfd_getfd` was untracked, so every send on it leaked.
- Four routes were not in D-21's list at all: `dprintf` (glibc writes through an internal call),
  `pwritev2` at offset −1 (which on a socket is `writev`), and glibc's public aliases `__write` and
  `__send`, which a program can link against directly.

In all, 11 of the leak client's 27 sends reached the destination with the proxy down.

**Decision.**

- **Raw and packet sockets are refused.** `SOCK_RAW` and `SOCK_PACKET` in `AF_INET`/`AF_INET6`,
  and any `AF_PACKET` socket, fail with `EPERM` and a diagnostic. `EPERM` is what a program without
  `CAP_NET_RAW` already gets, so programs take the fallback they would take unprivileged. Such a
  socket inherited across `exec`, received over `SCM_RIGHTS` or copied with `pidfd_getfd` is
  closed, as D-29 does for ICMP and UDP-Lite.
- **`syscall()` routes every number that has a hook to that hook**: the socket calls (`connect`,
  `bind`, `getpeername`, `getsockname`), every send and receive, `pwritev2` and `preadv2` (64-bit
  only, where the offset fits one argument), `sendfile`, `splice` and `pidfd_getfd`. D-23 had
  routed only the lifecycle calls.
- **Proxied by another route:** `dprintf`, `vdprintf` and their fortified forms are formatted into
  the thread's scratch buffer and sent through the send path as one datagram, or fail with
  `EMSGSIZE` above `max_datagram`. `pwritev2` and `preadv2` at offset −1 become `writev` and
  `readv`; any other offset is `ESPIPE`, as on any socket, and a non-zero `RWF_*` flag is
  `EOPNOTSUPP`.
- **Refused on a UDP socket, with `EINVAL`:** `fdopen`, `sendfile` and `sendfile64` (as the output),
  and `splice` in either direction (out of a UDP socket it would deliver the SOCKS header as data).
- **Adopted:** a socket returned by `pidfd_getfd`. The hook makes the system call itself, because
  glibc's wrapper is newer than the 2.34 floor (NFR-01a).
- **glibc's public aliases** `__write`, `__read`, `__send`, `__connect`, `__close`, `__dup2` and
  `__fcntl` are hooked and forwarded to their hooks. The `GLIBC_PRIVATE` ones cannot be linked by a
  program and are left alone.
- **`MSG_MORE` and a `UDP_SEGMENT` control message are refused with `EOPNOTSUPP`.** Each would make
  the kernel build one datagram from several sends, or several from one, and the SOCKS header
  cannot follow either. `setsockopt` stays unhooked (FR-I-07), so `UDP_CORK` and `UDP_GRO` set that
  way remain documented limitations.

**Why stdio is refused rather than emulated.** A stream built with `fopencookie` could route stdio
through the hooks, but `fileno()` on it returns −1, and stdio's buffering would decide where one
datagram ends and the next begins. Refusing at `fdopen`, the one point stdio can be stopped, is
simpler and says plainly that it is unsupported.

**What remains.**

- `io_uring`. glibc has no wrapper for it, and liburing makes its own system calls.
- System calls made without libc's `syscall()`: Go, static binaries, inline assembly. These are
  the subject of [`docs/FUTURE-STATIC-BINARIES.md`](docs/FUTURE-STATIC-BINARIES.md).

**Consequences.**

- A privileged program that opens a raw or packet socket for a purpose unrelated to the traffic
  being proxied (a DHCP client, a network monitor) now cannot open it under `udpchains`.
- A program that writes to a UDP socket through stdio, `sendfile` or `splice` now gets an error
  where before it either failed with `EDESTADDRREQ` or sent directly.
- 20 more exported symbols. The symbol gate checks each.
- TST-06's D-23 test closed a socket behind the shim's back with `fclose(fdopen(fd))`, which is
  now refused. It closes with libc's own `close`, looked up by handle so the hook is not reached.
- Tests: 55 more assertions in TST-05, 13 more routes in the leak client with 2 more leak-test
  checks, and 20 more checks in the symbol gate. With the 0.1.0 shim, 11 of the leak client's
  27 sends reach the destination with the proxy down; with this one, none do.

**Revisit if:** another libc entry point is found that moves data through a descriptor without a
hook, or glibc gains an `io_uring` wrapper.

---

## D-37
### Chains are strict: a dead hop fails the call

**Date:** 2026-10-20 · **Status:** Accepted · FR-CH-02.

**Context.** proxychains offers `strict_chain`, `dynamic_chain` (skip dead proxies) and
`random_chain`. The last two change the path a datagram takes without telling the program.

**Decision.** udpchains supports strict chains only. Every hop must be reached, negotiated and
associated, in order, or the call fails with an `errno`, and the diagnostic names the hop that
failed. There is no setting to skip, reorder or randomise hops.

**Why.** A skipped hop is a different path, and the hops a user lists are usually the point: each
is a foothold into the next network. Skipping one either fails later in a confusing way or, worse,
reaches the target by a route the user did not intend. This is D-05's argument against a bypass
list, applied to the chain.

**In the code.** `udpc_socks_associate_chain` associates hop 1 first, then each later hop, and
closes the hops already up if one fails. The single-hop `udpc_socks_associate` is given a chain only
by mistake; it then fails with `EINVAL` rather than associate with the first hop alone.

**Revisit if:** a user needs failover between equivalent first hops. That would be a list of
alternatives for one hop, not a looser chain.

---

## D-38
### A chain is configured as `[hop]` sections, repeated `-p`, or a list in `UDPCHAINS_PROXY`

**Date:** 2026-10-20 · **Status:** Accepted · FR-CH-01, FR-CH-03. Chosen by the maintainer from
three formats: `[hop]` sections, repeated `proxy =` lines, and a `[ProxyList]` stanza.

**Decision.**

- **Config file.** The top-level `proxy`, `username`, `password` and `password_file` are hop 1,
  exactly as in 0.1.0. Each `[hop]` section adds the next hop, and may hold only `proxy` (required),
  `username`, `password` and `password_file`. A `[hop]` section needs a top-level `proxy` before it.
  Other keys inside a `[hop]` section are an error, since they would look per-hop and are not.

  ```ini
  proxy = a.example:1080
  username = alice
  password_file = ~/.a.pw

  [hop]
  proxy = 10.0.0.5:1080
  username = bob
  password_file = ~/.b.pw
  ```

- **Command line.** `-p` may be repeated; the first is hop 1. Credentials are never accepted on the
  command line (SEC-03).
- **Environment.** `UDPCHAINS_PROXY` takes a comma-separated list. Hop *n*'s credentials, for *n*
  from 2, are `UDPCHAINS_USERNAME_<n>`, `UDPCHAINS_PASSWORD_FILE_<n>` and `UDPCHAINS_PASSWORD_<n>`;
  hop 1 keeps the unsuffixed names.
- **Precedence** (FR-C-02). The list of hops comes whole from the highest layer that names a proxy:
  a command line `-p` replaces a file's chain rather than editing it. Each hop's credentials come
  from the highest layer that sets them, as hop 1's do in 0.1.0.
- **Handoff to the shim** (D-27, D-25). The wrapper exports `UDPCHAINS_PROXY` as the list, hop 1 as
  the address it resolved and later hops as written (D-39). Each hop's password is passed on by
  location: `UDPCHAINS_PASSWORD_FILE_<n>`, or `UDPCHAINS_PASSWORD_CONFIG_<n>` naming the config file
  whose *n*th hop holds it inline. A chain of one exports exactly the variables 0.1.0 exports.

**Why `[hop]` sections.** A 0.1.0 file keeps its meaning without change, which FR-CH-01 requires,
and nothing within a hop depends on line order. Repeated `proxy =` lines would make a `username`
line's meaning depend on where it sits; a `[ProxyList]` line has nowhere safe to put a password.
FR-CH-14 can still accept `[ProxyList]` later as a second spelling. (D-47 does.)

**Until chains were carried on the wire** (step 4 of
[`docs/FUTURE-UDP-CHAINS.md`](docs/FUTURE-UDP-CHAINS.md) §7), a configuration of more than one hop
was parsed and checked, and then refused by both the wrapper and the shim, so it could never run as
a chain of one. Name lookups through a chain still fail closed until step 5 (FR-CH-11).

---

## D-39
### Hops after the first are resolved by the hop before them, never here

**Date:** 2026-10-20 · **Status:** Accepted · FR-CH-04. Amends D-27.

**Context.** D-27 has the wrapper resolve the proxy's name once and hand every program the address.
For hop 1 that stands: it is the one host this machine must reach.

**Decision.** Hop *k* (*k* ≥ 2) is reached through hop *k*−1, which is asked for it by `CONNECT`
with the address as written: a numeric address as `ATYP 0x01` or `0x04`, a name as `ATYP 0x03`.
The name is never looked up on this host. The wrapper checks only its form (host, or `[v6]`, and a
port from 1 to 65535) and exports it unchanged.

**Why.** A local lookup tells this host's resolver, and anyone watching it, which proxies the chain
uses. And an internal name may resolve only inside the network behind the previous hop, which is
often why the chain exists.

**Consequence.** A misspelt later hop is reported by the hop before it (a `CONNECT` reply code),
when the chain is first used, not by the wrapper before the program starts.

---

## D-40
### The relay fixup applies per hop; the loopback guard looks at the exit hop

**Date:** 2026-10-20 · **Status:** Accepted · FR-CH-07, FR-CH-08. Amends D-16 and D-05 R2.

**Context.** D-16 replaces a wildcard `BND.ADDR`, or a loopback one from a proxy that is not on this
host, with the proxy's own address. D-05 R2 warns about a loopback destination when the proxy is not
local, because the proxy is where it will be resolved. Both read one flag, `proxy_is_local`.

**Decision.**

- **The flag is split.** *First hop is local* drives D-16 for hop 1, unchanged. *Exit is local*
  drives D-05 R2: true only for a chain of one whose proxy is on this host. For a longer chain, a
  loopback destination always warns, and `strict_loopback` refuses it.
- **Hop *k* (*k* ≥ 2):** a wildcard `BND.ADDR` means hop *k*'s address as given, which may be a
  name, carried as `ATYP 0x03` in the outer header. A loopback `BND.ADDR` is used only if hop *k*
  was itself given as a loopback address, so that it is on the same host as hop *k*−1; otherwise it
  is replaced by hop *k*'s address.
- **`localhost` counts as a loopback address** (added with chain setup, the same day). A hop given
  as `localhost`, in any case and with or without the root dot, is treated like one given as
  `127.0.0.1`: its loopback relay is kept, and a wildcard relay becomes the loopback address in the
  relay's family. RFC 6761 reserves the name for loopback. Without this, the relay would become the
  name `localhost`, which costs header bytes, may resolve at hop *k*−1 to `::1` when the relay
  listens only on `127.0.0.1`, and leaves D-41 only the port to check. Other names that happen to
  resolve to loopback stay names. The hop itself is still reached by name, as D-39 says.
- **A relay given by name is refused at every hop.** A `BND.ADDR` of `ATYP 0x03` in a UDP ASSOCIATE
  reply fails the chain with `EPROTO`, as 0.1.0 does for its one proxy. For hop 1 this must stay:
  this host sends to that relay, and would have to resolve it. For a later hop it could be accepted,
  since only the hop before it needs to resolve the name, at the cost of D-41 checking that layer by
  port alone. No proxy known to do this has been seen.

**Open questions, answered by interop** (2026-10-21, FR-CH-T4). Whether real proxies accept a name
(`ATYP 0x03`) in a UDP header, which the wildcard case with a named hop needs: all seven tested
did, as hop 1 with hop 2 given by name and its loopback relay replaced by that name. Whether any
answers UDP ASSOCIATE with a named relay: none of the seven did. Both on one host only
([`docs/INTEROP-CHECKLIST.md`](docs/INTEROP-CHECKLIST.md) §13).

---

## D-41
### Every layer of a received datagram is checked, or the datagram is dropped

**Date:** 2026-10-20 · **Status:** Accepted · FR-CH-06.

**Decision.** A datagram from hop 1's relay is unwrapped outermost first. Each layer must have
`RSV` 0 and `FRAG` 0, be well formed, and, for every layer but the innermost, name as its source
the relay of the next hop as fixed up by D-40. A failure at any layer drops the whole datagram;
nothing is delivered from it, and it is counted like any other dropped datagram. Only the innermost
source reaches the program.

Where the next relay is known only by name (D-40's wildcard case), the layer's address cannot be
compared without resolving the name here, which D-39 forbids. Its port is compared, and the README
says so.

**Why.** This is where a chain could repeat a defect two tools in the comparison have: a header
delivered as payload. An unchecked inner layer would also let anyone who can reach an intermediate
relay inject datagrams with a forged inner source.

---

## D-42
### At most 8 hops; `max_datagram` stays the program's payload

**Date:** 2026-10-20 · **Status:** Accepted · FR-CH-13.

**Decision.**

- **At most 8 hops.** Each hop adds a TCP connection per socket (D-26's protected range holds about
  256), a handshake to every connection setup, and up to 262 bytes of header. Eight is far beyond
  any practical pivot.
- **`max_datagram` keeps its meaning:** the largest payload the program may send. The shim's buffers
  grow by the worst-case header for each hop.
- **No automatic adjustment.** Each hop's buffer limits its payload plus the headers inside it, so
  the smallest buffer in the chain decides what fits (D-12: configured, not discovered). The README
  will say how to choose `max_datagram` for a chain.

---

## D-43
### A chain's setup failures name the hop, once a second

**Date:** 2026-10-20 · **Status:** Accepted · FR-CH-12. Extends D-33.

**Context.** An `errno` such as `ECONNREFUSED` cannot say which of several hops failed. For one
proxy, 0.1.0 reports a failure to reach or associate with it by the `errno` alone, and prints only
for authentication problems. A program that retries its sends rebuilds the whole chain on each
retry, so a line per failure would repeat once per send.

**Decision.**

- **In a chain, every setup failure prints one line naming the hop:** its position, the chain's
  length and its address as given, then what failed and the `errno`. For example:
  `hop 2 of 3 (10.0.0.5:1080): hop 1's CONNECT to it failed: Connection refused`. The `errno`
  is hop 1's reply code: refused, unreachable, or `Operation not supported` from a hop that does
  not do `CONNECT` at all.
- **At error level,** so `-q` does not hide it: with it hidden, the `errno` would not say which hop
  to look at.
- **At most one a second,** shared by all hops, as D-33 limits repeated warnings. The next line
  that prints says how many were held back.
- **No vaguer line after a specific one.** Where the negotiation has already said what went wrong
  (for example, `proxy rejected the supplied credentials`), prefixed with the hop, no generic
  `negotiation failed` line follows it. Those specific lines are not rate-limited, as in 0.1.0.
- **A chain of one prints exactly what 0.1.0 printed** (FR-CH-01): nothing for a failure to reach
  or associate, and the same authentication messages with no prefix.

**Consequences.** Because the limit is shared, a second, different failure within the same second
is counted rather than shown. A chain that keeps failing in one way shows one line a second.

**Revisit if:** users find a whole chain's failures held back by one noisy hop. The limit could
then be kept per hop.

---

## D-44
### Later hops are declared the unspecified address, in the family they see

**Date:** 2026-10-20 · **Status:** Accepted · FR-P-05, applied to each hop.

**Context.** FR-P-05 declares in UDP ASSOCIATE the address the client will send from, or
`0.0.0.0:0` when it does not know it. Hop *k* (*k* ≥ 2) receives its datagrams from hop *k*−1's
UDP relay socket, whose address and port this host is never told. The only address hop *k*−1
reports is the one its `CONNECT` to hop *k* came from, in the `CONNECT` reply's `BND.ADDR`, and that
is a TCP connection, not the UDP socket.

**Decision.** Hop *k* is declared the unspecified address with port 0, in:

1. the family of hop *k*'s own address, when it was given as a number;
2. otherwise, the family of the `CONNECT` reply's `BND.ADDR`, which is the family hop *k* sees the
   chain arrive in, a v4-mapped address counting as IPv4. A reply of all zeros, or naming a domain,
   is not taken as a signal, since proxies that send zeros send them whatever the family;
3. otherwise, IPv4.

**Rejected: declaring the `CONNECT` reply's address with port 0.** A proxy that pins an association
to the declared address (Dante with `udp.connectdst`, the fixture's `--pin-declared`) would then
accept datagrams from hop *k*−1, but only if hop *k*−1 sends its UDP from the same address as its
TCP connection. That is common but not guaranteed, and where it fails the association silently
drops everything, which is the failure FR-P-05 exists to prevent.

**Revisit if:** interop (FR-CH-T4) finds a proxy that needs a declared address to serve as a later
hop, and that the address its predecessor connects from is also the one it sends UDP from.

---

## D-45
### Setup has an overall deadline, `chain_timeout`: by default `connect_timeout` per hop of a chain

**Date:** 2026-10-20, amended 2026-10-21 · **Status:** Accepted · FR-CH-02. Settles the
setup-time question that [`docs/FUTURE-UDP-CHAINS.md`](docs/FUTURE-UDP-CHAINS.md) §8 left for
step 4.

**Context.** `connect_timeout` (5 s by default) bounds each wait of a handshake: the connect, and
each reply. Hop *k* is reached through the *k*−1 hops before it, so a chain of *n* hops makes
*n*(*n*+1)/2 handshakes, 36 for 8 hops. A chain whose hops are slow but alive, each step just inside
its timeout, could take minutes to set up, and the program blocks on its first send for all of it.

**Decision.**

- **Every wait keeps its own `connect_timeout`,** as in 0.1.0.
- **The whole setup must also finish within `chain_timeout`,** counted from the start of the
  association, across all its handshakes. When that runs out, the wait in progress fails with
  `ETIMEDOUT`, the hops already up are released, and the diagnostic names the hop being set up
  (D-43). No wait runs past it, even if its own `connect_timeout` has longer to go.
- **`chain_timeout` is a setting:** `chain_timeout` in the config file, `UDPCHAINS_CHAIN_TIMEOUT`
  in the environment, in ms. The wrapper passes it to the shim like the other settings, and
  passes "unset" on as unset. It has no command-line flag, as `connect_timeout` has none.
  - **Unset,** it is `connect_timeout` × the number of hops for a chain of more than one, and
    there is no overall deadline for a chain of one, so a single proxy behaves exactly as 0.1.0
    (FR-CH-01): one whose every step is in time still succeeds, however long they take together.
  - **Set to a number of ms,** it is the deadline, for any chain, a chain of one included. A
    value below `connect_timeout` is allowed and shortens every wait with it.
  - **Set to 0,** there is no overall deadline, for any chain.
  - **It accepts 0 to 4,800,000:** up to 8 hops of the longest `connect_timeout`, the most the
    default can come to.
- **The same deadline bounds a `CONNECT` through the chain** for the resolver's TCP fallback (D-22).
- **It applies to each attempt.** A failed setup is retried once, so a send can block for up to
  about twice the deadline before it fails.

**Why this default.** It scales with the chain, so adding hops does not start cutting a healthy
chain off: each hop gets as long as a single proxy's slowest step.

**Why a setting, and one total.** The default is a guess. A chain through slow hops, Tor or a
satellite link, may need longer; a program that would rather fail fast may want less. A single
number is the easiest to reason about: the most time a send can spend setting up.

**Why it applies to a chain of one when set.** A single proxy is a chain of one, and silently
ignoring a value the user wrote down would be surprising. Unset, 0.1.0's behaviour is kept.

**Rejected.**

- **A time per hop** (`hop_timeout` × hops). It scales by itself, but a non-uniform chain, one slow
  hop among fast ones, fits it poorly, and it says less plainly how long a send can block.
- **A multiplier** of `connect_timeout` × hops. The user has to do arithmetic to know the limit.
- **A setting in each `[hop]` section,** summed. Hops given with `-p` or `UDPCHAINS_PROXY` cannot
  carry one, and it is more than the problem needs.
- **No overall deadline.** The program could block for minutes on a send with no error.
- **As first decided, no setting at all,** leaving `connect_timeout` as the only knob. Raising it
  to let a slow chain finish also lengthens every wait, which is not the same thing.

**Revisit if:** interop shows the default cutting off real chains whose steps are each quick.

---

## D-46
### When the shim's descriptor range is full, its connection stays where it is, protected, and that is reported

**Date:** 2026-10-21 · **Status:** Accepted · FR-CH-10. Extends D-26.

**Context.** D-26 moves each of the shim's own descriptors into a range starting at 768, or at half
the soft limit when that is below 1024, and marks it, so the program's close and `dup2` calls
cannot take it. With the usual limit of 1024 the range holds 256. A single proxy uses one per
socket, which a program would hit its own limit long before filling. A chain uses one per hop per
socket: 85 sockets through 3 hops, 32 through 8. Until now, a descriptor that could not be moved
stayed where it was without a word, and one that could not be marked was left unprotected.

**Decision.**

- **The connection is kept, at the number it has.** It is still marked, so the program's `close`
  is refused and its `dup2` onto it fails, as in D-26. What it loses is being out of the way: it
  takes a low number the program might otherwise have been given. This was already the code's
  fallback; D-46 makes it a decision and reports it.
- **That is reported** as a warning naming the range and the descriptor, at most once a second,
  as D-33 limits repeated warnings.
- **A descriptor that cannot be marked** (above the fd table's 2^20, or out of memory) is also
  kept and reported: a close-all loop in the program could take it, and the association would
  then be set up again on the next send (FR-P-08).
- **With no descriptor at all,** setup fails and the program's send fails with `EMFILE`, naming
  the hop in a chain (D-43). Nothing is ever sent directly (SEC-01).

**Cost.** A low number is not only cosmetic. Low numbers are the ones programs choose on purpose:
shells redirect onto 3 to 9 (`exec 5>file`), and daemons `dup2` onto fixed numbers for their
children. D-26's `EBUSY` for a `dup2` onto a shim descriptor was a remote case in the 768+ range;
with the shim's connection at, say, fd 5, it is a likely one, and a program that does not expect
`dup2` to fail may stop. The warning is there so that such a failure can be traced to the shim.
It is never a leak: the descriptor still carries only the shim's traffic to hop 1.

**Rejected.**

- **Failing the association when the range is full.** It would keep D-26's guarantee exactly,
  but a program that would otherwise run fails at its 86th socket through 3 hops, every time,
  where the cost above is a failure only if the program `dup2`s onto that number. D-37's
  strictness is about where traffic goes; this is only about which number a descriptor gets.
- **Raising the soft limit, or the range,** for the program. The range cannot go above the soft
  limit, so this means `setrlimit` on the program's behalf: its children inherit it, and
  `select()` breaks above 1024. D-26 already rejects growing the descriptor table.
- **Leaving it silent,** as before. The same behaviour, but a user whose program fails a `dup2`
  with `EBUSY` would have nothing to connect it to.
- **A setting choosing between keeping and failing.** Not until a program is found that needs it.

**Verified by** `test_faults.sh`: with the soft limit at 64 and a 3-hop chain, the range (32 to 63)
fills after ten sockets. Fifteen associations work, the warning is printed, the send that finds no
descriptor fails with `EMFILE`, and the exit hop relayed exactly the datagrams reported sent.

**Revisit if:** a real program is found to need more than the range holds, through a chain, or
fails a `dup2` onto a shim connection that stayed at a low number.

---

## D-47
### A proxychains.conf is read as it is, for the strict chain of `socks5` hops it shares

**Date:** 2026-10-21 · **Status:** Accepted · FR-CH-14, FR-C-04. Chosen by the maintainer: a real
`proxychains.conf` rather than only its `[ProxyList]` stanza inside a udpchains file; directives
without an equivalent warned about rather than refused or dropped silently; inline passwords
allowed, as `password =` is.

**Context.** FR-C-04 asks that proxychains users' configuration carry over, and was deferred with
chains (D-08). D-38 chose `[hop]` sections as udpchains' own format, and noted that a `[ProxyList]`
line has nowhere safe to put a password. Written from the format as proxychains documents it:
directives one to a line, then `[ProxyList]` with one proxy to a line, `type host port [user
pass]`, separated by spaces or tabs. Never from its source (D-01).

**Decision.**

- **`udpchains -f proxychains.conf` works.** The file is read by the same reader as any config
  file, and is never looked for by default. `[ProxyList]` lists the hops in order, the first being
  hop 1. Each hop fills the same fields a `[hop]` section does, so everything after reading —
  merging, the handoff to the shim, passwords by location (D-25), at most 8 hops (D-42) — is
  unchanged.
- **Only `socks5` lines.** `socks4`, `http` and `raw` cannot carry UDP and are errors naming the
  line. A bare IPv6 address is bracketed; a name is kept as written (D-39).
- **proxychains' directives,** before `[ProxyList]`:
  - `strict_chain` is accepted: it is what udpchains does.
  - `dynamic_chain`, `random_chain` and `round_robin_chain` are errors (D-37).
  - `quiet_mode` sets `quiet`; `tcp_connect_time_out` sets `connect_timeout`.
  - `chain_len`, `tcp_read_time_out`, `proxy_dns` and its variants, `remote_dns_subnet`,
    `localnet` and `dnat` are not applied, and the wrapper names each in a warning saying what
    happens instead. None of them can cause a direct send: `localnet`'s traffic goes through the
    proxies or fails (D-05), and names are looked up at `dns` through them, or fail.
  - udpchains' own `key = value` settings may sit beside them.
- **Inline credentials** (`socks5 host port user pass`) are accepted, with the rule an inline
  `password =` has: a warning if others can read the file, and the password passed on by naming
  the file, never by value (D-25). A password containing a space or tab, or starting with `#`,
  cannot be written on such a line; `[hop]` sections with `password_file` can hold any.
- **One way per file.** `[ProxyList]` with `proxy =` or `[hop]` sections, a second
  `[ProxyList]`, an empty one, or a setting after it are errors. `-p` and `UDPCHAINS_PROXY` still
  replace the file's chain whole (D-38).
- **The warnings are the wrapper's.** A shim reading the same file for a password says nothing,
  as for permission warnings (D-33).

**Rejected.**

- **Only the `[ProxyList]` stanza, in a udpchains file.** Every real proxychains.conf has
  directives, so none would load without editing; "carry over" would mean copy and trim.
- **Refusing directives udpchains does not apply.** Nothing in the file would be silently not
  honoured, but almost every real file would fail to load, for settings that are about TCP or
  proxychains' DNS and cannot make udpchains send anything directly.
- **Ignoring them silently.** A user relying on `localnet` or `proxy_dns` would get no hint.
- **Refusing inline passwords.** Keeps D-38's objection absolute, but no authenticated
  proxychains.conf would carry over, and the inline `password =` already has the same exposure.

**Verified by** `unit-config` (a file of proxychains' shape, read and handed to the shim; each
refusal with its line) and `test_auth.sh` (a proxychains.conf whose hop 2 requires the login on its
line: the datagram round-trips, the proxy logs the login, the password is passed on by naming the
file, three directives are warned about once each, and a `dynamic_chain` file runs nothing).

---

## D-48
### Supervisor mode intercepts system calls with seccomp user notification

**Date:** 2026-10-22 · **Status:** Accepted; built for x86-64 (steps 2 and 3); revised by
[D-54](#d-54), which carries calls on the reserved range through `ptrace` · FR-SV-02, FR-SV-03,
FR-SV-13.
Revisits FR-I-01 (`LD_PRELOAD` as the only mechanism). Background:
[`docs/FUTURE-STATIC-BINARIES.md`](docs/FUTURE-STATIC-BINARIES.md).

**Context.** Static binaries, Go binaries and programs making their own system calls never call
libc, so the shim cannot see their UDP, and they send directly. They can be seen only at the
system-call boundary, from outside the process.

**Decision.** `udpchains` stays running as the program's parent, the **supervisor**. Before the
program runs, the child sets `no_new_privs` and installs a seccomp filter with
`SECCOMP_FILTER_FLAG_NEW_LISTENER`, and hands the listener to the parent. The filter returns
`SECCOMP_RET_USER_NOTIF` for the calls D-50 and D-53 select, and lets everything else through in
the kernel. The supervisor performs each trapped call itself, or answers it with an error.

- **Fail-closed by construction** (FR-SV-13). Once the supervisor has gone, every trapped call in
  the program fails with `ENOSYS` (`seccomp(2)`, `seccomp_unotify(2)`). A filter cannot be
  removed, and is inherited across `fork` and `exec`.
- **One ABI** (FR-SV-03). The filter checks `arch` first, and fails any call from another ABI. On
  x86-64 it also fails any call number with `__X32_SYSCALL_BIT` set, since x32 shares x86-64's
  `arch` value (`seccomp(2)`). An architecture the filter does not know is refused, never
  allowed.
- **Reading and writing the program's memory** uses `process_vm_readv` and `process_vm_writev`.
  Every read is followed by `SECCOMP_IOCTL_NOTIF_ID_VALID` before the bytes are used, as
  `seccomp_unotify(2)` requires, so a call the program abandoned is never acted on.
- **The shim's code is reused:** the SOCKS5 client, chains, the header codec, configuration and
  address checks. The supervisor is a second front end, not a second implementation.

**Rejected.**

- **`ptrace`.** If the tracer dies, the program continues untraced and sends directly (SEC-01).
  It conflicts with `gdb` and `strace`, and the `ptrace` tool in the comparison lab ran reliably
  only with Docker's seccomp filter disabled.
- **A network namespace with a TUN device.** The strongest guarantee, but it needs unprivileged
  user namespaces, which Ubuntu 24.04 restricts by default, and the program's TCP would have
  nowhere to go unless udpchains carried TCP too (a §8 non-goal).

**Known limitations.**

- **Not a sandbox.** A call the supervisor lets continue in the kernel
  (`SECCOMP_USER_NOTIF_FLAG_CONTINUE`) is checked first and then performed, and a hostile program
  can change what it refers to in between, from another thread (`seccomp_unotify(2)` warns of
  exactly this). Like the shim, supervisor mode keeps a cooperative program from leaking by
  accident; it does not contain one trying to escape.
- **Access to the program's memory** needs the same permission as `ptrace`. Yama's default
  (`ptrace_scope` 1) lets a parent reach its children; a stricter setting does not, and the mode
  then refuses to start (D-53).
- **Inside containers,** a runtime's own seccomp profile may forbid installing the filter. The
  mode then refuses to start; it never runs the program unsupervised (FR-SV-02).

**Built in step 3** (2026-10-22): the supervisor is one thread, which answers every call in turn,
carrying the program's UDP through the same SOCKS5 client, chain codec and datagram checks as the
shim (`dgram.c` holds the checks both front ends apply). It adds three limitations:

- **Setting up an association holds up the program's other trapped calls.** While the supervisor
  waits for the proxy (up to `connect_timeout` per hop), every other trapped call in every
  supervised process waits too. Other system calls do not.
- **A process that makes itself non-dumpable cannot be inspected.** Linux then denies the
  supervisor `ptrace`-level access to it, as Yama's stricter settings do. Its connects and sends,
  TCP and Unix sockets included, fail with `EPERM`, and it cannot make a UDP socket; files, pipes
  and `read`/`write` below the range still work. It fails closed, with a diagnostic that names
  the cause. `ssh-agent` and `gpg-agent` are such programs (`prctl(PR_SET_DUMPABLE, 0)`; checked
  on this host, where the `ssh` client is not), and so is a process running a binary it cannot
  read. It matters most when such an agent is started under a supervised program, which it then
  inherits. Chosen by the maintainer over letting such a process's connects and sends below the
  range through unchecked, which would widen the received-socket gap (D-50) for it.
- **A send interrupted after its datagram has left is sent again** if the call restarts
  (`SA_RESTART`). UDP permits duplicates, but a native send is never repeated. *Removed by D-54:*
  a send is now performed while its thread is stopped.

**Revisit if:** a kernel interface appears that lets a supervisor see a descriptor's type in the
filter, which would remove the reserved range (D-50).

---

## D-49
### Supervisor mode is chosen explicitly, and never combined with the shim

**Date:** 2026-10-22 · **Status:** Accepted; built (steps 2 and 3) · FR-SV-01, FR-SV-17. Chosen by the
maintainer over choosing it automatically for static and Go binaries, and over supervising every
program.

**Decision.**

- **Explicit.** `udpchains --supervise <program>`, or `supervise = yes` in a config file, or
  `UDPCHAINS_SUPERVISE=1`, with the usual precedence (FR-C-02). Without it, behaviour is exactly
  0.2.0's. Configuration, credentials (SEC-03, D-25), chains and diagnostics are the same in both
  modes.
- **One front end per program.** A supervised program is not given the shim: the wrapper does not
  set `LD_PRELOAD`, and removes `libudpchains.so` from an inherited one. Everything the program
  starts stays supervised, since the filter is inherited and cannot be removed, so no descendant
  falls back to the shim or to nothing.
- **No automatic choice yet.** FR-SV-17 (supervising static and Go binaries without being asked)
  waits until supervisor mode has had the interop the shim has had.

**Rejected.**

- **Automatic for static and Go binaries.** Convenient, since such a program sends directly
  today, but it would put a new, less tested mode, with a higher kernel floor, under users who
  did not ask for it.
- **Supervising every program.** One mode to test, but every program would pay the supervisor's
  cost per call and its kernel floor, and 0.2.0's behaviour would change for everyone.
- **Both front ends on one program.** Every UDP call would be seen twice, by the shim inside and
  the supervisor outside, with two sets of headers and two views of each descriptor.

**Known limitation.** A user must know to ask: a static or Go program run without `--supervise`
still sends directly, as in 0.2.0, which the README already says.

**Built in step 3** (2026-10-22): an inherited `LD_PRELOAD` naming `libudpchains.so` has already
loaded the shim into `udpchains` itself by the time it reads its configuration. There the shim
would wrap the supervisor's own datagrams a second time. So `udpchains` removes the shim from
`LD_PRELOAD` and runs itself again (`/proc/self/exe`), before changing anything else. If it
cannot, it refuses to supervise.

**Revisit if:** supervisor mode has had remote and real-proxy interop; then FR-SV-17.

---

## D-50
### UDP sockets live in a reserved range; outside it, UDP sends and connects are refused

**Date:** 2026-10-22 · **Status:** Accepted; built (steps 2, 3 and 5) · FR-SV-04, FR-SV-18. Chosen by the
maintainer: trap sends on every descriptor and check its type, with three additions, over
trapping `recvmsg` everywhere and over documenting the gap.

**Context.** A seccomp filter sees a call's number and its raw arguments, never what a descriptor
refers to. `write` and `writev` carry nearly all of a program's I/O; sending every one to the
supervisor would cost two context switches on each.

**Decision.**

- **The reserved range.** Every `AF_INET`/`AF_INET6` `SOCK_DGRAM` socket the program creates is
  made by the supervisor and installed in the program at a number in the range
  (`SECCOMP_IOCTL_NOTIF_ADDFD`), and the supervisor keeps a copy of the same open file. The range
  starts as D-26's does: at 768, or at half the soft `RLIMIT_NOFILE` when that is below 1024. The
  filter traps `read`, `write` and the other data calls only for numbers in the range, so file
  and TCP I/O below it never leaves the kernel. A program descriptor that reaches the range is
  checked by the supervisor and let through (`SECCOMP_USER_NOTIF_FLAG_CONTINUE`).
- **The `dup` family** on a descriptor in the range is performed by the supervisor, inside the
  range; one that would put a UDP socket outside it is refused.
- **Outside the range, the type is checked.** `sendto`, `sendmsg` and `sendmmsg` on any descriptor
  are trapped. Outside the range the supervisor takes a copy of the descriptor (`pidfd_getfd`)
  and asks its domain and type: a UDP socket fails with `EPERM` and a diagnostic; anything else is
  let through. `send` is covered: on x86-64 and aarch64 libc implements it with `sendto`.
- **And three additions**, each cheap because the call is rare:
  - `connect` on any descriptor is trapped; outside the range, a UDP socket is refused with
    `EPERM`. A received socket the program connects itself cannot then be written to.
  - `sendfile` and `splice` are trapped on any descriptor, and refused with `EINVAL` when the
    destination is a UDP socket, as the shim refuses them (D-36). (`vmsplice` only fills a pipe;
    sending from it needs `splice`.)
  - **At start-up,** the descriptors the program would inherit are checked. A UDP socket among them
    (one handed over by a service manager, say), or a raw or packet socket (D-36), makes the
    supervisor refuse to start, naming the descriptor: it cannot be moved into the range without
    changing the number the program expects.

**Rejected.**

- **Trapping `recvmsg` everywhere,** to catch a UDP socket arriving over `SCM_RIGHTS` and move it
  into the range. It closes the gap below, but every `recvmsg` on every Unix socket — all of a
  D-Bus or Wayland program's traffic — would go through the supervisor.
- **Documenting the gap only,** as D-21 once did for the shim. A real leak path for programs that
  pass sockets between processes.

**Known limitations.**

- **A UDP socket received already connected, then written with `write`, `writev` or `pwritev2`,
  sends directly.** All four must hold: the socket arrives from another, unsupervised process
  over `SCM_RIGHTS`; it was connected before it was sent; the program never connects it again;
  and it sends with the write family rather than a send call. This is rare for the client
  programs supervisor mode is for, and most likely in privilege-separated daemons.
- **Cost outside UDP.** Every `sendto`, `sendmsg` and `sendmmsg` on a non-UDP descriptor makes a
  round trip to the supervisor for the type check: notably D-Bus, which sends with `sendmsg`, and
  TCP programs that use `sendmsg`. So does every `connect`.
- **A supervised UDP socket passed to an unsupervised process** is still connected to the relay.
  What that process writes reaches the relay without a SOCKS header, and goes no further; it is not
  a leak, but it does not work.
- **The range is decided before the program runs.** A program that raises its own descriptor
  limit later (Go does, at start-up) keeps the range where it was.

**Open for step 3** of the plan, and settled there (below): placing a socket at a number in the
range must not replace a descriptor the program already has there; how the supervisor finds a
free number, and what it does when the range is full (D-46 is the shim's answer).

**Built in step 2** (2026-10-22): the checks outside the range, the three additions, and the
start-up check, all as above. Until step 3 carries UDP, every UDP socket is outside the range, so
`socket()` refuses one with `EPROTONOSUPPORT` instead of making it: the mode fails closed at every
step of its construction. A mutation that stopped trapping `socket()` was still caught by the
checks outside the range: nothing was sent.

**Built in step 3** (2026-10-22): UDP is carried, and the refusal at `socket()` is gone.

- **Where a socket goes.** At the lowest free number at or above the range's start in the calling
  process, below its `RLIMIT_NOFILE`. The supervisor finds it by asking for each number in turn
  (`pidfd_getfd`), and installs the socket and answers the call in one step
  (`SECCOMP_ADDFD_FLAG_SEND`). With no free number, `socket()` fails with `EMFILE`, as a full
  descriptor table does. D-46's answer does not apply: there is nowhere else to put the socket.
- **What the supervisor knows is kept per socket, not per descriptor.** Entries are keyed by the
  kernel's socket cookie, which is never reused. A `dup`, a `fork`, an `exec`, or a socket passed
  between supervised processes all find the same entry, as they share one socket in the kernel.
  Nothing per process or per number can go stale.
- **Noticing a socket closed.** The kernel does not tell the supervisor when a program's last
  descriptor for a socket closes, so the supervisor looks. 200 ms after a close in the range or a
  child's exit, and every 5 s while it carries any socket, it reads `/proc/<pid>/fd` of each
  descendant. A socket none of them holds in the range has its association closed. A descendant
  whose descriptors cannot be read holds that sweep back entirely, so nothing in use is forgotten.
- **The `dup` family.** `dup` and `fcntl(F_DUPFD, F_DUPFD_CLOEXEC)` of a carried socket are placed
  in the range. `dup2` and `dup3` to a number in the range are let through; below it, they are
  refused with `EPERM` and a diagnostic.

It adds two limitations:

- **A narrow race in placing a socket.** The program allocates lowest-free, so it reaches the
  range only once it has the range's start of descriptors open. Even then, another of its threads
  would have to open a descriptor at the same number, between the supervisor's check and the
  install, for that descriptor to be replaced.
- **A carried socket that reaches another supervised process below the range** (over
  `SCM_RIGHTS`) still has its sends and `connect` carried, since those are trapped on every
  descriptor. `write` and `read` there are not trapped: what is written reaches the relay without
  a header and goes no further, and what is read still has its header. Neither is a leak.

**Built in step 5** (2026-10-23): threads, `fork`, `vfork`, `clone` and `exec`.

- **A thread with a descriptor table of its own** (`unshare(CLONE_FILES)`) is reached through a
  pidfd for the thread itself (`PIDFD_THREAD`, Linux 6.9), which `pidfd_getfd` reads that table
  through. `kcmp(KCMP_FILES)` tells whether a thread's table is its process's. Without this, its
  descriptors were looked up in its process's table, and a socket could be placed over one of
  its own descriptors. The sweep reads such a thread's table as well
  (`/proc/<pid>/task/<tid>/fd`), so a socket held only there is not forgotten.
- **Processes sharing one table** (`clone(CLONE_FILES)` without `CLONE_THREAD`) need nothing
  more: each one's pidfd reaches the table they share.
- **An `exec` prompts a sweep,** since it closes the close-on-exec descriptors.

It adds one limitation:

- **Before Linux 6.9,** a thread with a table of its own cannot be reached. Its calls on a
  descriptor in the range, and its UDP `socket()`, fail with `EPERM` and a diagnostic, rather
  than act on another table. On a kernel without `kcmp` (no `CONFIG_KCMP`), every thread is taken
  to share its process's table, as before.

**Revisit if:** the gap above is met by a real program, which would justify trapping `recvmsg` on
Unix sockets.

---

## D-51
### A supervised receive peeks, delivers, and consumes only once the program has the datagram

**Date:** 2026-10-22 · **Status:** Superseded by [D-54](#d-54), which found that a reply the
kernel accepted can still be discarded, losing the datagram; built in part (step 3) · FR-SV-07,
FR-SV-08. Chosen by the
maintainer over letting signals wait, and over accepting an occasional lost datagram.

**Context.** While the supervisor performs a receive, the program's call can be interrupted by a
signal. The supervisor is not told: its reply then fails with `ENOENT`, and with `SA_RESTART` the
call comes back as a new notification (`seccomp_unotify(2)`). A datagram already taken off the
socket at that point would be lost.

**Decision.**

- **Peek, deliver, commit.** The supervisor reads the next datagram with `MSG_PEEK`, checks and
  strips its headers (D-41), writes the payload and the real sender into the program, checks the
  notification is still valid, and replies. Only if the reply is accepted does it consume the
  datagram from its copy of the socket. If the call was interrupted, the datagram stays queued for
  the next receive. A datagram whose headers fail the checks is consumed and dropped at once, as
  in shim mode, since it could never be delivered.
- **Blocking receives** are run by a worker, which waits on the socket and on the notification
  staying valid, so an interrupted call is abandoned rather than left holding the socket.
- **Native behaviour otherwise.** `O_NONBLOCK` and `SO_RCVTIMEO` belong to the shared open file, so
  the supervisor's copy sees the program's settings; `MSG_DONTWAIT` is taken from the call. With
  nothing queued, a non-blocking receive fails with `EAGAIN` at once. An interrupted call returns
  `EINTR`, or restarts under `SA_RESTART`, as on a native socket.
- **Receives on one socket are serialised** in the supervisor, so the datagram peeked is the one
  consumed.

**Rejected.**

- **Letting signals wait** while the supervisor holds a receive. Simplest, but a program that
  relies on `alarm()` or another signal to break a blocking `recvfrom` would hang.
- **Consuming first and accepting the loss.** UDP may drop anything, but a loss caused by a signal
  is a difference from a native socket that programs cannot reason about.

**Known limitations.**

- **`recvmmsg` returns at most one datagram per call** in this mode: only the first queued
  datagram can be peeked. `recvmmsg` may always return fewer than asked.
- **An interrupted receive may still have written to the program's buffer** before the
  interruption was seen. The call reports `EINTR` or restarts, as it should; only the buffer's
  contents differ from a native socket's, which callers should not read after a failed call.
- **A socket also read by an unsupervised process** can lose a datagram: that process could take
  the peeked datagram before the supervisor consumes it, and the supervisor would then consume the
  next one.
- **Each receive costs** two context switches and a copy in each direction, against about 1 µs
  for the shim; it will be measured (FR-SV-15).

**Built in step 3** (2026-10-22): peek, deliver and commit, as decided. A blocking receive with
nothing queued is **parked** rather than given to a worker. Its call waits in the program while
the supervisor, one thread, watches the socket in its own loop, and answers the call when a
datagram arrives. At the socket's `SO_RCVTIMEO` it answers `EAGAIN`, as a native socket would. A
call that has gone is forgotten: the same thread's next call shows it was interrupted, and parked
calls are asked once a second whether they are still pending. A signal interrupting a waiting
receive gives `EINTR` (tested). Left for step 4: the signal tests of FR-SV-T4, including
`SA_RESTART` and that no datagram is lost. *Step 4 found the loss this design cannot prevent, and
replaced it (D-54).*

---

## D-52
### Queries to the system resolver are redirected to `dns`, through the proxy

**Date:** 2026-10-22 · **Status:** Accepted; built (step 6) · FR-SV-12. Revisits D-22, whose
libc-level resolver does not apply in this mode. Chosen by the maintainer over proxying port 53 as
addressed.

**Context.** A supervised program runs its own resolver, glibc's, musl's or Go's, reading
`/etc/resolv.conf`. On systemd-resolved hosts its nameserver is `127.0.0.53`, which, proxied as
addressed, would be resolved at the proxy host and usually fail. Resolvers also check that a reply
comes from the address they asked.

**Decision.**

- **A UDP datagram to port 53 of the system resolver** — a loopback address, or a nameserver listed
  in `/etc/resolv.conf` — is sent through the proxy (or chain) to the configured `dns` server
  instead. Its reply is reported as coming from the address the program asked, so the resolver
  accepts it.
- **`/etc/resolv.conf` is read again whenever it changes,** so a nameserver that a VPN or DHCP
  puts there while the program runs is recognised as the system resolver too.
- **With `dns` unset,** such a datagram fails with `ENETUNREACH`, so lookups fail, as they do in
  shim mode (D-22); none goes anywhere directly.
- **Port 53 elsewhere** (`dig @9.9.9.9`) is proxied as addressed, exactly as the shim does, so a
  user's explicit choice of server is kept.
- **TCP to the system resolver's port 53** is never made directly. It is carried by SOCKS5
  `CONNECT` to `dns`, as the shim's fallback is; until that is built, the connect is refused with
  `ECONNREFUSED`, so a truncated answer fails rather than leaks.

**Rejected.**

- **Proxying port 53 as addressed.** Simplest, and what the shim does for `dig`, but on most
  desktop hosts lookups would fail.
- **Redirecting every port-53 datagram,** whatever its destination. It would silently replace a
  server the user named.

**None of this is a leak.** Under any rule, every datagram goes through the proxy; the rule only
decides which server the proxy forwards a query to. A server named explicitly sees the proxy's
address, not this host's.

**Known limitations.**

- **A resolver configured somewhere other than `/etc/resolv.conf`,** on an address that is not
  loopback (a program's own setting, say), is proxied as addressed. A private address such as
  `192.168.1.1` is then reached on the proxy's network, so lookups fail; nothing leaks.
- **A local DNS server's own entries are not used.** A query to dnsmasq or similar on loopback goes
  to `dns` instead, as in shim mode (D-22): answering it locally would let that server forward the
  rest upstream directly. Entries in `/etc/hosts` still work, since the program's resolver reads
  that file itself.
- **Split DNS,** names that only a VPN's or a company's resolver knows, works only if `dns` is a
  resolver that knows them and that the proxy can reach.
- **DNS over TCP to other servers, DNS over TLS and DNS over HTTPS** are TCP, which udpchains does
  not proxy (§8), in either mode.

**Built in step 6** (2026-10-23), as decided:

- **The redirect.** A send on a carried socket to the system resolver has its destination
  replaced by `dns` in the SOCKS header, and the address it was sent to is kept with the socket.
  A socket connected to the system resolver accepts datagrams from `dns`, as the kernel's peer
  check would from the address it connected to. A reply from `dns` on such a socket is reported as
  from the address the program asked, in the socket's family. The loopback guard (D-05 R2)
  considers `dns`, where the datagrams go, not `127.0.0.53`.
- **The system resolver** is port 53 of any loopback address, `127.0.0.0/8`, `::1` and their
  IPv4-mapped forms, or of a `nameserver` in `/etc/resolv.conf`, its zone index ignored. The
  file is read again when its device, inode, size or modification time changes, which catches a
  file replaced by rename, as DHCP and VPN clients write it.
- **TCP to the system resolver's port 53** is refused with `ECONNREFUSED` and a diagnostic, by
  `connect()` or by a `sendto()` or `sendmsg()` that names it (TCP Fast Open). Carrying it by
  SOCKS5 `CONNECT` is not built.
- Tested with a static probe through the fixture proxy to `dnsd`: `sendto()` to `127.0.0.53` and
  `::1`, a `connect()`ed socket as glibc's resolver uses one, a static program's `getaddrinfo()`,
  a static Go program's own resolver, port 53 elsewhere not reaching `dns`, the TCP refusals, and
  `dns` unset. Through each of the seven proxies of the interop suite as well.

It adds one limitation, found while building it:

- **Lookups through an NSS module that asks a local daemon are not seen.** `nss-resolve` asks
  systemd-resolved over its Unix socket (`/run/systemd/resolve/io.systemd.Resolve`), `nscd` and
  `mdns` (avahi) theirs, and the daemon resolves the name itself, outside the proxy. A static
  glibc program loads these modules too. Ubuntu's default `hosts:` line (`files mdns4_minimal
  [NOTFOUND=return] dns`) sends everything but `.local` names by DNS; distributions that list
  `resolve` before `dns` do not.

---

## D-53
### What supervisor mode refuses, and Linux 5.14 as its floor

**Date:** 2026-10-22 · **Status:** Accepted; built (step 2) · FR-SV-02, FR-SV-09. Revisits D-29 and
D-36 (their refusals made at the system call instead of at libc), and NFR-01a (a higher floor for
this mode only).

**Decision.**

- **Refused, each with a diagnostic:**
  - `io_uring_setup`, with `ENOSYS`: the "not available" answer most programs fall back from. It
    is refused for files too, since the filter cannot tell what a ring will be used for. This
    closes the route the shim cannot (D-36).
  - `sendfile` and `splice` onto a UDP socket, with `EINVAL` (D-36, D-50).
  - `pidfd_getfd`, with `EPERM`: a copy of another process's descriptor would arrive outside the
    range.
  - Raw and packet sockets with `EPERM` (D-36), and ICMP and UDP-Lite sockets with
    `EPROTONOSUPPORT` (D-29), at `socket()`.
  - UDP sends and connects outside the range, with `EPERM` (D-50).
- **The floor is Linux 5.14,** for `SECCOMP_ADDFD_FLAG_SEND`, which installs a socket and answers
  the call in one step so none is leaked into the program (5.9 for `ADDFD`, 5.6 for
  `pidfd_getfd`, 5.0 for user notification). That matches the distributions with glibc 2.34
  (Ubuntu 22.04, RHEL 9). The shim's floor is unchanged.
- **Refusing to start** (FR-SV-02): on an older kernel, when the filter cannot be installed (a
  container's seccomp profile, say), when the program's memory cannot be reached (Yama
  `ptrace_scope` above 1), when the program cannot be traced (D-54: it is already traced, or
  `ptrace` is forbidden), or with an inherited UDP socket (D-50). The program is never run
  unsupervised.

**Why refusing `io_uring` is acceptable.** A filter sees only `io_uring_setup`, never what a ring
is later asked to do, and one ring does file and network work alike; allowing rings would reopen
the route the shim cannot close (D-36). Refusing it costs little for the programs this mode is
for: Go's standard library does not use `io_uring`, and static C tools rarely do. Many
environments already refuse it, for its record of kernel security bugs (Docker's default seccomp
profile in recent releases, ChromeOS, Android, and Linux's own `io_uring_disabled` setting), so
software that uses it generally handles `ENOSYS` and falls back to ordinary calls.

**Known limitations.**

- **Programs that use `io_uring` lose it,** for files too: some databases, QEMU's optional
  backend, `fio`. Most fall back to ordinary calls. A framework that requires it, with no
  fallback, fails to start under supervision. A dynamically linked one can still run under the
  shim, which cannot refuse `io_uring` (D-36).
- **Debian 11 and other pre-5.14 kernels** cannot use the mode.

**Revisit if:** a program is found that needs `io_uring` and cannot fall back; refusing only rings
that touch sockets would need inspecting each submission, which a seccomp filter cannot do.

---

## D-54
### A supervised program's calls on its UDP sockets are carried while it is stopped, through `ptrace`

**Date:** 2026-10-23, amended the same day (step 5) · **Status:** Accepted; built for x86-64
(steps 4 and 5) · FR-SV-06, FR-SV-07, FR-SV-08, FR-SV-13, FR-SV-T4. Revises D-48 (which
rejected `ptrace`) and D-51 (peek, deliver, commit), for the calls below. Chosen by the
maintainer over accepting a rare lost datagram, over checking for a pending signal before each
reply, and over making waiting receives uninterruptible.

**Context.** Step 4's signal tests found that D-51 cannot keep its promise that no datagram is
lost. With seccomp user notification, the supervisor's reply and the program's view of its call are
not settled at the same moment: the thread waits interruptibly until the reply is collected. When
a signal lands in that instant, `SECCOMP_IOCTL_NOTIF_SEND` succeeds, yet the call returns `EINTR`
or restarts, and the reply is discarded. A successful reply is therefore no proof that the program
has the datagram, and nothing the supervisor can see afterwards tells the two cases apart. Traced
twice: the payload had been written into the program's buffer and the reply accepted, but `recv`
returned -1. Measured under a signal every 100 µs, 1,000 datagrams per run:

| Under a signal every 100 µs | Runs | Lost | Duplicates | Sends failing `EINTR` | Interrupted receives |
|---|---|---|---|---|---|
| udpchains, step 4 (D-51 as built) | 25 | 2, in 2 runs | — | — | — |
| prototype, user notification (D-51's order) | 200 | 6, in 6 runs | 12,839 | 22,042 | 114,762 |
| prototype, `ptrace` (this decision) | 200 | **0** | **0** | **0** | 4,180 |

Further `ptrace` runs (`SA_RESTART`, a 1 ms and a 10 ms echo, a signal every 50 µs, 320 runs in
all, about 170,000 interrupted receives) lost nothing and sent nothing twice. A prototype that
dropped every 100th datagram on purpose was caught (10 lost per run). The same race reaches sends:
an interrupted send whose datagram has left returns `EINTR`, which a native UDP send never does,
and is then sent again. It reaches `bind` and `connect` too, which the supervisor performs itself:
a bind that succeeded can report `EINTR`, and the program's retry then fails with `EINVAL`.

It reaches `close`, which the supervisor lets continue in the kernel: when the reply is
discarded, the call reports `EINTR` without having run. Linux closes a descriptor even when
`close` reports `EINTR`, so programs do not close it again, and it stays open, with its socket and
association. Measured with 200,000 `close` calls on UDP sockets under a signal every 100 µs,
without `SA_RESTART`:

| `close` on a UDP socket | Failed with `EINTR` | Descriptor still open after it |
|---|---|---|
| native | 0 | 0 |
| udpchains, step 3 (user notification) | 7,122 | **7,122** |
| prototype, `ptrace` (this decision) | 0 | 0 |

With `SA_RESTART`, all three closed every descriptor: the interrupted call restarts and runs.

**Decision.** Every call the filter selects is traced; user notification is kept only to install
a descriptor, which nothing else can do. (As first decided, only calls on the range were traced;
the amendment below moved the rest.)

- **Every call the filter selects returns `SECCOMP_RET_TRACE`.** The thread then stops, and the
  supervisor, attached as its tracer, handles the call while it cannot run. A signal sent
  meanwhile is only queued: the call returns what the supervisor set, or runs as the program made
  it, and the signal is delivered after it (`ptrace(2)`). These are:
  - on a descriptor in the reserved range (D-50): the sends (`sendto`, `sendmsg`, `sendmmsg`,
    `write`, `writev`, `pwritev2`), the receives (`recvfrom`, `recvmsg`, `recvmmsg`, `read`,
    `readv`, `preadv2`), `bind`, `connect`, `getsockname`, `getpeername`, `close` and `dup`;
  - on any descriptor: `connect`, `sendto`, `sendmsg` and `sendmmsg` below the range, checked and
    then run natively or refused (D-50); `sendfile`, `splice`, `io_uring_setup` and `pidfd_getfd`
    (D-53);
  - `socket()` for the families the supervisor must see, `dup2` and `dup3` to or from the range,
    `close_range` reaching it, and `fcntl(F_DUPFD*)`.
- **Installing a descriptor uses user notification** (D-48): a UDP `socket()`, and a `dup` or
  `F_DUPFD` of a carried socket, must put one at a chosen number in the range. Only
  `SECCOMP_IOCTL_NOTIF_ADDFD` can; `ptrace` could only by injecting system calls into the program.
  At such a call's stop, the supervisor:
  1. blocks every signal in the thread (`PTRACE_SETSIGMASK`, Linux 3.11), so none can interrupt
     the notification;
  2. marks the call in its sixth argument, which `socket()`, `dup()` and `fcntl()` do not use. On
     the re-check Linux makes after the stop (`seccomp(2)`), the filter sends a marked call by
     notification;
  3. answers it with `ADDFD` and `SEND`, installing the descriptor and answering in one step;
  4. puts the thread's mask back at the call's exit stop.

  A signal that arrived before the mask was set can still end the notification before it is
  answered, as can `SIGSTOP`, which cannot be blocked. Nothing has been installed then, and the
  call is made again once the signal is handled, as `socket()` natively never fails with `EINTR`.
  A program marking a call itself gains nothing: it is answered the same way, only without its
  signals blocked.
- **`fcntl` is trapped only for `F_DUPFD` and `F_DUPFD_CLOEXEC`.** Step 3's filter traps every
  `fcntl` on a descriptor in the range and lets the other commands through unchanged, which only
  adds the chance of an `EINTR` that `F_GETFD` and its like never give natively. Measured: 1,530
  under the same storm.
- **A send** is performed at its stop, from the supervisor's copy of the socket. The call is then
  skipped, and returns what the send returned. If the association must first be set up and a
  signal becomes pending during the proxy handshake, the setup is abandoned and nothing is sent.
  The call is made again once the signal has been handled, as under `SA_RESTART`, so the signal
  takes effect at once rather than after `connect_timeout`. The same holds for a receive that
  sets up its association.
- **A receive** with a datagram queued, or that must not wait (`O_NONBLOCK`, `MSG_DONTWAIT`), is
  answered at its stop and skipped. Otherwise the program waits in its own kernel, natively:
  - The supervisor rewrites the call as a zero-length `recvfrom` with `MSG_PEEK | MSG_TRUNC`, on
    the same descriptor. That blocks until a datagram is queued, honours `SO_RCVTIMEO`, `EINTR`
    and `SA_RESTART` as a receive does, and consumes nothing. Linux checks a rewritten call against
    the filter again (since 4.8, `seccomp(2)`). This one, on the same descriptor in the range, is
    traced again, and then runs.
  - When it returns, the thread stops again. The supervisor first puts back the program's
    registers, call number included, since the program keeps its arguments across a call.
  - If a datagram was queued, the supervisor takes it from its copy, checks and strips its
    headers (D-41), writes the payload and real sender into the program, and sets the return
    value, all while the thread is stopped. `recvmmsg` gets as many as are queued, up to its
    `vlen`, without waiting for more. A program's own `MSG_PEEK` is delivered without
    consuming.
  - If another reader took the datagram first, the call is made again, to wait for the next one.
  - Otherwise the peek's own result stands: `EAGAIN` at `SO_RCVTIMEO`, `EINTR`, or a restart the
    kernel makes of the program's own call.
- **`bind` and `connect`** are performed at the stop, on the supervisor's copy, as now, and skipped.
  **`getsockname` and `getpeername`** are answered at the stop (FR-I-05). **`close`** is noted for a
  sweep (D-50) and runs natively.
- **Attaching.** The child waits until the supervisor has attached with `PTRACE_SEIZE`, before it
  installs the filter and runs the program. The options are:
  - `PTRACE_O_TRACESECCOMP` and `PTRACE_O_TRACESYSGOOD`, to see trapped calls and their returns;
  - `PTRACE_O_TRACECLONE`, `_TRACEFORK`, `_TRACEVFORK` and `_TRACEEXEC`, so every new thread and
    process is attached before it runs;
  - `PTRACE_O_EXITKILL`.

  The program's own signals are handed back to it at each signal stop. A group stop is held with
  `PTRACE_LISTEN`, so `SIGSTOP`, Ctrl-Z and `SIGCONT` behave as they do unsupervised.
- **Fail-closed, twice over** (FR-SV-13), which answers D-48's reason for rejecting `ptrace`. A
  traced call with no tracer attached is not executed and fails with `ENOSYS` (`seccomp(2)`;
  checked on this host). And with `PTRACE_O_EXITKILL`, every traced process is killed if the
  supervisor dies (checked: killing the prototype's tracer mid-run took the program with it).
  The program never continues untraced.
- **The floor stays Linux 5.14** (D-53): `PTRACE_SEIZE` and `PTRACE_LISTEN` date from 3.4,
  `PTRACE_O_EXITKILL` from 3.8, and the re-check of a rewritten call from 4.8. No new refusal is
  added for Yama: D-53 already refuses to start above `ptrace_scope` 1. A container whose seccomp
  profile denies `ptrace` makes the mode refuse to start (FR-SV-02).

**What this changes in D-51.** Peek, deliver, commit and parked receives are no longer needed, and
neither is carrying an `SO_RCVTIMEO` deadline across restarts (step 4's fix): the kernel waits,
times out and restarts the program's own call. D-51's limitations are lifted:

- `recvmmsg` is no longer limited to one datagram per call (FR-SV-07's "MAY").
- An interrupted receive no longer leaves a payload in the program's buffer.
- A socket also read by an unsupervised process loses nothing.

Receives are interrupted about as often as natively: in the prototype, 20 per run under `ptrace`,
against about 570 when every receive waited on the supervisor.

**What this changes in D-48.** User notification remains only the way a descriptor is installed.
D-48's step-3 limitation of repeated sends is removed. Its
limitation of association setup holding up other trapped calls remains: the supervisor is still
one thread.

**Rejected.**

- **Keeping D-51 and accepting the loss,** documented as a kernel race. Rare (about 1 in 10,000
  to 20,000 interrupted receives here), but the maintainer requires that none be lost.
- **Checking for a pending signal before each reply** (`/proc/<tid>/status`). It narrows the
  window, does not close it, and costs a read per receive.
- **`SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` for every call** (Linux 5.19). A call already taken by
  the supervisor could no longer be interrupted. A receive waiting there for a datagram would then
  wait through every signal but `SIGKILL`: the `alarm()` case D-51 rejected.
- **`ptrace` alone, for every call, installs included.** Placing a descriptor at a chosen number
  would need system calls injected into the stopped thread -- `socket()` run natively, then a
  `dup3()` into the range and a `close()` -- several stops each, with the socket briefly below the
  range where another thread could see it. `ADDFD` does it in one step, and with the thread's
  signals blocked it cannot be interrupted either.
- **The supervisor waiting while the thread is stopped,** instead of letting the program wait
  natively. Signals would wait with it: the `alarm()` case again.

**Known limitations.**

- **One tracer per process.** A supervised program cannot be debugged with `gdb` or traced with
  `strace` from inside the supervision. A supervised program that attaches to its children with
  `ptrace` (a debugger, `strace` itself, some crash reporters) gets `EPERM`. Running `udpchains`
  itself under `strace -f` makes the mode refuse to start, since its child is already traced.
  Accepted by the maintainer.
- **An install interrupted by `SIGSTOP`, or by a signal that came before its mask was set, is made
  again** once the signal is handled, never failing with `EINTR`: the program's handler runs
  before its `socket()` returns, where natively it might run after.
- **Cost.** A traced receive that waits costs two stops, and a send or an answered receive one.
  Each stop is a switch to the supervisor and back, with the registers read and written. In the
  prototype, without signals, a send and receive round trip took about 49 µs, against 54–86 µs
  through user notification and 9 µs natively. Measured in udpchains (FR-SV-15), a round trip
  through the fixture proxy takes 67–85 µs at the median supervised, against 44–68 µs under the
  shim and 7.5 µs directly; at the 99th percentile, up to about 700 µs.
- **Non-dumpable processes** (D-48) are unchanged. Being a process's tracer does not keep the
  supervisor's access once it makes itself non-dumpable: checked, its sends and receives on a
  socket placed before then fail with `EPERM`, with D-48's diagnostic.
- **An abandoned setup is made again, never reported.** A program that relies on a signal to get
  `EINTR` out of a send, while the proxy hangs in the handshake, has the send made again instead.
  A native UDP send never waits for a proxy, so programs have no reason to do this.
- **A blocking `recvmmsg` without `MSG_WAITFORONE`** returns the datagrams already queued, at least
  one, where a native socket waits until `vlen` have arrived. `recvmmsg` may always return fewer
  than asked.
- **A program built with LeakSanitizer** cannot run its leak check under supervision: it stops its
  own threads with `ptrace`, and it reports a fatal error at exit. AddressSanitizer itself works.
- **aarch64** (FR-SV-16) reads and rewrites registers differently (`PTRACE_GETREGSET`, with
  `NT_ARM_SYSTEM_CALL` to change or skip a call). It is to be done in step 6.

**Built in step 4** (2026-10-23), as decided, in `svtrace.c`. The parked receives, and step 4's
carrying of `SO_RCVTIMEO` deadlines across restarts, were removed. Measured in udpchains, under a
signal every 100 µs:

- **Receives:** 20 runs of the signal tests, 5,293 interrupted receives in the dense storm, none
  lost, and no send failed with `EINTR` or was repeated.
- **`close`:** 200,000 calls on UDP sockets, none failed with `EINTR`, and none left open (7,122
  under step 3).
- **`fcntl(F_GETFD)`:** never interrupted.
- **Abandoning:** a signal during a hung handshake was handled after 302 ms, against a 1,000 ms
  `connect_timeout`, and `SIGTERM` then ended the program at once.

`SO_RCVTIMEO` now behaves exactly as signal(7) describes for a native socket:
- an interrupted receive on a socket with a timeout fails with `EINTR` even under `SA_RESTART`;
- it also does after `SIGSTOP` and `SIGCONT`, where a socket without one restarts.

**Amended in step 5** (2026-10-23), by the maintainer, to keep signals from breaking calls as far
as possible. The calls left on user notification could fail with `EINTR` when a signal arrived
while the supervisor held them. That is often, with threads: the supervisor, busy with other
threads' stops, takes longer to answer. And `close_range`, which the supervisor only let continue,
reported `EINTR` without having run, leaving descriptors open, as `close` did before. In 20,000
iterations with 4 threads under a signal every 100 µs, before the amendment:
- `socket()` failed with `EINTR` 252 times;
- `close_range()` failed 395 times, each leaving its descriptor open;
- a TCP send below the range failed 1,182 times in 20,000.

After it:

| Under a signal every 100 µs, no `SA_RESTART` | Before | After |
|---|---|---|
| UDP `socket()` failing with `EINTR` (2,000) | 98 | **0** |
| `fcntl(F_DUPFD)` of one failing with `EINTR` | 148 | **0** |
| `close_range()` failing with `EINTR`, and leaving it open | 43 | **0** |
| a TCP `send()` below the range failing with `EINTR` | 46 | **0** |
| descriptors left in the range | 0 | 0 |

A TCP send below the range costs much the same traced as notified: 17 to 29 µs, against 1.4 µs
natively. With the call not made again (a mutation), `socket()` and `F_DUPFD` failed with
`EINTR` again. With the signals not blocked, the tests still passed. The mask guards a window the
tests cannot show, a signal arriving after the supervisor has taken the call. Without it, the
step would rely on `ADDFD` with `SEND` being atomic under interruption, which has only been
measured, not documented.

**Revisit if:** Linux gains a way for a notification's reply to be committed to the program before
a signal can take effect. Every call could then return to user notification.

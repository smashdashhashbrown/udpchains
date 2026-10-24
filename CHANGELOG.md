# Changelog

All notable changes to `udpchains`. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); this project uses
[semantic versioning](https://semver.org/).

Design decisions referenced as **D-nn** are recorded in [`DECISIONS.md`](DECISIONS.md).
Requirement IDs (`FR-*`, `NFR-*`, `SEC-*`) are from
[`UDP-PRELOAD-REQUIREMENTS.md`](UDP-PRELOAD-REQUIREMENTS.md) and mapped in
[`docs/TRACEABILITY.md`](docs/TRACEABILITY.md).

## [Unreleased]

### Added

- **Supervisor mode** (D-48 to D-54), in progress, for static and Go binaries, which the shim
  cannot see. `udpchains --supervise` (or `supervise = yes`, or `UDPCHAINS_SUPERVISE=1`) runs the
  program under a seccomp filter whose calls udpchains answers, instead of preloading the shim.
  - **So far** (steps 2 to 5 of `docs/FUTURE-STATIC-BINARIES.md`): a static program's UDP is
    carried through the proxy or chain. The supervisor makes each UDP socket in a reserved range
    of descriptors (768 and up) and performs its sends and receives there: headers added and
    checked, the true sender reported, blocking and non-blocking receives, `SO_RCVTIMEO`,
    interruption by a signal, the `dup` family, `connect`, `bind` and the name calls. The program
    is never given the shim; its exit status and the signals sent to `udpchains` are passed on;
    descendants it leaves running are waited for and stay supervised. x86-64 and Linux 5.14 or
    later only.
  - **Signals** (step 4, D-54): calls on the program's UDP sockets are carried while its thread is
    stopped by `ptrace`, so a signal never loses a received datagram, never makes a send fail
    with `EINTR` or go twice, and never leaves a `close` undone. A receive with nothing queued
    waits in the program's own kernel, so `SO_RCVTIMEO`, `EINTR` and `SA_RESTART` behave exactly
    as natively. A signal arriving while an association is set up is handled at once. If
    `udpchains` is killed, so is the program.
  - **Threads, `fork`, `vfork`, `clone` and `exec`** (step 5): followed and tested. A thread with
    a descriptor table of its own is reached through a thread pidfd (Linux 6.9), and the sweep
    for closed sockets reads its table too; an `exec` prompts a sweep. Fixed: a traced program
    whose threads exited before it could leave `udpchains` waiting for ever.
  - **Every supervised call is now handled while its thread is stopped** (D-54, amended): the
    checks below the range, `close_range` and the refusals too. Notification is kept only to
    install a descriptor, with the thread's signals blocked meanwhile. So `socket()`, `dup`,
    `close_range` and TCP sends no longer fail with `EINTR` under signals, and an interrupted
    `close_range` no longer leaves descriptors open.
  - **Refused, as decided:** raw, packet, ICMP and UDP-Lite sockets; `io_uring_setup`;
    `pidfd_getfd`; sends, connects, `sendfile` and `splice` on a UDP socket received from another
    process; `dup2` of a carried socket below the range; and starting with an inherited UDP
    socket.
  - **Known limitations found while building it:**
    - a program that makes itself non-dumpable (`ssh-agent`, `gpg-agent`) is refused its connects
      and sends, TCP included, with a diagnostic naming the cause;
    - setting up an association holds up the program's other trapped calls;
    - a blocking `recvmmsg` returns the datagrams already queued rather than waiting for all;
    - the program is traced, so it cannot be debugged with `gdb` or `strace` from inside, and
      `udpchains` refuses to start under `strace -f`;
    - a program built with LeakSanitizer cannot run its leak check;
    - before Linux 6.9, a thread with a descriptor table of its own is refused its UDP calls.
  - **Name lookups** (step 6, D-52): the program's own resolver runs. Queries to the system
    resolver (a loopback address, or a nameserver in `/etc/resolv.conf`, re-read when it changes)
    go through the proxy to `dns`, and their replies are reported from the address asked. Port 53
    elsewhere is proxied as addressed.
  - **DNS over TCP** (D-52): a TCP connection to the system resolver's port 53, as resolvers make
    after a truncated answer, goes to `dns` too, by SOCKS5 `CONNECT` through the proxy or chain,
    on the program's own socket, which the program then uses natively. Large answers and `options
    use-vc` now resolve; before, the connection was refused.
  - **Tested** with a static Go client, through the seven interop proxies, and in `make compare`,
    where supervisor mode carried every combination and the static Go binary through the proxy.
  - **Documented** in the README, the man page and `udpchains -h`, with the limits of each mode.
  - **Not yet:** aarch64. Lookups through an NSS module that asks a local daemon (`nss-resolve`,
    `nscd`, `mdns`) are not seen.

### Changed

- **Under supervision, `fcntl` is trapped only for `F_DUPFD` and `F_DUPFD_CLOEXEC`** (D-54). Every
  other command runs in the kernel, so `fcntl(F_GETFD)` and its like are never interrupted.
- The checks both front ends apply to a datagram (multicast and broadcast, `MSG_MORE`, GSO, the
  loopback guard, and a received datagram's headers) moved from the shim's `core.c`, `assoc.c`
  and `hooks.c` into `dgram.c`, unchanged, so the supervisor applies the same ones.

### Verification

- 2319 assertions across 26 groups. Supervisor mode adds `unit-supervise` (27), 6 to
  unit-config, `FR-SV-supervise` (59 checks, with static programs making 18, 6, 37, 25, 4, 24, 26,
  2, 4, 26, 4 and 5 assertions), the hook matrix built `-static` under the supervisor (108, and 108 more
  through two hops), and the fidelity test built `-static` under it (172). The supervisor also
  runs under ASan and UBSan, with the static matrix and fidelity tests.

## [0.2.0] — 2026-10-21

Multi-hop chains, a proxychains.conf read as it is, and the routes around the hooks closed.

### Added

- **Multi-hop chains** (D-37 to D-47): up to 8 SOCKS5 proxies in a strict chain. A single proxy
  behaves exactly as before.
  - **Configuration:** `[hop]` sections in a config file, repeated `-p`, a comma-separated
    `UDPCHAINS_PROXY`, and credentials per hop, passed on by location like hop 1's (D-38).
  - **Setup:** each hop is reached by `CONNECT` through the hops before it and negotiated with
    its own credentials, later hops by the address as written (D-39). Each hop's relay is fixed
    up as D-40 says, `localhost` counting as loopback. Later hops are declared the unspecified
    address in the family they see (D-44). A failure at any hop fails the whole chain and names
    the hop, once a second (D-37, D-43). Setup must finish within `chain_timeout`
    (`UDPCHAINS_CHAIN_TIMEOUT`), by default `connect_timeout` per hop of a chain of more than one;
    set, it applies to a single proxy too, and 0 means no limit (D-45).
  - **Datagrams:** each carries one header per hop, still without copying the payload, and every
    layer of a reply is checked before any of it is delivered (D-41). The association holds a
    control connection per hop; losing any one loses the association, and a forked child closes
    all of them. The loopback guard considers the chain's last hop (D-40).
  - **Name lookups** go through the chain, UDP queries and the TCP fallback alike (FR-CH-11).
  - **Descriptors:** when the shim's protected range fills, as a long chain can make it, its
    connection stays where it is, still protected, and a warning says so (D-46). At a low number
    it can make a program's `dup2` onto that number fail with `EBUSY`; the warning names it.
  - **proxychains.conf:** `udpchains -f proxychains.conf` reads one as it is, for its strict
    chain of `socks5` hops, inline logins included. `strict_chain` is accepted; the other chain
    modes and `socks4`, `http` and `raw` proxies are errors naming the line; `quiet_mode` and
    `tcp_connect_time_out` are applied; the other directives, such as `proxy_dns` and
    `localnet`, are named in a warning and not applied (D-47, FR-CH-14).
  - **Real proxies:** `make interop` also runs chains of the seven proxies it tests. Each works
    as a middle hop and as the exit hop, and all seven work as one chain. The largest datagram
    through a chain is each hop's own limit less 10 bytes per IPv4 header it carries for the hops
    after it, as measured (FR-CH-T4).
  - **Documented** in the README's new *Chains* section, the man page, `udpchains -h` and
    `docs/DESIGN.md` §12.

### Changed

- **Raw and packet sockets are refused** with `EPERM` and a diagnostic: `SOCK_RAW` and
  `SOCK_PACKET` in `AF_INET`/`AF_INET6`, and any `AF_PACKET` socket. One inherited, received or
  copied is closed. A privileged program that opens one now fails to (D-36, superseding D-18).
- **`MSG_MORE` and a `UDP_SEGMENT` control message are refused** with `EOPNOTSUPP`, rather than
  corrupting the datagram (D-36).
- **`fdopen`, `sendfile` and `splice` are refused on a UDP socket** with `EINVAL` (D-36).

### Fixed

- **Sends that could reach the destination directly** with the proxy down (D-36). With the proxy
  stopped, 11 of the leak client's 27 sends got through; now none do.
  - `syscall()` with a socket, send or receive number went straight to the kernel. It is now routed
    to the hook.
  - `dprintf`, `vdprintf` and their fortified forms, and `pwritev2`/`preadv2` at offset −1, wrote
    without a hook. They are now proxied.
  - glibc's public aliases `__write`, `__read`, `__send`, `__connect`, `__close`, `__dup2` and
    `__fcntl` bypassed the hooks. They are now hooked.
  - A socket copied with `pidfd_getfd` was untracked. It is now adopted.
  - `sendfile`, `splice` and stdio sent directly on a socket connected outside the `connect()` hook.
    They are now refused.

### Verification

- 1839 assertions across 21 groups, plus a 91-check symbol gate. TST-05 has 55 new assertions, the
  leak client tries 13 more routes, and the leak test checks the raw-socket refusal. The chain
  configuration adds 89 to unit-config and 5 to the wrapper tests, and chain setup has a new
  group, unit-chain, with 135, against chained fixture proxies. The integration tests run again
  through 2- and 3-hop fixture chains, 378 assertions each, and Valgrind and Helgrind run through
  2 hops. Name lookups are tested through 2 hops (13 more resolver checks), the leak test runs
  with each hop of a 3-hop chain dead in turn (12 more), and the fault tests add the chain's
  faults and a full descriptor range (26 more). Reading a proxychains.conf adds 83 to unit-config
  and 5 to the authentication test. Clean under ASan/UBSan, ThreadSanitizer, Valgrind and Helgrind.
  On the wire, as root, the capture script saw no datagram and no lookup leave with each hop of a
  3-hop chain dead in turn.
- `make interop` adds 70 results for chains of the seven real proxies, all as expected: a 2-hop
  chain with each proxy as the middle hop and as the exit hop, all seven in one
  chain, and authentication at two hops (`docs/INTEROP-CHECKLIST.md` §13).

## [0.1.0] — 2026-10-20

First release.

### Added

- **UDP over SOCKS5.** An `LD_PRELOAD` shim that routes a dynamically-linked program's UDP
  traffic through a SOCKS5 proxy supporting `UDP ASSOCIATE` (RFC 1928 §7), without modifying or
  recompiling the program.
- **Fail-closed behaviour (SEC-01).** A datagram that cannot be proxied fails with an appropriate
  `errno`. There is no fallback to a direct send, and no bypass list (D-05) — which is what makes
  the leak test meaningful.
- **Every send and receive call interposed,** with every send variant funnelling into one send
  path and every receive variant into one receive path, including the fortified `__recv_chk`,
  `__recvfrom_chk` and `__read_chk` that `_FORTIFY_SOURCE` programs call. A 108-cell matrix
  asserts byte-identical round-trips across `{sendto, send, write, writev, sendmsg, sendmmsg}` ×
  `{recvfrom, recv, read, readv, recvmsg, recvmmsg}`, over IPv4 and IPv6, connected and
  unconnected.
- **Every route by which a UDP socket enters the process is tracked** (D-21): `socket`, the `dup`
  family, `fcntl(F_DUPFD)`, sockets received over `SCM_RIGHTS`, and sockets inherited across
  `exec`. Closes are tracked through `close`, `close_range`, `closefrom` and the lifecycle calls of
  `syscall()`. A socket the shim cannot track is closed and the call fails, rather than being let
  through. Each call confirms its descriptor by kernel socket cookie, so a number reused behind
  the shim's back is never mistaken for the socket it tracked (D-23).
- **Name resolution through the proxy** (D-22). glibc's resolver makes its socket calls through
  internal functions no preload can intercept, so the shim answers `getaddrinfo`, `getnameinfo`,
  `gethostby*` and the `res_*` query API itself: from numeric input, `localhost`, the hosts file,
  or a DNS query to the resolver named by `dns`, **sent through the proxy** — over UDP, and over
  TCP with SOCKS5 `CONNECT` when an answer is truncated. The host's resolver is never consulted.
  There is no default resolver: without `dns`, a lookup needing DNS fails.
- **No shadow socket.** The application's own descriptor is redirected at the relay, so `poll`,
  `select`, `epoll` and every socket option keep working untouched, and are deliberately not
  hooked (FR-I-07).
- **Lock-free per-descriptor state** in a two-level radix table (D-07). Once a socket's
  association is up, the datagram path takes no locks and allocates nothing; it makes one
  `getsockopt` per call to confirm the descriptor, which costs about 0.8 µs. Associations are type-stable and read through a
  counted reference, so threads sharing a socket never read freed memory (D-24).
- **Refusal to run unproxied.** No default proxy (D-10). Setuid, setgid and capability-endowed
  targets are refused, because the loader ignores `LD_PRELOAD` for them (SEC-06), and the file
  checked is the file run (D-28). An unloadable shim is refused before `exec` (D-19). ICMP "ping"
  and UDP-Lite sockets, which SOCKS5 cannot carry, are refused with `EPROTONOSUPPORT` (D-29).
- **SOCKS5 username/password authentication** (RFC 1929, D-20), offered only when credentials are
  configured. Credentials are never accepted on the command line (SEC-03), and never logged. The
  password is never put in the program's environment: `udpchains` passes on where it is, and the
  shim reads it from there (D-25).
- **Configuration resolved once,** by `udpchains`, and handed to the programs it runs, including
  the proxy's resolved address, so none of them looks the proxy up again (D-27).
- **Fork handling.** A child using an inherited socket gets a private one, bound again to the
  parent's address or port where possible (FR-L-04, D-34), and drops its copies of the parent's
  proxy connections (D-31).
- **Diagnostics** with a `udpchains:` prefix. `-q` means errors only, `-v` shows protocol steps and
  never payload. Repeated warnings are rate-limited, and nothing is written to a descriptor 2 that
  is no longer the original stderr (D-33).
- **Hardened build.** Only the hooks are exported. Built with `-fstack-protector-strong`, full
  RELRO, immediate binding, and `_FORTIFY_SOURCE=2` in optimised builds (D-35).
- `udpchains(1)` manual page, [`SECURITY.md`](SECURITY.md) and
  [`CONTRIBUTING.md`](CONTRIBUTING.md).

### Fixed before release

Found against a real proxy after the fixture suite was green. Each is the reason its decision
record exists.

- **D-14** — a v4-mapped IPv6 destination (`::ffff:a.b.c.d`) was emitted as `ATYP 0x04` rather
  than `ATYP 0x01`. A real proxy accepted the association and silently delivered nothing. The
  in-repo fixture decoded it and forgave it, so 108 green matrix cells said nothing.
- **D-15** — a connected socket accepted datagrams from any origin, where the kernel filters by
  the connected peer. The shim was *more* permissive than an unhooked socket.
- **D-16** — a loopback `BND.ADDR` from a remote proxy was taken literally, pointing the
  application's socket at the local loopback. Every datagram was silently discarded, and the
  resulting `ECONNREFUSED` was misread as an expired association, causing endless re-association.
- **D-17** — descriptors closed by a route that bypasses the interposed `close()` (dig closes
  through libuv; 4 of its 64 close syscalls reach the hook) stranded their table entries. The next
  socket on that descriptor number was refused with a spurious `EMFILE`, and the stranded entry
  leaked its control connection.
- **`recvmmsg`** applied `MSG_DONTWAIT` after the first message unconditionally; the kernel only
  does that for `MSG_WAITFORONE`.
- **`fork()`** — parent and child share one open file description, so a child re-pointing its
  socket also re-pointed the parent's. The child now gets a private socket (FR-L-04).
- **A race on the entry `family`/`type` fields**, found by ThreadSanitizer.
- **A proxy that was not listening was reported as `ECONNRESET`,** not the `ECONNREFUSED` the
  connect returned. The poll that waits for the connect saw `POLLERR` and reported a reset
  without reading `SO_ERROR`. Found by the seven-proxy runs (INTEROP-CHECKLIST.md §12).

Found in a pre-release review, tracked in [`docs/REVIEW-BACKLOG.md`](docs/REVIEW-BACKLOG.md). Each
was reproduced before it was fixed, and each fix has a test that fails without it.

- **Sockets that escaped the shim (D-21).** `fcntl(F_DUPFD)` duplicates, sockets received over
  `SCM_RIGHTS`, and inherited sockets without `/proc` were untracked and sent directly with the
  proxy down. A failed `dup2` untracked a live socket. The fortified receive calls delivered the
  SOCKS header as payload.
- **Name lookups went directly to the host's resolver (D-22),** whatever the proxy was doing.
- **A stale fd-table entry took over whatever reused its number (D-23).** A socket closed by a
  route no hook saw left its entry behind, and the next file, pipe or TCP socket given that number
  was treated as UDP: a TCP `connect()` was swallowed and its peer waited forever.
- **A use-after-free when threads share a socket (D-24),** when one of them saw the association
  expire.
- **The password was exported into the program's environment (D-25).**
- **The program could close the shim's own descriptors (D-26),** after which the shim polled, and
  eventually closed, whatever the program had put at that number. `close_range(3, ~0U)` walked a
  million table entries.
- **The shim re-read the default config files behind the wrapper's back (D-27),** and each
  exec'd program looked the proxy's name up again, directly.
- **The setuid check and the exec could look at different files (D-28).**
- **ICMP and UDP-Lite sockets were treated as UDP (D-29).**
- **Forked children kept the parent's associations alive at the proxy (D-31),** and a child could
  wait forever on an association a parent thread had been setting up.
- **A forked child's datagrams were dropped by a proxy honouring the declared address (D-34).**
- **Warnings were written into whatever took over descriptor 2, repeated once per datagram, and
  printed under `-q` (D-33).**
- **Argument handling.** A short address was read past rather than refused with `EINVAL`, a `NULL`
  `msg_iov` crashed, `msg_iovlen` was truncated to `int`, and exactly `IOV_MAX` buffers failed.
- **Configuration.** A password file over 255 bytes was silently truncated, `\r\n` was not
  stripped, `UDPCHAINS_QUIET=0` meant quiet, an indented overlong line was not caught, and an
  inline `# comment` became part of the value. The last is now an error.
- **Internal functions were exported, and the library was built without hardening (D-35).**
- **A fd-table generation counter** documented as a guard against descriptor reuse was never
  checked, and has been removed (D-30).

### Known limitations

Documented in full in the README's *Security considerations* and *What does not work*.

- **Security.** RFC 1929 credentials cross the network in cleartext, and datagrams to and from
  the proxy's relay are neither authenticated nor encrypted.
- **Raw sockets are not intercepted** (D-18). A program using `SOCK_RAW` reaches the network
  directly, with no diagnostic. Raw sockets require `CAP_NET_RAW`. Refusing them is the v2 change.
- **Some sends bypass the shim** (D-21): `io_uring`, `sendfile` and `splice` onto a UDP socket,
  and stdio on one (`fdopen`), send directly, with no diagnostic, on a socket not yet used
  through the shim. A socket copied from another process with `pidfd_getfd` is never tracked, so
  every send on it goes directly.
- **LSM denials may still leak** (D-19). The pre-`exec` loadability probe runs in the wrapper's
  security domain; if the target transitions to a confined domain on `exec`, the probe can pass
  while the target is denied and runs unproxied.
- **Tested against real proxies on the same host only.** Interop was checked against the
  reference SOCKS5 proxy with `nc -u`, TFTP (10 MB), `dig`, `iperf -u` and `ntpdate -q`. It was
  also checked against Dante 1.4.3, 3proxy 1.0.1, gost 3.3.1, Xray 26.3.27, sing-box 1.14.3,
  hev-socks5-server 2.13.1 and shadowsocks-rust 1.25.0. These runs covered the hook matrix,
  `ATYP 0x04` to `::1`, name resolution and its `CONNECT` fallback, authentication, idle expiry and
  a proxy killed mid-stream. A proxy on another host, and a global IPv6 destination, are untested.
  See [`docs/INTEROP-CHECKLIST.md`](docs/INTEROP-CHECKLIST.md) §12.
- **Some proxies silently truncate datagrams below the default `max_datagram`:**
  hev-socks5-server above 1 490 bytes, gost above 4 086 at its default buffer size, and Xray
  above 8 182. Set `max_datagram` to the proxy's limit. 3proxy, Xray, hev-socks5-server and
  shadowsocks-rust drop zero-length datagrams. Dante is port-restricted unless
  `udp.connectdst: no` is set.
- Cannot help statically-linked binaries, Go binaries, or programs issuing raw syscalls. UDP
  servers do not work through a proxy.
- `MSG_MORE`, `UDP_CORK`, GSO and GRO corrupt data rather than failing. The first send or receive
  blocks during the proxy handshake, even on a non-blocking socket. `strict_loopback` is checked
  only at association setup. A socket shared with another process is re-pointed for both (D-32).
- Sending from a signal handler is safe only on a socket already in use: a socket's first send, a
  thread's first datagram, and `socket()`, `dup()` and `close()` allocate or free memory (NFR-03 is
  partial).
- A proxy given by hostname is reached at its first address only (D-35). A forked child cannot
  keep a port its parent still holds (D-34). A non-`NULL` invalid pointer inside a message faults
  in the shim instead of returning `EFAULT`.
- **Name resolution** consults only the hosts file and DNS: mDNS, `systemd-resolved` and
  `myhostname` are skipped. Address order is simpler than glibc's RFC 6724 sort. Non-ASCII names
  and `getaddrinfo_a` are refused.
- SOCKS5 **GSSAPI** authentication (method `0x01`) is not implemented; a proxy selecting it is
  refused with a diagnostic naming what is supported.
- TCP is not proxied, except the shim's own DNS fallback. Multicast and broadcast fail with
  `ENETUNREACH`. Ancillary data (`msg_control`) is returned empty.
- A loopback destination is resolved *at the proxy*, so with a remote proxy it reaches the proxy
  host's loopback (D-05 R2). A warning is issued; `strict_loopback` makes it an error.

### Verification

- 656 assertions across 17 groups, plus a 71-check exported-symbol and hardening gate. Clean
  under ASan/UBSan, ThreadSanitizer, Valgrind memcheck and Helgrind.
- **`make interop`** runs the integration tests against seven real SOCKS5 proxies in Docker,
  pinned by digest, and checks each one's known behaviour (INTEROP-CHECKLIST.md §12). It is
  opt-in, since it needs Docker and downloads images.
- **`make compare`** runs the README's comparison with Dante `socksify`, proxychains-ng PR #570,
  Proxando and graftcp in a Docker lab, judging each datagram by where the server saw it arrive
  from. Also opt-in.
- Every fix from the pre-release review has a test that fails, hangs or crashes against the code
  before it.
- **Fail-closed on the wire.** `tests/test_failclosed_capture.sh`, run as root, captures with
  `tcpdump`: with the proxy absent, `UDP ASSOCIATE` refused, or the shim unconfigured, zero
  packets reach the destination, against a positive control that proves the capture works. Name
  lookups are checked the same way: none asks for the looked-up name with the proxy down or no
  `dns` set.
- **Independent of the shim's own account,** the resolver tests count what reached the fixture
  resolver, and check with `strace` that the process never addressed a resolver directly.
- NFR-04: about 50 µs added median per datagram (direct 17.7 µs → proxied 67.6 µs), measured as
  the delta between the same binary run with and without the shim. Inside the 100 µs budget, and
  an upper bound since the proxy hop is not separable.

[0.2.0]: https://github.com/smashdashhashbrown/udpchains/releases/tag/v0.2.0
[0.1.0]: https://github.com/smashdashhashbrown/udpchains/releases/tag/v0.1.0

# Changelog

All notable changes to `udpchains`. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); this project uses
[semantic versioning](https://semver.org/).

Design decisions referenced as **D-nn** are recorded in [`DECISIONS.md`](DECISIONS.md).
Requirement IDs (`FR-*`, `NFR-*`, `SEC-*`) are from
[`UDP-PRELOAD-REQUIREMENTS.md`](UDP-PRELOAD-REQUIREMENTS.md) and mapped in
[`docs/TRACEABILITY.md`](docs/TRACEABILITY.md).

## [0.1.0] — 2026-09-24

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

[0.1.0]: https://github.com/smashdashhashbrown/udpchains/releases/tag/v0.1.0

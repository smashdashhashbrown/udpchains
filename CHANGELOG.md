# Changelog

All notable changes to `udpchains`. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); this project uses
[semantic versioning](https://semver.org/).

Design decisions referenced as **D-nn** are recorded in [`DECISIONS.md`](DECISIONS.md).
Requirement IDs (`FR-*`, `NFR-*`, `SEC-*`) are from
[`UDP-PRELOAD-REQUIREMENTS.md`](UDP-PRELOAD-REQUIREMENTS.md) and mapped in
[`docs/TRACEABILITY.md`](docs/TRACEABILITY.md).

## [Unreleased]

### Security

- **Name lookups went directly to the host's resolver (D-22).** glibc's resolver has lived
  inside libc since 2.34 — this project's minimum — and makes its socket calls through internal
  functions no preload can intercept. With the proxy down, `getaddrinfo()` still resolved, and the
  query went straight to `127.0.0.53`. The README's "No DNS leak" claim was false for every
  program resolving names through libc. The shim now answers `getaddrinfo`, `getnameinfo`,
  `gethostby*` and the `res_*` query API itself: from numeric input, `localhost`, the hosts file,
  or a DNS query **sent through the proxy** — over UDP, and over TCP with SOCKS5 `CONNECT` when
  an answer is truncated. The host's resolver is never consulted; if the proxy route fails, the
  lookup fails.

- **The password was exported into the target's environment (D-25).** The wrapper resolved a
  password file, or `password =` in a config file, and exported the secret as `UDPCHAINS_PASSWORD`,
  where every process the target started inherited it, and anything that dumped the environment
  printed it. The wrapper now exports only where the password is (`UDPCHAINS_PASSWORD_FILE`, or
  `UDPCHAINS_PASSWORD_CONFIG` naming the config file, both absolute), and each shim reads it from
  there.

- **Processes under the shim looked up the proxy's name directly (D-27).** The wrapper exported the
  proxy as written, so a hostname was resolved again, unproxied, in every process the program
  started. It is now exported as the address the wrapper resolved.
- **The wrapper could check one file and run another (D-28).** The setuid/capability check inspected
  the file found on `PATH`, then `execvp()` searched `PATH` again. The checked file is now the one
  executed.
- **The library exported its internals, and was built without hardening (D-35).** Every internal
  `udpc_*` function was an exported symbol, so a program defining a function of the same name
  could replace a piece of the shim. Only the hooks are exported now. The library is built with
  `-fstack-protector-strong`, full RELRO and immediate binding, and `_FORTIFY_SOURCE=2` in
  optimised builds.

### Added

- `dns` / `UDPCHAINS_DNS`: the resolver to query through the proxy, numeric only. **No default:**
  without it, a lookup needing DNS fails with `EAI_FAIL` and one diagnostic. Also
  `dns_timeout`, `dns_search` (search domains, opt-in — `/etc/resolv.conf` is not read) and
  `hosts_file`.
- SOCKS5 `CONNECT`, used only for the resolver's TCP fallback. Application TCP is still not
  proxied.

### Changed

- **Non-UDP datagram sockets are refused (D-29).** An ICMP "ping" socket or a UDP-Lite socket was
  taken for UDP and sent to the proxy's relay wrapped in SOCKS headers. Creating one now fails with
  `EPROTONOSUPPORT` and a diagnostic, and an inherited or received one is closed. `ping` fails
  under the shim rather than misbehaving.
- Each intercepted call makes one `getsockopt`, to confirm its descriptor (D-23). That costs about
  0.8 µs per call: a `send()` in a tight loop went from 5.1 to 5.9 µs, averaged over six
  alternating runs, which is essentially the `getsockopt` itself. The effect on a round trip
  through the proxy is a few microseconds at most, inside run-to-run noise.
- The program cannot close the shim's descriptors: `close()` on one is `EBADF`, and `dup2()` onto
  one is `EBUSY` (D-26).
- Name services other than the hosts file and DNS (mDNS, `systemd-resolved`, `myhostname`) are no
  longer consulted by proxied programs, since each resolves through a local daemon. Address order
  no longer follows glibc's RFC 6724 sort. Non-ASCII names and `getaddrinfo_a` are refused.
  See the README's *Name resolution* section.
- **`-q` means errors only, as documented (D-33).** It previously still printed warnings.
  `UDPCHAINS_QUIET` and `UDPCHAINS_DEBUG` now take a boolean, so `UDPCHAINS_QUIET=0` is no longer
  quiet, and a value that is not a boolean is an error.
- **Repeated warnings are rate-limited (D-33).** A warning that fired per datagram (a refused
  multicast or broadcast send, an oversized inbound datagram) now prints at most once a second,
  with a count of those held back.
- **A readable password file is warned about once,** by `udpchains`, not again by the program it
  runs. A config file holding `password =` that other users can read is now warned about too.

### Fixed

- **A stale fd-table entry took over whatever reused its number (D-23).** A UDP socket closed by
  a route no hook saw — libuv's `syscall(SYS_close)`, glibc's `closefrom()`, `fclose()` on an
  `fdopen()`ed socket — left its entry behind. The next file, pipe or TCP socket given that number
  was treated as UDP: writes failed, and a TCP `connect()` was swallowed so the peer waited
  forever. Each entry now records the socket's kernel cookie, and every intercepted call confirms
  it. `closefrom()` and the lifecycle calls of `syscall()` are now hooked, so those routes release
  at once.
- **A use-after-free when threads share a socket (D-24).** The datagram path read the association
  through a bare pointer, which another thread could free by noticing the proxy had expired it.
  Associations are now type-stable and read through a counted reference. A TSan test reports a
  heap use-after-free on the old code and nothing on the new.
- **The shim read the default config files behind the wrapper's back (D-27).** With `-f`, the
  credentials in `~/.udpchains.conf` were still used, and a broken home file made the shim report
  itself unconfigured after the wrapper had reported success. Launched by the wrapper, the shim now
  reads only the environment it was given.
- **Forked children kept the parent's associations alive at the proxy (D-31).** A child held copies
  of the parent's control connections until it exited, and a TCP connection closes only when its
  last holder does. The child now closes its copies at fork. A parent thread caught mid-way through
  setting up an association also no longer leaves the child's first send waiting forever.
- **The shim's own descriptors could be closed by the program (D-26).** A close-all loop,
  `close_range` or a `dup2` took a control connection away. The shim then polled, and on teardown
  *closed*, whatever the program had put at that number. Shim descriptors now live at 768 and up
  and are protected. `close_range(3, ~0U)` no longer walks a million table entries.
- **Warnings were written into whatever took over descriptor 2 (D-33).** A daemon that closes
  stderr and opens its log file gets descriptor 2 for it, and the shim's warnings landed in the
  log. The shim now checks descriptor 2 is still the stderr it started with.
- **A forked child's datagrams were dropped by a proxy honouring the declared address (D-34).**
  The child's private socket lost a wildcard-with-port binding, and a failed re-bind was ignored,
  so the child declared the parent's address while sending from another port. It now binds again
  in both cases, and when that fails it stops declaring the address and warns once.
- **Short addresses and oversized messages were read past or misreported.** `connect()` and
  `sendto()` copied a full address whatever length was passed, reading past a short buffer; they
  now fail with `EINVAL`, as the kernel does. A `NULL` `msg_iov` with a non-zero length crashed and
  is now `EFAULT`. `msg_iovlen` above `IOV_MAX` was truncated to `int` and is now `EMSGSIZE`.
  A send of exactly `IOV_MAX` buffers, which the header's extra buffer pushed over the kernel's
  limit, now works.
- **Password and config-file edge cases.** A password file over 255 bytes, the RFC 1929 limit, was
  silently truncated and is now an error. A Windows line ending (`\r\n`) is stripped. An overlong
  config line starting with whitespace was not detected.

Four ways an intercepted socket could escape the shim, all found in review after 1.0.0 and each
reproduced before being fixed. Two were SEC-01 violations — a datagram sent directly with the
proxy down — and one was the FR-I-02 defect the project exists to prevent. See **D-21**.

- **`fcntl(F_DUPFD)` duplicates sent directly.** `fcntl(F_DUPFD)` and `F_DUPFD_CLOEXEC` were not
  hooked, so a copy made that way was untracked and sent straight to its destination. Python's
  `socket.dup()` and `os.dup()` duplicate this way. `fcntl` and `fcntl64` are now hooked.
- **UDP sockets received over `SCM_RIGHTS` sent directly.** A descriptor passed from another
  process arrives as a new number that never went through `socket()`. `recvmsg` and `recvmmsg` now
  adopt any UDP socket in `SCM_RIGHTS` ancillary data before returning it.
- **A failed `dup2`/`dup3` untracked its target.** The target's entry was released before the call,
  so a call that failed (for example with `EBADF`) left the target open, still a UDP socket, and no
  longer tracked. The entry now changes only after the call succeeds. A duplicate that cannot be
  tracked is now closed and the call fails with `EMFILE`, as `socket()` already did; previously it
  was logged and left open.
- **Fortified receive calls delivered the SOCKS header.** A program built with `_FORTIFY_SOURCE`,
  the default for distribution packages, calls `__recvfrom_chk`, `__recv_chk` and `__read_chk`.
  glibc implements these with internal calls that bypass any preload, so the application got the
  10-byte SOCKS header as payload. They are now hooked and funnel into the one receive path.
- **Inherited sockets without `/proc`.** Adopting inherited descriptors silently gave up when
  `/proc/self/fd` could not be opened. The descriptor table is now probed instead. An inherited
  UDP socket that cannot be tracked is closed rather than left to send directly.

### Verification

- New assertions: the leak test's client now also sends through an `fcntl` duplicate, an
  `SCM_RIGHTS`-received socket, and a failed `dup2` target. Each of these reached the destination
  on 1.0.0; with the fix, none does. The fidelity test covers the three fortified receive calls.
  The lifecycle test checks that the new descriptors are actually *proxied* (by counting control
  connections), not merely delivered, because an untracked socket also round-trips — directly.
  The symbol gate now requires all five new hooks.
- Every new assertion fails against the 1.0.0 shim and passes against this one. Clean under
  ASan/UBSan, ThreadSanitizer, Valgrind memcheck and Helgrind.
- D-22: a DNS fixture (`tests/fixtures/dnsd.c`) with a truncating answer and a CNAME loop; `CONNECT`
  and `--no-connect` in the proxy fixture; codec unit tests against hostile input (compression
  loops, out-of-range pointers, overlong records, forged answers); an integration test of every
  hooked resolver entry point; and a leak-test scenario. Independent of the shim's own account,
  the tests count what reached the fixture resolver and check with `strace` that the process never
  addressed a resolver directly — against the previous shim, that check finds 10–13 direct
  port-53 sends. The resolver is clean under ASan/UBSan (codec), Valgrind memcheck and Helgrind
  (the association pool). The wire-level capture script gains a DNS case, **not yet run**: it
  needs root.
- H1–H4 (D-23–D-26). Each new test fails, or hangs, against the previous shim:
  - The lifecycle test covers a stale entry reused by a TCP socket, which hung; `syscall(SYS_close)`
    and `closefrom()` releasing at once; and a close-all loop, `close_range`, `close()` and `dup2()`
    against the shim's descriptors, including that teardown closes none of the program's.
  - The leak test sends through a socket created, and one duplicated, via `syscall()`; the old shim
    let both through with the proxy down.
  - The auth test checks, with `env` as the target, that no password reaches the environment, and
    that a relative password file survives a `chdir`.
  - The fd-table test races association readers against replacement under TSan: 15 warnings,
    including a heap use-after-free, on the old code; none on the new.
- M4–M9 (D-27–D-31):
  - The wrapper test checks a broken home config under `-f`, the numeric proxy export and the
    resolved-environment marker (the old code fails all three), and a script with no `#!` line.
  - The fidelity test checks that ICMP, ICMPv6 and UDP-Lite datagram sockets are refused while
    explicit `IPPROTO_UDP` still works; the old shim accepted all three.
  - The lifecycle test checks that a forked child holds no control connection; the old shim left
    it one.
- L1–L7 (D-33–D-35):
  - The fidelity test covers short addresses, a 24-byte IPv6 address, a `NULL` `msg_iov`, and
    `msg_iovlen` of `IOV_MAX + 1` and of a value that truncates to 1, then round-trips `IOV_MAX`
    one-byte buffers. The previous shim crashes.
  - The fault test forks a child from a bound socket under a proxy fixture enforcing the declared
    address (`--pin-declared`). The previous shim times out. It also checks that 50 refused
    multicast sends print one warning, that `-q` prints none, and that a file opened at descriptor 2
    receives nothing.
  - The auth test checks a readable password file is warned about once, and a readable config file
    holding a password is warned about.
  - The config unit test covers the password-file limit and `\r\n`, boolean `UDPCHAINS_QUIET`, and
    overlong lines.
  - The symbol gate checks that no `udpc_*` symbol is exported, and for RELRO, immediate binding
    and the stack protector.
- Suite: 644 assertions across 17 groups. Clean under ASan/UBSan, TSan, Valgrind memcheck and
  Helgrind.

### Documentation

- The limitations accepted for 1.0 are now in the README (D-32): `strict_loopback` is checked only
  at association setup; `MSG_MORE`, `UDP_CORK` and GSO/GRO corrupt data rather than failing; the
  first send blocks during the handshake, even on a non-blocking socket; and a socket shared with
  another process is re-pointed for both.
- NFR-03 (signal safety) is marked partial. The 1.0.0 claim below, that a send from a signal
  handler "cannot deadlock", holds only for a socket already in use; the README now says which
  calls allocate.
- The fd-table generation counter, described as a guard against descriptor reuse but never
  checked, is removed along with an unused flag (D-30). The docs now point at the per-call cookie
  check that does the job.

## [1.0.0] — 2026-08-20

First release.

### Added

- **UDP over SOCKS5.** An `LD_PRELOAD` shim that routes a dynamically-linked program's UDP
  traffic through a SOCKS5 proxy supporting `UDP ASSOCIATE` (RFC 1928 §7), without modifying or
  recompiling the program.
- **Fail-closed behaviour (SEC-01).** A datagram that cannot be proxied fails with an appropriate
  `errno`. There is no fallback to a direct send, and no bypass list (D-05) — which is what makes
  the leak test meaningful.
- **Twelve interposed calls**, with every send variant funnelling into one send path and every
  receive variant into one receive path. A 108-cell matrix asserts byte-identical round-trips
  across `{sendto, send, write, writev, sendmsg, sendmmsg}` × `{recvfrom, recv, read, readv,
  recvmsg, recvmmsg}`, IPv4 and IPv6, connected and unconnected.
- **No shadow socket.** The application's own descriptor is redirected at the relay, so `poll`,
  `select`, `epoll` and every socket option keep working untouched, and are deliberately not
  hooked (FR-I-07).
- **Lock-free per-descriptor state** in a two-level radix table: no allocation, no locks and no
  syscalls on the datagram path, so a send from a signal handler cannot deadlock (D-07, NFR-02,
  NFR-03).
- **Refusal to run unproxied.** No default proxy (D-10); setuid, setgid and capability-endowed
  targets are refused because the loader ignores `LD_PRELOAD` for them (SEC-06); and an
  unloadable shim is refused before `exec` (D-19).
- **SOCKS5 username/password authentication** (RFC 1929, FR-P-09), offered only when credentials
  are configured. Credentials are never accepted on the command line (SEC-03), and the password is
  never logged by either side (NFR-05). Wrong or absent credentials deliver nothing rather than
  falling through to a direct send.
- `udpchains(1)` manual page.

### Fixed during development

These were found against a real proxy after the fixture suite was green, and each is the reason
its decision record exists.

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
- **`run_sanitizers.sh`** passed one echo server where two were needed, so the D-15
  connected-peer assertions failed while the shim was behaving correctly.

### Known limitations

Documented in full in [`README.md`](README.md).

- **Raw sockets are not intercepted** (D-18). A program using `SOCK_RAW` reaches the network
  directly, with no diagnostic. This is a genuine gap in the no-bypass claim, bounded by the fact
  that raw sockets require `CAP_NET_RAW`. Refusing them is the v2 change.
- **LSM denials may still leak** (D-19). The pre-`exec` loadability probe runs in the wrapper's
  security domain; if the target transitions to a confined domain on `exec`, the probe can pass
  while the target is denied and runs unproxied.
- Cannot help statically-linked binaries, Go binaries, or programs issuing raw syscalls.
- SOCKS5 **GSSAPI** authentication (method `0x01`) is not implemented; a proxy selecting it is
  refused with a diagnostic naming what is supported. Username/password is implemented (D-20).
- TCP is not proxied. Multicast and broadcast fail with `ENETUNREACH`. Ancillary data
  (`msg_control`) is returned empty. GSO/GRO are unsupported.
- A loopback destination is resolved *at the proxy*, so with a remote proxy it reaches the proxy
  host's loopback (D-05 R2). A warning is issued; `strict_loopback` makes it an error.

### Verification

- 455 assertions across 15 groups, plus a 43-check exported-symbol build gate.
- Clean under ASan/UBSan, ThreadSanitizer, Valgrind memcheck and Helgrind.
- NFR-04: 42 µs added median per datagram (direct 32 µs → proxied 74 µs), measured as the delta
  between the same binary run with and without the shim. Inside the 100 µs budget, and an upper
  bound since the proxy hop is not separable.
- Interop confirmed against a real SOCKS5 proxy with `nc -u`, TFTP (10 MB), `dig`, `iperf -u` and
  `ntpdate -q`. See [`docs/INTEROP-CHECKLIST.md`](docs/INTEROP-CHECKLIST.md) for what each proves
  and what remains untested.

[1.0.0]: https://github.com/smashdashhashbrown/udpchains/releases/tag/v1.0.0

# Changelog

All notable changes to `udpchains`. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); this project uses
[semantic versioning](https://semver.org/).

Design decisions referenced as **D-nn** are recorded in [`DECISIONS.md`](DECISIONS.md).
Requirement IDs (`FR-*`, `NFR-*`, `SEC-*`) are from
[`UDP-PRELOAD-REQUIREMENTS.md`](UDP-PRELOAD-REQUIREMENTS.md) and mapped in
[`docs/TRACEABILITY.md`](docs/TRACEABILITY.md).

## [Unreleased]

### Fixed

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

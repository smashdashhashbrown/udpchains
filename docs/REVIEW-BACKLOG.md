# Release review backlog — `udpchains` 1.0.0

Open findings from the pre-release review of 2026-09-23, on branch `release_1.0.0_review`. Each item
keeps the ID it was given in the review so discussions and commits can refer to it.

**PoC** means the defect was reproduced with a test program; **inspection** means it was found by
reading the code. File and line references are to commit `a7ec506`.

Tick an item when its fix is committed, and cite the commit, for example `(a7ec506)`.

---

## Done

- [x] **C1** — `fcntl(F_DUPFD)` duplicates, `SCM_RIGHTS`-received sockets and inherited sockets
  without `/proc` were untracked and sent directly. (a7ec506, D-21)
- [x] **C2** — fortified `__recvfrom_chk` / `__recv_chk` / `__read_chk` delivered the SOCKS header
  as payload. (a7ec506, D-21)
- [x] **C3** — a failed `dup2`/`dup3` untracked a live socket; an untrackable duplicate was left
  open. (a7ec506, D-21)
- [x] **C4** — glibc's resolver leaked every libc name lookup to the host's resolver, since its
  internal calls bypass the hooks. Lookups are now answered locally or through the proxy, and fail
  closed otherwise. (98e715e, D-22; follow-ups under *Verification still owed* below)

## Critical

None open.

## High

- [ ] **H1 — stale fd-table entries take over unrelated descriptors.** *PoC.* D-17 recycles a stale
  entry only when a UDP `socket()` or a dup lands on its number. `open`, `pipe`, `accept`,
  `socketpair` and non-UDP `socket()` do not, so after a close that bypasses the hook (libuv's raw
  `close` syscall), a TCP socket, pipe or file on that number is treated as UDP. Demonstrated: a
  unix stream socket's `write()` failed with `EAGAIN`. A connected TCP socket would get SOCKS headers
  injected into its stream, and its reads would silently lose bytes. a7ec506 fixed the dup routes
  only.
  - **Implemented (D-23), awaiting commit.**
- [ ] **H2 — use-after-free when one socket is used from several threads.** *Inspection.*
  `udpc_assoc_relay`, `_touch`, `_revalidate` and `_ensure` read `e->assoc` and dereference it
  without taking a reference. `udpc_assoc_invalidate` on another thread can free it at the same
  time, for example when idle expiry is detected. See `src/assoc.c:70-150` and
  `src/core.c:140,266,281,356`. TST-07 never combines multiple threads with expiry.
  - **Implemented (D-24), awaiting commit.**
- [ ] **H3 — the password is exported in plaintext to the target and all its descendants.**
  `udpc_config_export` (`src/config.c:500`) turns `password_file` into
  `UDPCHAINS_PASSWORD=<secret>`. This defeats the reason for using a file.
  - **Implemented (D-25), awaiting commit.**
- [ ] **H4 — control-connection descriptors are unprotected in the app's descriptor space.** If
  the app closes one (close-all loops, `close_range`, `dup2` onto that number), the association
  keeps the stale number. `udpc_socks_disconnect` (`src/socks5.c:726`) later closes whatever the
  app has there, and the liveness probe polls the wrong descriptor. Usual fix: `F_DUPFD_CLOEXEC`
  to a high number.
  - **Implemented (D-26), awaiting commit.**

## Medium

- [ ] **M1 — `strict_loopback` can be bypassed.** The guard runs only at association setup, and
  only for connected sockets (`src/assoc.c:156`). An unconnected `sendto(127.0.0.1)`, a `connect()`
  after association, or a re-connect is never checked. Check per send in `udpc_core_send` instead.
- [ ] **M2 — `MSG_MORE` / `UDP_CORK` / GSO / GRO silently corrupt data.** *PoC.* Sending
  `AAA` + `BBB` with `MSG_MORE` delivers `AAA` + a 10-byte header + `BBB`. The README says such
  programs "fall back or fail". At minimum, reject `MSG_MORE` with `EOPNOTSUPP`.
- [ ] **M3 — the proxy handshake blocks, even on non-blocking sockets.** The first send or receive
  runs the full connect and handshake synchronously, with `connect_timeout` applied per step
  rather than overall. With the proxy down, every failed send makes two full attempts
  (`src/core.c:277`, where `ECONNREFUSED` counts as "looks dead").
- [ ] **M4 — the shim re-reads the default config files.** `udpc_config_load_shim` still reads
  `~/.udpchains.conf` and `/etc/udpchains.conf` (`src/config.c:414`), contradicting the comment at
  `src/config.c:509`. With `-f a.conf`, the home file's credentials still get used, and a broken
  home file breaks the target after the wrapper reported success.
- [ ] **M5 — the wrapper exports the proxy's hostname, not its resolved address.** Every exec'd
  descendant repeats the DNS lookup directly and may get a different address.
- [ ] **M6 — the setuid/setgid check and the exec can look at different files.** The wrapper
  checks the path `resolve_program()` found, then `execvp` searches `PATH` again
  (`src/wrapper.c:463`). Use `execv(program, ...)`.
- [ ] **M7 — interception ignores the protocol number.** ICMP ping sockets
  (`SOCK_DGRAM`/`IPPROTO_ICMP`, used by unprivileged `ping`) and UDP-Lite are treated as UDP
  (`src/hooks.c`, `is_intercepted_kind` and `adopt_fd`). *Inspection*: ping sockets are disabled
  on the review host.
- [ ] **M8 — the FR-L-02 generation counter is never read.** It is written at
  `src/fdtable.c:162` and nowhere checked, so the guard that comments and docs describe does not
  exist. `redirected` is also written but never read. Implement or remove both, and fix the docs.
- [ ] **M9 — a socket shared with another process is re-pointed.** After `fork()` + `exec`, an
  inherited UDP socket is adopted fresh, and first use `connect()`s the shared socket to a new
  relay, which also redirects the parent's. The same applies to sockets received via
  `SCM_RIGHTS` whose sender keeps a copy (noted in D-21). Separately, children keep the parent's
  control connections open, so the parent's associations linger at the proxy.
- [ ] **M10 — the signal-safety claim (NFR-03) is overstated.** The first send on a socket
  (`calloc`, handshake), the first datagram on each thread (`udpc_tls_get` mallocs), and
  `socket`, `dup` and `close` (block `calloc`, `free` via unref) all allocate or free memory.

## Low

- [ ] **L1** — `connect()` and `sendto()` copy the family's full address size regardless of the
  `addrlen` passed (`src/hooks.c` connect hook, `src/core.c:234`), so they can read past a short
  buffer. The kernel would return `EINVAL`.
- [ ] **L2** — a bad `msg_iov` pointer segfaults instead of returning `EFAULT`; `msg_iovlen` is
  truncated to `int`; 1024 iovecs plus the header iovec exceeds `UIO_MAXIOV`.
- [ ] **L3** — `close_range(3, ~0U)` walks up to 1,048,576 entries. Iterate only allocated blocks.
  - **Fixed alongside H4 (D-26), awaiting commit:** the range release now visits only allocated
    blocks.
- [ ] **L4** — per-datagram warnings (oversized inbound, multicast) are not rate-limited. Logs are
  written to fd 2 even if the app has reused it for a file or socket.
- [ ] **L5** — config and password-file handling:
  - A password file is silently truncated at 255 bytes, and a Windows line ending (`\r\n`) is not
    stripped.
  - There is no warning when a config file containing `password =` is readable by others.
  - Any value of `UDPCHAINS_QUIET`, including `0`, enables quiet mode.
  - Overlong-line detection misses lines with leading whitespace (`src/config.c:253`).
- [ ] **L6** — post-fork `reprivatize_socket` ignores a failed `bind()` and loses a
  wildcard-with-port binding (`src/assoc.c:249`).
- [ ] **L7** — build and address resolution:
  - Internal `udpc_*` symbols are exported (no `-fvisibility=hidden`).
  - There are no hardening flags (`-fstack-protector-strong`, `-z relro -z now`).
  - `udpc_addr_parse` uses only the first `getaddrinfo` result.

## Documentation

- [ ] **D1** — release setup:
  - The CHANGELOG links a `v1.0.0` tag that does not exist.
  - There is no CI configuration.
  - There is no `SECURITY.md`.
  - There is no `CONTRIBUTING.md`, although D-01 requires contributors to state their work is not
    derived from GPL code.
- [ ] **D2** — interop is overstated. The CHANGELOG says "interop confirmed against a real SOCKS5
  proxy", but that was one proxy (`dtun`, co-located). No end-to-end run against a remote proxy has
  succeeded, and `ATYP 0x04` has never been tested against a real proxy. Add this to Known
  limitations, and test Dante plus one other UDP-capable proxy before 1.0.
- [ ] **D3** — security caveats are missing from the README and man page:
  - RFC 1929 credentials cross the network in cleartext.
  - The relay leg to a remote proxy is unauthenticated and unencrypted, so spoofed datagrams can
    claim any source.
  - ~~The password is propagated through the environment (H3).~~ No longer true (D-25); the README
    now says what is passed instead.
  - UDP servers that only receive don't work through a proxy.
  - ~~The README's "No DNS leak" claim is false (C4).~~ Corrected with the D-22 implementation.
- [ ] **D4** — the configuration reference is incomplete:
  - The README's environment table omits `UDPCHAINS_PASSWORD`, `_QUIET`, `_DEBUG` and `_LIB`.
  - Config-file keys are listed nowhere.
  - Nothing says inline `#` comments are unsupported.
  - `connect_timeout` applies per handshake step.
  - The man page cites `LD_PRELOAD(8)`, which does not exist (use `ld.so(8)`).
- [ ] **D5** — stale design docs:
  - DESIGN.md says "no code written".
  - DESIGN §3.1 says a CLAIMING entry "spins briefly, then passes through"; it passes through
    immediately.
  - DESIGN §3.2 describes an association `state` field that does not exist.
  - DESIGN uses the names `do_send`/`do_recv`.
  - The DESIGN §6.4 errno table does not match the code's reply-code mapping.
  - The DECISIONS.md index stops at D-15 (D-16 to D-21 are missing).
  - `src/config.h:57` still says FR-P-09 is deferred.
- [ ] **D6** — the numbers disagree:
  - The suite now prints 498 assertions; TRACEABILITY says 455.
  - TST-05 is listed as 93 and as 76 (it is now 101).
  - TST-06 is now 43.
  - The matrix is called "36-cell" (README), 108 (CHANGELOG) and "36 × 4" (TRACEABILITY);
    the actual count is 108.
  - The TRACEABILITY rows need entries for D-21.
- [ ] **D7** — overclaims to soften:
  - ~~"no syscalls on the datagram path … cannot deadlock" (M10; the send path also calls `poll()`
    after 1 s idle).~~ Removed from the README with D-23, which adds a `getsockopt` per call. The
    same claim remains in the CHANGELOG's 1.0.0 entry and in DESIGN.md §3.1.
  - The FR-L-02 generation guard (M8).
  - "fall back or fail" for GSO/GRO (M2).
  - "nothing breaks" for the D-17 fix (H1).

## Verification still owed

- [ ] **C4 wire check** — run the capture script's D-22 case, which needs root:
  `sudo tests/test_failclosed_capture.sh`. Its client commands were checked without root.
- [ ] **C4 interop** — name resolution against a real proxy and resolver, INTEROP-CHECKLIST.md §11,
  including whether that proxy supports `CONNECT` for the TCP fallback.

## Residuals recorded in D-21 (no fix planned yet)

- [ ] stdio over a UDP socket (`fdopen`) uses glibc-internal read and write, and bypasses the hooks.
- [ ] `io_uring`, `sendfile` and `splice` bypass libc entirely.
- [ ] `pidfd_getfd` can obtain a UDP socket without passing through a hook.

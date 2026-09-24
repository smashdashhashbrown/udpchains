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
- [x] **H1** — a stale fd-table entry took over whatever the kernel next put at its number: a TCP
  socket's `connect()` was swallowed, a Unix socket's `write()` failed. Every intercepted call now
  confirms the socket's kernel cookie; `closefrom()` and the lifecycle calls of `syscall()` are
  hooked. (da42f4e, D-23)
- [x] **H2** — a use-after-free when threads share a socket and one sees the association expire.
  Associations are type-stable and read through one counted reference per datagram. (da42f4e,
  D-24)
- [x] **H3** — the wrapper exported the password itself into the target's environment. It now
  exports only where the password is. (da42f4e, D-25)
- [x] **H4** — the program could close the shim's own descriptors, after which the shim closed the
  program's. Shim descriptors now live at 768 and up and are protected. (da42f4e, D-26)
- [x] **L3** — `close_range(3, ~0U)` walked a million table entries; it now visits only allocated
  blocks. (da42f4e, with D-26)
- [x] **M1–M3, M9 (i)** — `strict_loopback` checked only at setup; `MSG_MORE`/`UDP_CORK`/GSO/GRO
  corrupt data; the first send blocks during the handshake; a socket shared with another process
  is re-pointed. Accepted for 1.0 and documented in the README. (dba3c76, D-32)
- [x] **M4** — the shim re-read the default config files. (dba3c76, D-27)
- [x] **M5** — the wrapper exported the proxy's hostname, not its address. (dba3c76, D-27)
- [x] **M6** — the setuid check and the exec could look at different files. (dba3c76, D-28)
- [x] **M7** — ICMP and UDP-Lite datagram sockets were treated as UDP; now refused. (dba3c76, D-29)
- [x] **M8** — the never-checked generation counter and `redirected` flag are removed. (dba3c76,
  D-30)
- [x] **M9 (ii)** — forked children kept the parent's control connections. (dba3c76, D-31)
- [x] **M10** — the signal-safety claim is corrected; NFR-03 is marked partial. (dba3c76)
- [x] **L1** — `connect()` and `sendto()` read past a short address; now `EINVAL`, or
  `EAFNOSUPPORT` for another family. (8eb4c80)
- [x] **L2** — a `NULL` `msg_iov` crashed, `msg_iovlen` was truncated to `int`, and `IOV_MAX`
  buffers overflowed the kernel limit. Now `EFAULT`, `EMSGSIZE`, and working. A non-`NULL` invalid
  pointer still faults; documented in the README. (8eb4c80)
- [x] **L4** — per-datagram warnings are rate-limited, nothing is written unless fd 2 is still the
  original stderr, and `-q` means errors only. (8eb4c80, D-33)
- [x] **L5** — password-file limit and `\r\n`, the readable-config warning, a boolean
  `UDPCHAINS_QUIET`, and indented overlong lines; the password-file warning is given once.
  (8eb4c80, D-33)
- [x] **L6** — a forked child binds its private socket again, and stops declaring an address it
  cannot bind. (8eb4c80, D-34)
- [x] **L7** — only hooks are exported, and the library is hardened; first-address-only is
  documented, not fixed. (8eb4c80, D-35)

## Critical

None open.

## High

None open.

## Medium

None open.

## Low

None open.

## Documentation

- [ ] **D1** — release setup:
  - The CHANGELOG links a `v1.0.0` tag that does not exist.
  - There is no CI configuration.
  - There is no `SECURITY.md`.
  - There is no `CONTRIBUTING.md`, although D-01 requires contributors to state their work is not
    derived from GPL code.
  - **Done, awaiting commit,** except CI, which was declined for 1.0.0. The CHANGELOG is one 1.0.0
    entry dated 2026-09-24; tag `v1.0.0` when releasing. `SECURITY.md` uses GitHub private
    vulnerability reporting, which must be enabled in the repository settings.
    `CONTRIBUTING.md` carries the D-01 statement.
- [ ] **D2** — interop is overstated. The CHANGELOG says "interop confirmed against a real SOCKS5
  proxy", but that was one proxy, co-located. No end-to-end run against a remote proxy has
  succeeded, and `ATYP 0x04` has never been tested against a real proxy. Add this to Known
  limitations, and test Dante plus one other UDP-capable proxy before 1.0.
  - **Documentation done, awaiting commit:** the claim is narrowed in the CHANGELOG, and the README
    and CHANGELOG list what is untested. The testing against Dante and a remote proxy is still
    owed; see *Verification still owed*.
- [ ] **D3** — security caveats are missing from the README and man page:
  - RFC 1929 credentials cross the network in cleartext.
  - The relay leg to a remote proxy is unauthenticated and unencrypted, so spoofed datagrams can
    claim any source.
  - ~~The password is propagated through the environment (H3).~~ No longer true (D-25); the README
    now says what is passed instead.
  - UDP servers that only receive don't work through a proxy.
  - ~~The README's "No DNS leak" claim is false (C4).~~ Corrected with the D-22 implementation.
  - **Done, awaiting commit:** a *Security considerations* section in the README and a SECURITY
    section in the man page.
- [ ] **D4** — the configuration reference is incomplete:
  - The README's environment table omits `UDPCHAINS_PASSWORD` and `_LIB`. (`_QUIET` and `_DEBUG`
    were added with L5.)
  - Config-file keys are listed nowhere.
  - Nothing says inline `#` comments are unsupported.
  - `connect_timeout` applies per handshake step.
  - The man page cites `LD_PRELOAD(8)`, which does not exist (use `ld.so(8)`).
  - **Done, awaiting commit.** Environment and key tables in the README and man page. An inline
    `#` after whitespace is now an error (unit-tested); a `#` inside a value is kept.
- [ ] **D5** — stale design docs:
  - DESIGN.md says "no code written".
  - DESIGN §3.1 says a CLAIMING entry "spins briefly, then passes through"; it passes through
    immediately.
  - DESIGN §3.2 describes an association `state` field that does not exist.
  - DESIGN uses the names `do_send`/`do_recv`.
  - The DESIGN §6.4 errno table does not match the code's reply-code mapping.
  - The DECISIONS.md index stops at D-15 (D-16 to D-21 are missing).
  - `src/config.h:57` still says FR-P-09 is deferred.
  - **Done, awaiting commit.** All seven; also DESIGN §8 (the TCP fallback now exists), the man
    page's LIMITATIONS, and a stale comment in `src/assoc.h`. The index runs to D-35.
- [ ] **D6** — the numbers disagree:
  - The suite now prints 498 assertions; TRACEABILITY says 455.
  - TST-05 is listed as 93 and as 76 (it is now 101).
  - TST-06 is now 43.
  - The matrix is called "36-cell" (README), 108 (CHANGELOG) and "36 × 4" (TRACEABILITY);
    the actual count is 108.
  - The TRACEABILITY rows need entries for D-21.
  - **Done, awaiting commit.** The totals table is regenerated from a run (651 assertions, 17
    groups, 71-check gate), and the per-test rows point at it rather than repeating numbers.
- [ ] **D7** — overclaims to soften:
  - ~~"no syscalls on the datagram path … cannot deadlock" (M10; the send path also calls `poll()`
    after 1 s idle).~~ Removed from the README with D-23, which adds a `getsockopt` per call. The
    same claim remains in the CHANGELOG's 1.0.0 entry and in DESIGN.md §3.1.
  - The FR-L-02 generation guard (M8).
  - "fall back or fail" for GSO/GRO (M2).
  - "nothing breaks" for the D-17 fix (H1).
  - **Done, awaiting commit:** the 1.0.0 CHANGELOG entry is rewritten without the claims.

## Verification still owed

- [x] **C4 wire check** — run the capture script's D-22 case, which needs root:
  `sudo tests/test_failclosed_capture.sh`. Run on 2026-09-24; all 14 checks pass. A first run
  failed the two DNS leak checks on other programs' lookups, since the check counted every port-53
  packet on the host. `strace` showed the proxied process made no port-53 call, and the check now
  counts only packets carrying its own lookup name.
- [ ] **D2 interop** — run the INTEROP-CHECKLIST against Dante and one other UDP-capable proxy, on
  another host, including an `ATYP 0x04` destination. Combine with the C4 interop check below.
- [ ] **C4 interop** — name resolution against a real proxy and resolver, INTEROP-CHECKLIST.md §11,
  including whether that proxy supports `CONNECT` for the TCP fallback.

## Residuals recorded in D-21 (no fix planned yet)

- [ ] stdio over a UDP socket (`fdopen`) uses glibc-internal read and write, and bypasses the hooks.
- [ ] `io_uring`, `sendfile` and `splice` bypass libc entirely.
- [ ] `pidfd_getfd` can obtain a UDP socket without passing through a hook.

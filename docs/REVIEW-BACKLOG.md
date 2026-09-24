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
- [x] **D1** — release setup: the CHANGELOG is one 1.0.0 entry, `SECURITY.md` (GitHub private
  vulnerability reporting) and `CONTRIBUTING.md` (the D-01 statement) exist. CI was declined for
  1.0.0. (749b973)
- [x] **D2** — the interop claim is narrowed to the one co-located proxy tested, and what is
  untested is listed; the testing itself is under *Verification still owed*. (749b973)
- [x] **D3** — security considerations in the README and man page. (749b973)
- [x] **D4** — complete environment and config-key references; an inline `#` comment is an error.
  (749b973)
- [x] **D5** — DESIGN.md, the decision index and the man page's limitations match the code.
  (749b973)
- [x] **D6** — traceability totals regenerated from a run; D-21 traced. (749b973)
- [x] **D7** — the overclaims removed with the 1.0.0 CHANGELOG rewrite. (749b973)

## Critical

None open.

## High

None open.

## Medium

None open.

## Low

None open.

## Documentation

None open.

## Verification still owed

- [x] **C4 wire check** — run the capture script's D-22 case, which needs root:
  `sudo tests/test_failclosed_capture.sh`. Run on 2026-09-24; all 14 checks pass. A first run
  failed the two DNS leak checks on other programs' lookups, since the check counted every port-53
  packet on the host. `strace` showed the proxied process made no port-53 call, and the check now
  counts only packets carrying its own lookup name. (7d1da61)
- [ ] **D2 interop** — run the INTEROP-CHECKLIST against Dante and one other UDP-capable proxy, on
  another host, including an `ATYP 0x04` destination. Combine with the C4 interop check below.
- [ ] **C4 interop** — name resolution against a real proxy and resolver, INTEROP-CHECKLIST.md §11,
  including whether that proxy supports `CONNECT` for the TCP fallback.

## Residuals recorded in D-21 (no fix planned yet)

Not fixed, but documented for users as ways around the proxy: the README (*Traffic it
deliberately refuses*), the man page's LIMITATIONS, `SECURITY.md` and the CHANGELOG. Awaiting
commit.

- [ ] stdio over a UDP socket (`fdopen`) uses glibc-internal read and write, and bypasses the hooks.
- [ ] `io_uring`, `sendfile` and `splice` bypass libc entirely.
- [ ] `pidfd_getfd` can obtain a UDP socket without passing through a hook.

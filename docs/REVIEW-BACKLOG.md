# Release review backlog

Findings of each pre-release review, newest first. Each item keeps the ID it was given in its
review, so discussions and commits can refer to it; IDs continue from one review to the next.

---

# Next release (supervisor mode) — review of 2026-10-26

Comprehensive review of code, documentation and tests on branch `release_review`, at `e9c08bb`.
`make test` was run from a clean build: all 26 groups passed (2346 assertions, 91 symbol checks);
tftp, ntpdate and iperf3 were skipped. Findings are recorded, not fixed, until the maintainer says
which to fix.

**Reproduced** means shown with a test program, recorded with the finding; **inspection** means
found by reading the code. File and line references are to `e9c08bb`.

## Critical

None found.

## High

- [x] **H5** — *Reproduced.* A carried UDP socket received below the range, over `SCM_RIGHTS`, is
  carried for `sendto`, `sendmsg`, `sendmmsg` and `connect`, which are trapped on every
  descriptor, but not for `recvfrom`, `recv`, `recvmsg`, `recvmmsg`, `read`, `readv`, `write` or
  `splice`, which are trapped only in the range. A static program that passed its own socket to
  itself got fd 5: `sendto` reached the echo server through the proxy, then `recvfrom` returned 19
  bytes from the relay's address, `00 00 00 01 7f 00 00 01 ae fc` followed by the 9-byte payload.
  That is the SOCKS header delivered as data, the defect of §0.3.2 that FR-I-02 (M) forbids.
  `write` on it sends the payload to the relay with no header. `decide()` (`src/svcall.c:1638`)
  calls `on_carried` for any descriptor whose cookie is known, whatever its number. By inspection,
  once the program closes its in-range copy, the sweep forgets the socket (`mark_table` skips
  numbers below the range), and the same calls switch to `EPERM`.
  D-50 accepts this, but its text says only "another supervised process" (the same process
  does it too) and only `read`/`write`. The README and man page do not mention it (see D8).
  *Suggested:* refuse every call but `close`, `getsockname` and `getpeername` on a carried
  socket below the range with `EPERM`, as FR-SV-18 does for a socket the supervisor did not make,
  and add the case to `test_supervise received`.
  **Fixed (6570c74):** refused at the pass instead (D-50 amended): a `sendmsg` or
  `sendmmsg` passing a carried socket over `SCM_RIGHTS` fails with `EPERM`; a carried socket
  below the range by any other route is refused too. New probe `test_supervise passing`.

## Medium

- [x] **M11** — *Reproduced.* A TCP query to the system resolver sent with
  `sendmmsg(..., MSG_FASTOPEN)` reaches it directly. `decide_other` checks only `connect`,
  `sendto` and `sendmsg` (`src/svcall.c:1540`, `stream_to_system_resolver` at `:1349`). A
  static probe supervised with `dns` unset sent a TCP query for `example.com` to
  `127.0.0.53:53` by `sendmmsg`, was connected to `127.0.0.53:53`, and got a 63-byte answer
  from systemd-resolved, which resolved it outside the proxy. FR-SV-12 (M): "never made
  directly". The call is unusual, but closing the gap means adding one case.
  **Fixed (6570c74):** `sendmmsg` is checked and carried as `sendmsg` is (D-52); tested
  in the `dns` and `nodns` probes.
- [ ] **M12** — *Reproduced.* Every `read`, `write`, `readv`, `writev`, `close`, `bind` and
  name call on any descriptor at 768 and up is traced, whatever it is (`g_in_range`,
  `src/supervise.c:116`). A `read` of `/dev/zero` at fd 800 took 39 µs supervised, against
  1.1 µs natively and 2.2 µs at fd 3. A program with more than 768 descriptors open (a server;
  Go raises its soft limit to the hard one at start-up) pays this on every file and TCP call at
  those numbers. The README, the man page and FUTURE-STATIC-BINARIES §9 do not say so; §9 and
  DESIGN §13.3 say only that I/O *below* the range never leaves the kernel. *Suggested:* document
  it at least.
  **Documented, not yet committed,** as the maintainer chose: README, man page, DESIGN §13.3,
  FUTURE-STATIC-BINARIES §9, FR-SV-15, and D-50, which records the two fixes considered (a range
  capped at 1024, and placeholder descriptors) and when to revisit them.
- [ ] **M13** — *Measured.* Each sweep (`svsock_sweep`, `src/svsock.c:212`) opens
  `/proc/<pid>/stat` for **every process on the host** to find the supervisor's descendants.
  It runs every 5 s while any socket is carried, and 200 ms after every `close`, `close_range`,
  `dup2`, exit or `exec` in the range. The supervisor is one thread, so every traced call of
  every supervised process waits meanwhile. A C loop over the same files took 12.9 ms per pass
  with 391 processes on this host, and the cost grows with the host, not the program. Marking is
  also O(descriptors × sockets): each socket descriptor walks every bucket. *Suggested:* the
  supervisor already sees every tracee start and end (`PTRACE_EVENT_FORK`/`CLONE`, `waitpid`),
  so it can keep its own list of processes, and index sockets by inode.
  **Fixed, not yet committed:** the sweep reads only the processes `svtrace.c` records as the
  kernel reports them, plus any child not reported yet, from `/proc/<pid>/task/<tid>/children`;
  sockets are indexed by inode (D-50 amended). New probe `test_supervise orphan`.
- [ ] **M14** — *Reproduced; found while testing M13.* A signal sent to `udpchains` while an
  association is being set up is not passed to the program until the setup ends, up to
  `connect_timeout` per hop later. The supervisor is inside the handshake, not reading its
  signalfd, and the handshake is abandoned only for a signal pending for the *program's* thread
  (`abandon()`, `src/svtrace.c`). The FR-SV-supervise check "SIGTERM during a hung association
  setup ends the program" passes only because its probe's own `SIGALRM`, at 300 ms, happens to
  abandon the setup first. If the retried send stops again before the loop reads the signalfd,
  the second setup hangs for the full timeout. Late in 4 of 30 runs at `8dbbf74`, and 9 of 30
  with M13's change, a difference within chance; once with exit status 0, the signal arriving
  after the program had ended. The check is therefore flaky (L17). *Suggested:* the abandon check
  first takes any forwardable signal pending for the supervisor (`sigtimedwait` on the forwarded
  set with a zero timeout, `SIGCHLD` excluded), and passes it on (`si_code` at or below zero, as
  `on_signal` does). The program's thread then has it pending, and the setup is abandoned as for
  a signal of its own.

## Low

- [ ] **L8** — *Inspection.* The two modes classify a datagram socket's protocol differently. The
  shim allows only `0` and `IPPROTO_UDP` (`src/hooks.c:279`), as D-29 decides. The supervisor
  refuses only ICMP, ICMPv6 and UDP-Lite (`src/svcall.c:1257`), so any other `SOCK_DGRAM`
  protocol the kernel accepts (L2TP/IP, for one) is made and "carried" as if it were UDP. Nothing
  goes direct, but it fails strangely instead of with `EPROTONOSUPPORT`. DESIGN §13.5 describes
  the denylist.
- [ ] **L9** — *Reproduced.* Once the program has exited, a signal sent to `udpchains` by another
  process is no longer forwarded (`!sv->child_done`, `src/supervise.c:364`), yet the
  supervisor goes on waiting for the descendants left running. `udpchains --supervise sh -c
  'sleep 30 & exit 0'` was still running 2 s after `kill -TERM`; only `SIGKILL` ended it.
- [ ] **L10** — *Inspection.* On a full send buffer, `send_via` (`src/svcall.c:569`) blocks the
  whole supervisor for up to 1 s, then returns `EAGAIN` to a socket the program made blocking,
  which never returns `EAGAIN` natively.
- [ ] **L11** — *Inspection.* `free_number` (`src/svcall.c:388`) probes every number from the
  range's start with `pidfd_getfd` until it finds a free one, so a program holding *n* sockets
  pays *n* + 1 system calls for each new `socket()` or `dup`: quadratic for a program that keeps
  many.
- [ ] **L12** — *Inspection.* Dead code in the shipped library and wrapper: `udpc_shim_ready()`
  (`src/shim.c:58`) has had no caller since the first commit. `udpc_socks_associate`,
  `udpc_socks_disconnect`, `udpc_socks_control_alive` and `udpc_socks_encode_domain` are called
  only by the unit tests; production uses the chain versions.
- [ ] **L13** — *Inspection.* The shim's `sendmmsg` and `recvmmsg` (`src/hooks.c:853`, `:1012`) do
  not cap `vlen` at 1024 (`UIO_MAXIOV`) as the kernel does, so a blocking `recvmmsg` with a
  larger `vlen` waits for more datagrams than the kernel would return, and `sendmmsg` sends more
  than it would. The supervisor caps both (`MMSG_MAX`), so the two modes differ. FR-F-09:
  partial success "as the kernel does".
- [ ] **L14** — *Reproduced.* A supervised program is given the full shim environment
  (`udpc_config_export`, `src/wrapper.c:528`): `UDPCHAINS_PROXY`, `UDPCHAINS_USERNAME`, the
  password file's path (or `UDPCHAINS_PASSWORD_CONFIG`) and the rest. The supervisor, not the
  program, talks to the proxy, so none of it is needed. This is no worse than shim mode (D-25),
  but it is exposure that serves no purpose.
- [ ] **L15** — *Inspection.* `dns_redirected` (`src/svcall.c:669`) stays set on a socket for good.
  If the same socket later sends to the configured `dns` address itself, replies from it are
  relabelled as coming from the system resolver it once asked.
- [ ] **L16** — *Inspection, not reproduced.* seccomp(2) ranks `SECCOMP_RET_USER_NOTIF` above
  `SECCOMP_RET_TRACE`. A supervised program that installs its own filter with a listener and
  answers with `SECCOMP_USER_NOTIF_FLAG_CONTINUE` has those calls run without the supervisor
  seeing them. This is deliberate evasion, covered by "not a sandbox" (D-48), but a program that
  uses seccomp notification itself would bypass the supervisor without meaning to. Worth one line
  in the limitations.
- [ ] **L17** — *Inspection.* Test harness:
  - 37 supervised runs in the test scripts use `timeout` without `-k`, which CLAUDE.md asks for
    because the supervisor passes `SIGTERM` on to its program;
  - TST-04 passes with three of its five tools skipped, and `NFR-04-bench`, which cannot fail, is
    counted among the groups passed, so the headline "ALL 26 TEST GROUPS PASSED" does not show
    either;
  - nothing tests a carried socket received below the range (H5); FR-SV-T3's `SCM_RIGHTS` check
    covers only a socket from an unsupervised process.

## Documentation

- [ ] **D8** — FR-SV-19 (M) is marked Verified, but neither the README's *What supervisor mode
  cannot do* nor the man page's *Limitations* states several of D-50's accepted limitations: H5's
  carried socket below the range; a supervised socket passed to an unsupervised process; the
  reserved range fixed before the program runs; the race in placing a socket. M12's cost at 768
  and up is not documented either. README line 370, "Everything the shim refuses is refused here
  too", is not true of stdio (`fdopen`), which the shim refuses and the supervisor carries, nor,
  per L8, of protocols other than UDP.
- [ ] **D9** — The decision index at the top of `DECISIONS.md` stops at D-54; D-55 is missing.
- [x] **D10** — `docs/TRACEABILITY.md`: the TST-02 row says 71 symbol checks; the run, and the
  paragraph above the table, say 91. **Fixed (6570c74),** with the totals regenerated
  for H5 and M11.
- [ ] **D11** — The man page's EXIT STATUS lists only 0, 1, 126 and 127. It does not say that
  otherwise `udpchains` exits with the program's status, or, supervised, dies of the signal that
  killed it, nor that 1 can be the program's own status as well as a refusal.
- [ ] **D12** — `UDP-PRELOAD-REQUIREMENTS.md`: the header still describes an `LD_PRELOAD` shim for
  dynamically linked programs only, and is marked "Draft for implementation, 2026-08-17".
- [ ] **D13** — Release steps not yet done: `VERSION` in the `Makefile` is still `0.2.0`, and the
  CHANGELOG entry is `[Unreleased]`.

## Carried over

Not new: from the 0.1.0 review below, still open, and deferred by the maintainer until a second
host exists: **D2 interop** and **C4 interop** across hosts. Supervisor mode has had the same
same-host interop as the shim, not yet across hosts (FR-SV-17 waits on it).

---

# `udpchains` 0.1.0

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
  is re-pointed. Accepted for 0.1.0 and documented in the README. (dba3c76, D-32)
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
- [x] **D1** — release setup: the CHANGELOG is one 0.1.0 entry, `SECURITY.md` (GitHub private
  vulnerability reporting) and `CONTRIBUTING.md` (the D-01 statement) exist. CI was declined for
  0.1.0. (749b973)
- [x] **D2** — the interop claim is narrowed to the one co-located proxy tested, and what is
  untested is listed; the testing itself is under *Verification still owed*. (749b973)
- [x] **D3** — security considerations in the README and man page. (749b973)
- [x] **D4** — complete environment and config-key references; an inline `#` comment is an error.
  (749b973)
- [x] **D5** — DESIGN.md, the decision index and the man page's limitations match the code.
  (749b973)
- [x] **D6** — traceability totals regenerated from a run; D-21 traced. (749b973)
- [x] **D7** — the overclaims removed with the 0.1.0 CHANGELOG rewrite. (749b973)

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
  *Partly done 2026-10-19 (INTEROP-CHECKLIST.md §12):* Dante and six other proxies were run on this
  host, with `ATYP 0x04` to `::1`. No proxy-specific udpchains defect was found. What remains is
  a proxy on another host.
- [ ] **C4 interop** — name resolution against a real proxy and resolver, INTEROP-CHECKLIST.md §11,
  including whether that proxy supports `CONNECT` for the TCP fallback. *Partly done 2026-10-19:*
  through each of the seven proxies, `getent` resolved through `9.9.9.9`, and the TCP fallback ran
  over each proxy's `CONNECT` against the fixture resolver. Not yet checked: with a remote proxy, or
  with `tcpdump` on this host.
- [x] **errno when the proxy is down** — found in the §12 runs. With no proxy listening, a send
  failed with `ECONNRESET`, not the connect's own `ECONNREFUSED` that DESIGN.md §6.4 specifies,
  because the proxy-connect wait reported `POLLERR` as a reset without reading `SO_ERROR`. It
  still failed closed. `connect_with_timeout` in `src/socks5.c` now returns `SO_ERROR`, and
  `unit-socks5` has a test that fails without the fix. (b31b583)

## Residuals recorded in D-21

Documented for users as ways around the proxy: the README (*Traffic that bypasses the shim*), the
man page's LIMITATIONS, `SECURITY.md` and the CHANGELOG. D-36 (released in 0.2.0) closed all but
`io_uring`.

- [x] stdio over a UDP socket (`fdopen`) uses glibc-internal read and write, and bypasses the hooks.
  Now refused with `EINVAL` (D-36, 5084498).
- [x] `sendfile` and `splice` bypass libc entirely. Now refused with `EINVAL` on a UDP socket
  (D-36, 5084498).
- [x] `pidfd_getfd` can obtain a UDP socket without passing through a hook. The copy is now
  adopted and tracked (D-36, 5084498).
- [ ] `io_uring` bypasses libc entirely. No fix is possible in the shim; supervisor mode could
  refuse `io_uring_setup` (FR-SV-09, [`FUTURE-STATIC-BINARIES.md`](FUTURE-STATIC-BINARIES.md)).

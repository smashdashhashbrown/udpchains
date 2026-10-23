# Future requirement — static and Go binaries (supervisor mode)

**Status:** in progress after 0.2.0, on branch `supervisor_mode`. Steps 1 to 3 of §7 are done: the
decisions are D-48 to D-53, the requirements are §2b of
[`UDP-PRELOAD-REQUIREMENTS.md`](../UDP-PRELOAD-REQUIREMENTS.md), which is now the reference for
them, and the supervisor carries a static program's UDP (DESIGN.md §13). §9 lists the known
limitations the decisions accept.
**Written:** 2026-10-20, against `9acf337`. Line counts and file references are as of that
commit; recheck them before starting. The kernel versions in §8 were confirmed in the man pages
on 2026-10-22.

This works out far enough to start from how udpchains could proxy programs that `LD_PRELOAD`
cannot reach: what the feature is, who it is for, the mechanism, draft requirements, what it
changes in the current design, and an estimate. When the work begins, the draft requirements move
into [`UDP-PRELOAD-REQUIREMENTS.md`](../UDP-PRELOAD-REQUIREMENTS.md), and each design question
below gets a decision record in [`DECISIONS.md`](../DECISIONS.md).

---

## 1. What it is

The shim works by being loaded before libc and replacing its functions (FR-I-01). Three kinds of
program never call those functions, so today they send directly:

- **Statically-linked binaries.** No dynamic loader, so `LD_PRELOAD` is never read.
- **Go binaries,** static or not. The Go runtime makes its own system calls.
- **Programs calling `syscall()` directly** for sends and receives.

The only place all three can be seen is the system-call boundary, from outside the process. In
**supervisor mode**, `udpchains` stays running as the program's parent, and the kernel hands it
the program's UDP system calls to perform or refuse:

```
                 ┌───────────── kernel ─────────────┐
program ──sendto──▶ seccomp filter ──notification──▶ udpchains (supervisor)
                 │                                  │   reads payload, adds header,
                 │  program's own socket ◀──────────┤   sends on its copy of that socket
                 └───────────────┬──────────────────┘
                                 ▼
                            proxy relay
```

The shim does not go away. Supervisor mode is a second front end over the same SOCKS5 client,
association handling and header code.

## 2. Who it is for

- **Users of Go tools.** Much current network and security tooling is written in Go, including
  DNS tools, scanners and agents. None of it can be proxied by any `LD_PRELOAD` tool today. In the
  comparison lab (README, *Comparison with similar tools*), only graftcp sent a static Go binary's
  UDP through the proxy.
- **Static binaries generally:** musl builds, busybox, binaries copied into minimal containers.
- **Anyone relying on the no-bypass guarantee.** Because the supervisor sees system calls rather
  than libc functions, it can refuse the routes the shim still cannot see: `io_uring`, and system
  calls made without libc (D-36). This mode would be the stronger of the two.

**Not a sandbox.** A program that wants to escape can still do so, for example by racing its own
memory between the supervisor's check and a call the supervisor lets through, or by talking to
another process that is not supervised. Like the shim, this keeps a cooperative program from
leaking by accident. The documentation must say so.

## 3. Mechanism

Three ways of intercepting from outside were considered.

| | Verdict |
|---|---|
| **`ptrace`** | **Rejected.** If the tracer dies, the program continues untraced and sends directly, which breaks SEC-01. It conflicts with `gdb` and `strace`. In the comparison lab, the `ptrace`-based tool ran reliably only with Docker's seccomp filter disabled. |
| **Network namespace and TUN device** | **Rejected.** The strongest guarantee, but it needs unprivileged user namespaces, which Ubuntu 24.04 restricts by default through AppArmor. The program's TCP would have nowhere to go unless udpchains carried TCP too, which is a §8 non-goal. |
| **seccomp user notification** (`seccomp_unotify(2)`) | **Chosen (D-48).** The kernel stops the program at the system calls the filter selects and sends a notification to the supervisor, which performs the call itself or answers with an error. If the supervisor exits, those calls fail with `ENOSYS`, so the program stays fail-closed. No conflict with debuggers. |

In outline:

1. The wrapper forks. The child sets `no_new_privs`, installs the filter with
   `SECCOMP_FILTER_FLAG_NEW_LISTENER`, hands the listener to the parent, and runs the program. The
   parent becomes the supervisor.
2. **`socket()`** for `AF_INET`/`AF_INET6` `SOCK_DGRAM` is performed by the supervisor, which
   installs the socket in the program at a descriptor number in a **reserved range**
   (`SECCOMP_IOCTL_NOTIF_ADDFD`) and keeps its own copy of the same open file.
3. **Sends** are performed by the supervisor: payload and addresses read from the program's memory
   (`process_vm_readv`), header added, and sent on its copy. The datagram leaves from the
   program's own socket, so FR-I-07 still holds: there is no shadow socket.
4. **Receives** are performed by the supervisor on its copy: header checked and stripped, payload
   and the real sender written back (`process_vm_writev`). Replies arrive on the program's own
   socket, so `poll`, `select`, `epoll` and Go's network poller work with no help.
5. **The reserved range keeps the cost to UDP.** A seccomp filter cannot tell what kind of socket a
   descriptor is, but it can compare descriptor numbers. Because every UDP socket lives in the
   range, `read`, `write` and the rest are sent to the supervisor only for descriptors in it.
   Ordinary file and TCP I/O never leaves the kernel.

The supervisor's own descriptors (control connections, copies of sockets) live in the supervisor,
not the program, so D-26's protected band is not needed in this mode.

## 4. Draft requirements

**Moved** to §2b of [`UDP-PRELOAD-REQUIREMENTS.md`](../UDP-PRELOAD-REQUIREMENTS.md) on 2026-10-22,
updated to the decisions and with FR-SV-18 and FR-SV-19 added. The draft below is kept as it was
written, for the record; §2b is the reference.

| ID | Pri | Requirement | Verify |
|---|---|---|---|
| FR-SV-01 | M | Supervisor mode SHALL be chosen explicitly (for example `udpchains --supervise`). Without it, behaviour SHALL be exactly as 0.1.0. The same configuration, credentials (SEC-03) and diagnostics SHALL apply in both modes. | integration |
| FR-SV-02 | M | If supervisor mode cannot be set up — kernel too old, seccomp unavailable, the program's memory not accessible — `udpchains` SHALL refuse to run the program, and SHALL NOT run it unsupervised. | integration |
| FR-SV-03 | M | The filter SHALL check the architecture, and refuse system calls from any other ABI the kernel accepts, such as x32 and 32-bit calls on x86-64. An unrecognised architecture SHALL be refused, never allowed. | unit |
| FR-SV-04 | M | Every `AF_INET`/`AF_INET6` `SOCK_DGRAM` socket in a supervised process SHALL live in the reserved range. `dup`, `dup2`, `dup3` and `fcntl(F_DUPFD*)` that would place one outside it SHALL be performed by the supervisor inside the range, or refused. | integration |
| FR-SV-05 | M | The program's own socket SHALL remain the only data socket (FR-I-07). The supervisor works on a copy of the same open file. | integration |
| FR-SV-06 | M | Every send on a reserved descriptor — `sendto`, `sendmsg`, `sendmmsg`, `write`, `writev`, `pwritev2` — SHALL be performed by the supervisor, with the return values and `errno`s of shim mode. | integration |
| FR-SV-07 | M | Every receive on a reserved descriptor — `recvfrom`, `recvmsg`, `recvmmsg`, `read`, `readv`, `preadv2` — SHALL be performed by the supervisor: header checked and stripped, the real sender reported, truncation and `MSG_TRUNC` as in shim mode. | integration |
| FR-SV-08 | M | Blocking and non-blocking receives (`O_NONBLOCK`, `MSG_DONTWAIT`), `SO_RCVTIMEO`, and interruption by a signal SHALL behave as on a native socket. A datagram SHALL NOT be lost because a signal interrupted the call that was receiving it. | integration |
| FR-SV-09 | M | Routes that cannot be proxied SHALL be refused with an `errno` and a diagnostic: `io_uring_setup`, `sendfile` and `splice` onto a reserved descriptor, `pidfd_getfd`, `SOCK_RAW` creation (D-18), and ICMP and UDP-Lite sockets (D-29). | integration |
| FR-SV-10 | M | `getpeername` and `getsockname` SHALL report what the program believes (FR-I-05). | integration |
| FR-SV-11 | M | `fork`, `vfork`, threads, `clone` with and without `CLONE_FILES`, and `exec` SHALL be followed: children are supervised, state follows each descriptor table, and descriptors closed on `exec` are noticed (D-23's cookie check is one way). The supervisor SHALL stay until the last supervised process exits, and SHALL exit with the program's status. | integration |
| FR-SV-12 | M | **DNS.** A supervised program runs its own resolver, configured by `/etc/resolv.conf`. UDP queries to port 53 SHALL go through the proxy, to the configured `dns` server if decision 5 (§5) so decides. A TCP connection to port 53 SHALL be refused or carried by SOCKS5 `CONNECT`, and SHALL NOT be made directly. | integration |
| FR-SV-13 | M | If the supervisor exits or is killed, every supervised call SHALL fail, and nothing SHALL be sent directly. | integration |
| FR-SV-14 | M | The supervisor SHALL open no listening socket (SEC-05), and SHALL NOT log payload (NFR-05). setuid and setgid targets SHALL still be refused (SEC-06). | inspection |
| FR-SV-15 | S | The added latency per call SHALL be measured and documented, against NFR-04's 100 µs. | manual (benchmark) |
| FR-SV-16 | S | aarch64 SHALL be supported as well as x86-64. | integration |
| FR-SV-17 | C | Supervisor mode MAY be chosen automatically for static and Go binaries, once it has had the same interop as the shim. | unit |
| FR-SV-T1 | M | The hook matrix (TST-01, 108 cells) SHALL pass under supervisor mode with the probe built `-static`. | integration |
| FR-SV-T2 | M | The leak test (SEC-02) and the wire capture (`test_failclosed_capture.sh`) SHALL pass with a static client, and with the supervisor killed mid-run. | integration |
| FR-SV-T3 | M | Lifecycle tests SHALL cover `fork`, `exec`, threads, the `dup` family, `close_range`, `SCM_RIGHTS`, and each refused route of FR-SV-09. | integration |
| FR-SV-T4 | M | Signal tests SHALL interrupt blocking receives, with and without `SA_RESTART`, and check that no datagram is lost. | integration |
| FR-SV-T5 | S | A Go client SHALL be tested when a Go toolchain is present; `make` itself SHALL still need only a C compiler (acceptance criterion 5). `make compare` SHALL gain a supervisor-mode column. | integration |

## 5. What changes in the current design

The SOCKS5 client, header codec, address checks and configuration carry over unchanged. What is
new is the front end: a filter, a notification loop, and system-call emulation in place of libc
hooks.

| Module (lines at `9acf337`) | Change | Estimate |
|---|---|---|
| new `supervise.c` | Building the filter, handing the listener to the parent, the notification loop, worker threads for blocking calls, the supervisor's exit and the program's status. | +650–900 |
| new `emulate.c` | Decoding each system call's arguments, reading and writing the program's memory (`msghdr`, `mmsghdr`, iovecs, addresses), and performing the send and receive calls. | +850–1,100 |
| new per-process state | Descriptor tables per process, shared between threads and copied on `fork`; the reserved range; noticing `exec`. Plays the part of `fdtable.c` (515). | +400–550 |
| `core.c` (571) | The send and receive paths take buffers the supervisor has already copied, as well as the program's own iovecs. | +100–200 |
| `assoc.c` (571) | Associations live in the supervisor and are keyed by process and descriptor. `fork` is simpler than D-31, since the control connections never enter the program. | +100–150 |
| `wrapper.c` (502) | Forking rather than replacing itself, the flag, refusing to run unsupervised. | +150–250 |
| `resolve.c` (989), `dns.c` (333) | Port-53 redirection, if decision 5 chooses it. The shim's resolver hooks (`dnshooks.c`, 735) do not apply in this mode. | +100–200 |
| system-call tables | x86-64, then aarch64. aarch64 has no `dup2`, and neither has `send` or `recv` (libc uses `sendto` and `recvfrom`). | +100–150 |

**Decisions this revisits:** FR-I-01 (`LD_PRELOAD` as the only mechanism), D-36 (its refusals,
made at the system call instead of at libc, and `io_uring` refusable too), D-22 (the program's own
resolver runs), D-23 (cookie checks, now across processes), D-26 (protected descriptors, not
needed in the program), D-31 (fork), NFR-01a (a higher kernel floor for this mode), and NFR-03
(signal safety, moot outside the process).

**Decision records to write before coding** — written 2026-10-22 as D-48 to D-53, in this order:

1. Seccomp user notification, rather than `ptrace` or namespaces (§3).
2. How the mode is chosen (FR-SV-01, FR-SV-17), and whether the shim and the supervisor are ever
   used together on one program.
3. The reserved range: where it starts, what happens near `RLIMIT_NOFILE`, and what to do about a
   UDP socket received over `SCM_RIGHTS`. Catching that means performing `recvmsg` on every Unix
   socket, which D-Bus and Wayland programs call constantly. The alternative is to document it, as
   D-21 does for the shim today.
4. Receiving under signals (FR-SV-08). One approach: peek at the datagram, deliver it, and consume
   it only once the kernel confirms the program received the answer.
5. DNS in supervisor mode (FR-SV-12). Resolvers check that a reply comes from the address they
   asked, so a redirected query's reply must appear to come from the original destination.
6. What is refused (FR-SV-09), and the kernel floor. Refusing `io_uring_setup` refuses it for
   files too. Most programs fall back to ordinary calls, but that needs checking.

## 6. Estimate

- **Production code:** about 2,500–3,500 lines, most of it new; about 8,800 today.
- **Tests:** about 1,500–2,500 lines. The existing matrix, leak, lifecycle and fault tests run in
  both modes, plus signal tests and supervisor-killed tests.
- **Documents:** the six decision records, a DESIGN.md section, README (the *What does not work*
  section has a column per mode), man page, TRACEABILITY.
- **Time:** about six to ten focused weeks to the 0.1.0 standard, for x86-64. aarch64 adds about a
  week. For scale, multi-hop chains are estimated at two to three weeks
  ([`FUTURE-UDP-CHAINS.md`](FUTURE-UDP-CHAINS.md)).

## 7. Suggested order

1. The decision records. Move §4 into the requirements document.
2. A supervisor that installs the filter and lets everything through, with the program's exit
   status and signals passed on. The whole suite still green in shim mode. A safe point to stop.
   *Done 2026-10-22, with one change:* "everything" would have included UDP, sent directly, so
   instead a UDP socket is refused until step 3 can carry it, and D-50's and D-53's refusals are
   in place already. Every commit of the mode fails closed.
3. `socket()`, the reserved range and the `dup` family. Then sends, then non-blocking receives:
   enough for the matrix with a static probe, and for Go, which never blocks in a receive.
   *Done 2026-10-22,* with blocking receives brought forward from step 4, since the matrix makes
   them. A receive with nothing queued is parked in the supervisor's own loop rather than given
   to a worker, honouring `SO_RCVTIMEO` and ending in `EINTR` when a signal interrupts it (D-51).
   The static matrix passes directly and through two hops, and the fidelity test passes with the
   two documented differences. Sockets are tracked by the kernel's socket cookie, so `fork` and
   `exec` need nothing more for state; step 5 is left their tests and threads.
4. Blocking receives and signals. The hardest part, so it gets its own step. What is left after
   step 3: the signal tests of FR-SV-T4, `SA_RESTART`, and that no datagram is lost.
5. `fork`, threads and `exec`; the refused routes; the supervisor-killed test; the wire capture.
6. DNS. Then aarch64, interop, `make compare`, and documentation.

## 8. Risks and open questions

- **Kernel features.** User notification needs Linux 5.0, `pidfd_getfd` 5.6,
  `SECCOMP_IOCTL_NOTIF_ADDFD` 5.9 and `SECCOMP_ADDFD_FLAG_SEND` 5.14, so the floor is 5.14 (D-53).
  That matches distributions with glibc 2.34 (Ubuntu 22.04, RHEL 9), but excludes Debian 11.
  The listener reports end of file (`POLLHUP`) once the last thread using the filter has
  terminated and been reaped (`seccomp_unotify(2)`), which is how the supervisor knows to exit.
- **Containers.** Whether Docker's default seccomp profile lets the supervisor install its filter,
  and whether user notification works inside other sandboxes such as gVisor, needs testing.
- **Access to the program's memory.** `process_vm_readv` and `pidfd_getfd` need the same
  permission as `ptrace`. Yama's default (`ptrace_scope` 1) allows a parent to reach its children,
  which is the supervisor's position; a stricter setting does not, and FR-SV-02 must then refuse.
- **Signals.** FR-SV-08 is the hardest requirement. Go's runtime signals its threads often for
  preemption, but uses non-blocking sockets, so it may not meet the problem; C programs blocked in
  `recvfrom` will.
- **Speed.** Each UDP call costs two context switches and a copy. Several microseconds per call
  is expected, against about 1 µs for the shim, but that is unmeasured.
- **Two front ends.** Every behaviour has to be tested twice and documented per mode. The
  requirements should say which differences between the modes are allowed.
- **The shim loaded into the supervisor.** An inherited `LD_PRELOAD` naming `libudpchains.so`
  loads the shim into the wrapper itself, where it would wrap the supervisor's own datagrams.
  *Settled in step 3:* the wrapper runs itself again without it (D-49).
- **Setting up an association holds up the loop.** The supervisor is one thread, so while it
  waits for the proxy, every other trapped call waits too. Moving setup to a worker is a candidate
  for step 4 or 5, if a program is found that suffers from it.
- **Processes that cannot be inspected.** A process that makes itself non-dumpable
  (`ssh-agent`, `gpg-agent`) denies the supervisor the access it needs, so its connects and sends
  fail closed, TCP included, with a diagnostic naming the cause (D-48). Found in step 3. *Decided:*
  it stays fail-closed. Letting such a process's connects and sends through below the range would
  widen D-50's received-socket gap for it; revisit if a program needs it.
- **A thread with its own descriptor table.** A notification names a thread; the supervisor reads
  the descriptor through its process (`pidfd_open` takes a process before Linux 6.9). A thread
  that has unshared its descriptor table (`unshare(CLONE_FILES)`) would be checked against the
  wrong table. Rare; step 5 (threads) settles it.
- **Clean room (D-01).** graftcp is GPL-3.0 and must not be read. The design comes from the man
  pages: `seccomp(2)`, `seccomp_unotify(2)`, `pidfd_getfd(2)`, `process_vm_readv(2)`, `ptrace(2)`
  (for the access rules).

## 9. Known limitations, as decided

What the decisions accept, collected here so the README and man page can state them per mode when
the mode is built (FR-SV-19). Each is explained in its record.

- **Not a sandbox** (D-48). A call let through after a check can be changed in between by a hostile
  program. Like the shim, the mode prevents accidental leaks, not deliberate ones.
- **A UDP socket received already connected, then written with `write`, `writev` or `pwritev2`,
  sends directly** (D-50). It needs a socket passed over `SCM_RIGHTS` by an unsupervised process,
  connected before it was passed, and never connected again by the program.
- **Every `sendto`, `sendmsg`, `sendmmsg` and `connect` makes a round trip to the supervisor,**
  UDP or not (D-50): D-Bus traffic, TCP programs using `sendmsg`, and every connection.
- **A supervised UDP socket passed to an unsupervised process** does not work there: what it writes
  reaches the relay without a header (D-50). Not a leak.
- **The reserved range is fixed before the program runs** (D-50); a program raising its own
  descriptor limit does not move it.
- **An inherited UDP socket stops the program from starting** (D-50), so a service handed a UDP
  socket by its service manager cannot be supervised.
- **`recvmmsg` returns at most one datagram per call** (D-51).
- **An interrupted receive may still have written to the program's buffer** (D-51); the call
  itself fails or restarts as it should.
- **A socket also read by an unsupervised process** can lose a datagram (D-51).
- **DNS** (D-52), none of it a leak:
  - only queries to the system resolver (loopback, or `/etc/resolv.conf`, re-read when it changes)
    are redirected to `dns`; other port-53 traffic is proxied as addressed, so a private resolver
    configured elsewhere is reached on the proxy's network, and fails;
  - a local DNS server's own entries are not used; `/etc/hosts` is;
  - split DNS works only if `dns` knows the internal names and the proxy can reach it;
  - DNS over TCP to other servers, over TLS and over HTTPS is TCP, which is not proxied; and until
    TCP to the system resolver is carried by `CONNECT`, a truncated answer fails.
- **`io_uring` is refused for everything,** files included (D-53). Go does not use it; software
  that does mostly falls back, but a framework that requires it fails to start under supervision.
- **Linux 5.14 or later,** a reachable program memory (Yama `ptrace_scope` 1 or less), and a
  container runtime that allows the filter are required; otherwise the program is not run (D-53).
- **Each supervised call costs two context switches and a copy,** against about 1 µs for the
  shim; to be measured (FR-SV-15).
- **Found in step 3** (D-48, D-50):
  - while an association is set up, the program's other trapped calls wait for it;
  - a process that makes itself non-dumpable (`ssh-agent`, `gpg-agent`) fails closed, with a
    diagnostic naming the cause: its connects and sends, TCP included,
    are refused, and it cannot make a UDP socket;
  - a send interrupted after its datagram has left is sent again if the call restarts;
  - a socket is placed at a free number, but a program with the range's start of descriptors open
    could, from another thread, open one at that number in the instant before the install;
  - a carried socket passed to another supervised process below the range is carried by its
    sends, but not by `write` and `read` there;
  - stdio on a UDP socket is carried, where the shim refuses it (D-36): a difference between the
    modes, not a limitation.

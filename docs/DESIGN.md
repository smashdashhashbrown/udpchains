# Design — `udpchains`

How the shim is built. Requirements live in [`UDP-PRELOAD-REQUIREMENTS.md`](../UDP-PRELOAD-REQUIREMENTS.md);
the choices behind this design and their rationale live in [`DECISIONS.md`](../DECISIONS.md).
Requirement IDs are cited inline so [`TRACEABILITY.md`](TRACEABILITY.md) can map each one to a section
here.

**Status:** as built in 0.1.0, plus multi-hop chains (§12). Where the first draft changed, the
decision record that changed it is cited.

---

## 1. Overview

Two artefacts:

| Artefact | Role |
|---|---|
| `libudpchains.so` | The shim. Interposes on libc socket calls via `LD_PRELOAD`. |
| `udpchains` | Wrapper executable. Resolves configuration, refuses to run if it cannot, sets `LD_PRELOAD`, `exec`s the target. |

Plus test-only artefacts (§9), never linked into the shim.

The central architectural commitment is **FR-I-07: the application's own fd is redirected to the
relay.** There is no shadow socket. The fd the application holds is a real kernel UDP socket that
happens to point at the SOCKS5 relay instead of the destination the application named. Everything
else follows from this:

- `poll`, `select`, `epoll_wait`, `SO_RCVBUF`, `O_NONBLOCK`, `SO_RCVTIMEO` and every other
  readiness or socket-option mechanism keeps working untouched, because there is exactly one real
  socket and it is the application's. These are **not hooked and must not be** (FR-I-07).
- The shim never owns a data socket, so FR-P-06 (one stable local socket per association) is
  automatic rather than enforced.
- The shim's work reduces to: rewrite addresses on the way in and out, prepend a header on send,
  strip it on receive, and keep per-fd state consistent.

Data flow for one datagram:

```
app: sendto(fd, payload, dst)
  └─ hook: look up fd → association
     ├─ dst is multicast/broadcast? → ENETUNREACH + diagnostic   [D-05 R1]
     ├─ payload > max_datagram?     → EMSGSIZE                   [FR-F-07, D-12]
     ├─ no association yet?         → establish (§4)             [FR-P-01]
     └─ real_sendmsg(fd, iov[ header, payload ])                 [D-11]
        └─ returns wrapped length; hook returns payload length   [FR-F-01]

app: recvfrom(fd, buf, &src)
  └─ hook: real_recvmsg(fd, scratch)                             [D-11]
     ├─ FRAG != 0?  → discard, read again                        [FR-P-04]
     ├─ parse header → true source address                       [FR-F-02]
     ├─ copy payload into app buffer, set MSG_TRUNC if short     [FR-F-04]
     └─ return payload length, src = true origin
```

---

## 2. Hook layer

### 2.1 Symbol resolution

Each hooked function resolves its real implementation with `dlsym(RTLD_NEXT, name)` (FR-I-01),
cached in a file-scope atomic pointer. Resolution is lazy — performed on first call, not in a library
constructor — to avoid ordering hazards with other preloaded libraries and with the loader's own
use of these symbols during startup.

`dlsym` itself may allocate. That is acceptable because it happens once per symbol, on a path that is
not the per-datagram path (NFR-02), and never inside a signal handler in practice. A double
resolution under a race is harmless: both threads compute the same pointer.

### 2.2 Interception predicate

A call is intercepted only if **all** hold (FR-I-06):

1. The fd has an entry in the table in state `ACTIVE` (§3.1); and
2. it was created as `SOCK_DGRAM` in `AF_INET` or `AF_INET6`.

Everything else — TCP, unix, netlink, raw, and any fd the shim never saw created — passes straight
through to the real function with no inspection. In particular the shim's own control connections are
TCP and so are excluded by the same predicate that excludes the application's TCP sockets; no special
case is needed, and none should be added.

The predicate is checked with atomic loads only. A non-intercepted call costs one table lookup.

### 2.3 Hook inventory

Required by FR-I-03/04/05, gated at build time by TST-02 (`nm -D`).

| Group | Symbols |
|---|---|
| Send | `sendto`, `sendmsg`, `sendmmsg`, `send`, `write`, `writev` |
| Receive | `recvfrom`, `recvmsg`, `recvmmsg`, `recv`, `read`, `readv` |
| Receive, fortified | `__recvfrom_chk`, `__recv_chk`, `__read_chk` (D-21) |
| Lifecycle | `socket`, `connect`, `bind`, `close`, `close_range`, `closefrom`, `dup`, `dup2`, `dup3`, `fcntl`, `fcntl64` (D-21, D-23) |
| Via `syscall()` | `syscall` — every number with a hook is routed to that hook: the lifecycle calls (D-23), and since D-36 the socket, send and receive calls, `sendfile`, `splice` and `pidfd_getfd`; every other number goes straight to the kernel |
| Introspection | `getpeername`, `getsockname` |
| Proxied by another route (D-36) | `dprintf`, `vdprintf`, `__dprintf_chk`, `__vdprintf_chk` (formatted, then one datagram through the send path); `pwritev2`, `pwritev64v2`, `preadv2`, `preadv64v2` (at offset −1, as `writev` and `readv`) |
| Refused on a UDP socket (D-36) | `sendfile`, `sendfile64`, `splice`, `fdopen` — `EINVAL` |
| Adopted (D-36) | `pidfd_getfd` |
| glibc's public aliases (D-36) | `__write`, `__read`, `__send`, `__connect`, `__close`, `__dup2`, `__fcntl`, each forwarded to its hook |

The fortified variants are what a `_FORTIFY_SOURCE` build calls in place of `recvfrom`, `recv` and
`read`. glibc implements them with internal calls that no preload can see, so they are hooked
separately and funnel into the same receive path. `fcntl` is hooked only for `F_DUPFD` and
`F_DUPFD_CLOEXEC`, which duplicate a descriptor exactly as `dup` does; every other command passes
through.

A UDP socket can also enter the process without passing through any of these hooks: it can be
inherited across `exec`, received as `SCM_RIGHTS` ancillary data, or copied from another process
with `pidfd_getfd`. Inherited sockets are adopted at start-up, from `/proc/self/fd` or, without
`/proc`, by probing the descriptor table. Received sockets are adopted by the `recvmsg`/`recvmmsg`
hooks before the call returns, and copied ones by the `pidfd_getfd` hook. A socket that cannot be
tracked is closed, never left to send directly (D-21). So is a raw or packet socket, and the
`socket()` hook refuses to create one with `EPERM` (D-36).

What still reaches the kernel without a hook: `io_uring`, which has no glibc wrapper, and system
calls made without libc's `syscall()` (D-36).

**FR-I-02 is structural, not a checklist item.** Send and receive hooks are implemented in pairs, and
the internal implementation funnels every send variant into one `udpc_core_send()` and every
receive variant into one `udpc_core_recv()` (`src/core.c`). `send` is
`sendto` with a NULL destination; `write` is `send` with zero flags; `writev` is `sendmsg` with one
iovec and no control data. This is what makes it structurally hard to ship the Proxando failure —
a send path that works with a receive path that returns wrapped bytes (§0.3.2). There is no code path
that wraps without a corresponding path that unwraps.

`close_range` is conditionally compiled per D-09.

---

## 3. State model

### 3.1 The fd table

Two-level radix table (D-07), indexed by fd:

```
top[fd >> 8]  →  block of 256 entries  →  entry[fd & 0xff]
```

- Top level: fixed array of atomic pointers, sized for the maximum plausible fd. Costs one pointer
  per 256 fds.
- Blocks: allocated on demand in `socket()`/`dup*()`, published with a release-store CAS. Never
  freed — an application that once used fd N is likely to again, and a thread still holding a
  pointer into a freed block would read freed memory.
- **No allocation and no locks on the datagram path** once a socket's association is up (NFR-02,
  NFR-03). A lookup is two atomic loads, plus one `getsockopt` for a descriptor the shim tracks,
  to confirm it is still the same socket (D-23). NFR-03 holds only in that steady state; see §3.5.

Entry contents:

| Field | Purpose |
|---|---|
| `state` (atomic) | `FREE` → `CLAIMING` → `ACTIVE` → `DYING` → `FREE`; or `SHIM` for the shim's own descriptors (D-26) |
| `cookie` (atomic) | The socket's `SO_COOKIE`, checked by every intercepted call so a stale entry never claims whatever reused its number (D-23) |
| `assoc` | Pointer to the shared association object (§3.2) |
| `app_dst` | Destination the application named via `connect()` (FR-F-08) |
| `connected` | Whether `connect()` has been called and not dissolved |
| `bound_addr` | Concrete address from `bind()`, if any (FR-P-05, FR-I-05) |
| `family`, `type` | For the §2.2 predicate |

`CLAIMING` exists so that a concurrent operation on an fd being set up neither observes a half-built
entry nor treats it as absent. A hooked call that finds `CLAIMING` does not wait: for that call the
descriptor reads as untracked, and the call goes to the real function. Only a thread using a number
that `socket()` or a `dup` call has not yet returned can see this. Never a lock, because a signal handler could be
the one waiting.

### 3.2 The association object

Owns the SOCKS5 relationship for one application socket (D-13):

| Field | Purpose |
|---|---|
| `conn` | The control connection — a shim-owned, close-on-exec descriptor (FR-P-02, FR-L-05, D-26) — and the relay's `BND.ADDR`/`BND.PORT` from the `UDP ASSOCIATE` reply (FR-P-01) |
| `refcount` (atomic) | Descriptors sharing this association, plus readers holding a reference (FR-L-03, D-24); 0 on the free list |
| `fork_generation` | Global generation at creation; stale ⇒ inherited across `fork` (§3.4) |
| `last_used` (atomic) | When a datagram last used it, for the idle check before a send (FR-P-08) |
| `next_free` | Free-list link (D-24) |

There is no state field. An entry's `assoc` pointer is `NULL` (none yet), a sentinel meaning
"being established", or the association. An association that turns out to be dead is detached from
the entry and replaced on the next use.

It owns **no data socket** — the application's fd is the data socket (FR-I-07).

Association objects are **type-stable** (D-24): released ones go onto a free list and are never
returned to the allocator, and every reader takes a counted reference through `udpc_assoc_get()`,
which re-checks the entry still points at the object. A thread that loaded the pointer just as
another dropped the last reference therefore reads valid memory, and lets go on finding it
recycled. The datagram path takes exactly one reference per datagram, through `udpc_assoc_hold()`,
and uses it for everything the datagram needs. It stays lock-free. Its control connection is a shim-owned descriptor in
the protected band (§3.3, D-26).

### 3.3 Refcounting, `dup`, and `close`

`dup`/`dup2`/`dup3` point the new fd's entry at the same association and increment the refcount
(FR-L-03). `close` decrements; the association is torn down — control connection closed, which the
proxy takes as the signal to release the association (§0.5) — when the count reaches zero.

`dup2`/`dup3` onto an fd that already has an `ACTIVE` entry replace or release that entry, as the
kernel implicitly closes the target descriptor — but only **after** the call succeeds. Releasing it
first meant a failed call left the target open, still a UDP socket, and untracked (D-21). The same
rule covers every duplication route (`dup`, `dup2`, `dup3`, `fcntl(F_DUPFD)`): if the source is
intercepted, the new descriptor shares its association. Otherwise any stale entry at the new number
is released. A duplicate of an intercepted socket that the table cannot track is closed, and the
call fails with `EMFILE`.

`close_range` releases each entry in the range, visiting only allocated blocks, and honours
`CLOSE_RANGE_CLOEXEC` by marking rather than closing. `closefrom` is `close_range(lowfd, ~0U)`.

**The shim's own descriptors are protected** (D-26). Control connections and the resolver's
sockets are moved into a band from 768 up, and marked `SHIM` in the table. `close()` on one fails
with `EBADF`, `close_range` closes around them, and `dup2`/`dup3` onto one fails with `EBUSY`. A
mark whose cookie no longer matches is stale — the descriptor was closed by a route no hook sees —
and is cleared rather than enforced.

On release the entry is reset before its state returns to `FREE`, so a subsequent socket receiving
the same fd number cannot inherit stale state (FR-L-02). A generation counter once described here as
a guard against reuse was never checked, and has been removed (D-30): the per-call cookie check
(D-23) is what catches an entry that no longer matches its socket.

Release depends on interposing `close()`, and not every program's closes reach it — `dig` closes
through libuv, and 4 of its 64 `close` syscalls arrive at the hook. Those entries are stranded
`ACTIVE` for descriptors the kernel has already freed. Because every caller of `udpc_fd_claim`
passes a descriptor the kernel has *just* allocated, and the kernel never hands out a live
descriptor number, a non-`FREE` entry at claim time is proof of staleness rather than evidence of a
conflict: the slot is released and re-claimed rather than refused (D-17). Refusing it produced a
spurious `EMFILE` and leaked the stranded entry's control connection.

### 3.4 `fork`

A `pthread_atfork` **child** handler bumps a global fork generation, and closes the child's copies of
the parent's control connections (D-31), so the parent's associations end when the parent closes
them rather than when the last child exits. That is all it does: closing descriptors and storing to
memory the child alone owns are safe there. It also clears any "establishing" marker left by a parent
thread that did not survive the fork. Tearing the associations down is deferred to first use.

On the child's next use of an inherited fd, the association's `fork_generation` is found stale and
the association is torn down and re-established (FR-L-04). Closing the inherited `control_fd` in the
child is safe: the parent holds its own descriptor reference, so no FIN is sent and the parent's
association survives.

### 3.5 Concurrency summary

- Datagram path, once a socket's association is up: atomic operations, one `getsockopt` (D-23), no
  locks, no allocation.
- **NFR-03 is partial.** A socket's first send (association setup allocates and handshakes), a
  thread's first datagram (its scratch buffers are allocated), and `socket()`, `dup*()` and
  `close()` (table blocks, association release) all allocate or free memory. Any of those inside a
  signal handler that interrupted `malloc` can deadlock. The steady-state send and receive cannot.
- Mutation path (`socket`, `close`, `dup*`, association establishment): CAS on entry state; block
  allocation via CAS on the top-level slot.
- Association establishment is serialised per entry by the "being established" sentinel in the
  entry's `assoc` pointer, so two threads sending on the same fresh fd produce one association, not
  two (FR-L-01).
- Verified by TST-07 under TSan and ASan (D-07, D-08).

---

## 4. SOCKS5 client

Implemented from RFC 1928 §7 only. See D-01 — reference implementations must not be consulted.

### 4.1 Control connection

On first use of an intercepted socket (FR-P-01):

1. TCP connect to the configured proxy; set `FD_CLOEXEC` immediately (FR-L-05).
2. Method negotiation offering `0x00`, plus `0x02` when credentials are configured. Offering `0x02`
   unconditionally would push a proxy that accepts either into an authenticated exchange the user
   did not ask for, so the offer is conditional (D-20).
3. If the proxy selects `0x02`, the RFC 1929 sub-negotiation. Its version byte is `0x01` — the
   sub-negotiation's own, not SOCKS5's `0x05`. A proxy selecting `0x02` when it was not offered is
   an `EPROTO` protocol violation, not an authentication failure.
4. `UDP ASSOCIATE` request.
5. Take `BND.ADDR`/`BND.PORT` from the reply as the relay. A wildcard, or a loopback address from a
   proxy that is not on this host, is replaced by the proxy's own address (D-16) — both mean "the
   address you already reached me on", and taken literally both send datagrams nowhere.
6. `connect()` the application's fd to the relay, so the kernel filters datagrams from anything else
   and the application's own `send`/`write` reach the relay (FR-I-07).

The control connection stays open for the application socket's lifetime (FR-P-02). It is never read
from except to detect closure; the proxy ties association lifetime to it (§0.5).

**FR-P-05:** the request declares `0.0.0.0:0` unless the application called `bind()` with a concrete
address, in which case that address is declared. Declaring an address the shim will not send from
breaks the association on proxies that pin to the declared address.

### 4.2 Failure is not fallback

If any step fails, the association is not established and the **application's send call fails**
(SEC-01, FR-L-06) with an errno derived from the failure (§6.4). There is no code path from a failed
association to a direct send. This is the single most important invariant in the project (§0.3.1) and
is verified by TST-03 rather than by inspection alone.

### 4.3 Header codec

Per RFC 1928 §7: `RSV(2)=0 | FRAG(1) | ATYP(1) | DST.ADDR | DST.PORT`.

- Encode: `ATYP` `0x01` (IPv4, 4 bytes) or `0x04` (IPv6, 16 bytes) for the normal UDP case where only
  an address is available; `0x03` (length-prefixed domain) when the application supplied a hostname,
  forwarded for proxy-side resolution rather than resolved locally (FR-P-07).
- Decode: all three `ATYP` forms honoured (FR-P-03). The decoded address becomes the source reported
  to the application (FR-F-02).
- `FRAG` is always emitted as `0`; any datagram received with `FRAG != 0` is **discarded** and the
  receive retried, not surfaced as an error (FR-P-04).
- A datagram too short for its declared `ATYP`, or with a domain length exceeding the remaining
  bytes, is discarded as malformed. It is never partially delivered.

### 4.4 Re-association (FR-P-08)

The reference proxy expires an association after 60 s of silence in both directions. On send, if the
control connection is observed closed or the relay send fails in a way consistent with a dropped
association, the shim tears down and re-establishes **once**, then retries the send. A second failure
fails the call (SEC-01). Re-association is transparent — the application sees a successful send, not
an error it must handle.

---

## 5. Data path

### 5.1 Send

All variants funnel into `udpc_core_send` (§2.3). Buffers per D-11: the header is built in a small
thread-local buffer and passed as the first `iovec` to the real `sendmsg`, with the application's
buffers following. **The payload is not copied,** with one exception: an application passing
`IOV_MAX` buffers leaves no room for the header's, so the header and the first buffer are copied
together into one. Scatter/gather (FR-F-10) is inherent.

- Return value is the byte count the application supplied, never the wrapped length (FR-F-01).
- Destination: the `sendto` argument if given; otherwise `app_dst` recorded by `connect()`
  (FR-F-08). Neither present ⇒ `EDESTADDRREQ`.
- Zero-length payloads produce a header-only datagram and are a valid send (FR-F-06).

### 5.2 Receive

All variants funnel into `udpc_core_recv`. The wrapped datagram is read into a thread-local scratch buffer
sized `max_datagram + 262`, the header parsed, and the payload copied into the application's iovecs
(D-11 explains why receive copies and send does not).

- Source address is taken from the header, so the application sees the true origin, never the relay
  (FR-F-02).
- **Truncation (FR-F-04):** because the whole datagram is in scratch, the true payload length is
  known exactly. If the application's buffers are shorter, the excess is discarded and `MSG_TRUNC` is
  set in `msg_flags` for `recvmsg`. `recvmsg` called *with* `MSG_TRUNC` returns the true payload
  length, matching kernel behaviour.
- **`MSG_PEEK` (FR-F-05):** passed through to the real receive, so the datagram stays queued; the
  header is stripped from the scratch copy. A subsequent non-peek receive reads the same datagram and
  yields an identical payload.
- **Zero-length (FR-F-06):** a header-only datagram unwraps to a zero-length payload, returning `0`
   — distinct from "no datagram available", which blocks or returns `EAGAIN`.
- **Ancillary data (FR-F-11):** `msg_control` is returned empty with `msg_controllen` set to zero.
  Relay-derived values would describe a socket the application does not own; see §8 of the
  requirements. `MSG_CTRUNC` is not set, because nothing was truncated — there was nothing.
- Discarded datagrams (`FRAG != 0`, malformed, short) cause a re-read rather than a return, so the
  application never observes them. On a non-blocking socket an exhausted queue then yields `EAGAIN`
  as it would normally.

### 5.3 `sendmmsg` / `recvmmsg` (FR-F-09)

Each message in the vector is processed independently through `udpc_core_send`/`udpc_core_recv`. The return value
is the count of messages processed, with per-message lengths written back into the `mmsghdr` array.
Partial success is reported as the kernel does: if message *k* fails after *k* succeeded, return *k*;
if the first fails, return `-1` with `errno` set. `errno` from a partial success is not clobbered.

### 5.4 Datagram boundaries

One application datagram is exactly one relayed datagram (FR-F-03). The shim never coalesces, never
splits, and never fragments (FR-P-04). A payload exceeding the configured limit fails with
`EMSGSIZE` rather than being split (FR-F-07, D-12).

---

## 6. Policy and fail-closed behaviour

### 6.1 No bypass

Per D-05 there is no bypass path in v1. Every intercepted datagram is proxied or fails. There is no
rule engine and no configuration that permits a direct send.

### 6.2 Multicast and broadcast (D-05 R1)

Destinations in `224.0.0.0/4`, `ff00::/8`, or `255.255.255.255` fail with `ENETUNREACH` plus a
one-line stderr diagnostic naming the reason. SOCKS5 cannot express these destinations.

Note that `setsockopt` is not hooked, so `SO_BROADCAST` and `IP_ADD_MEMBERSHIP` still succeed and the
subsequent send then fails. This is inconsistent-looking but honest; the diagnostic is what makes it
legible.

### 6.3 Loopback guard (D-05 R2)

When a destination is loopback (`127.0.0.0/8`, `::1`) and the configured proxy is not on this host,
emit a diagnostic at association time — `127.0.0.1` is resolved at the *proxy*, so the datagram
reaches the proxy host's loopback, not the application's. Config knob
`strict_loopback` / `UDPCHAINS_STRICT_LOOPBACK` promotes the diagnostic to a hard error.

This matters most for DNS: on a systemd-resolved host the stub resolver is `127.0.0.53:53`, and with
DNS proxied as ordinary UDP (D-04) every lookup hits this path.

### 6.4 `errno` map (FR-F-07)

`errno` is set as the unhooked call would set it. Where the shim originates a failure:

| Condition | `errno` |
|---|---|
| Payload exceeds configured datagram limit, or more than `IOV_MAX` buffers | `EMSGSIZE` |
| Multicast/broadcast destination | `ENETUNREACH` |
| Proxy unreachable / connection refused | as the TCP connect reported: `ECONNREFUSED`, `ENETUNREACH`, … |
| Handshake step exceeds `connect_timeout` | `ETIMEDOUT` |
| Proxy closes the control connection mid-handshake | `ECONNRESET` |
| Authentication refused, no acceptable method, or credentials the proxy rejects | `EACCES` |
| `UDP ASSOCIATE` refused, by reply code (RFC 1928 §6): `0x02` not allowed | `EACCES` |
| `0x03` network unreachable | `ENETUNREACH` |
| `0x04` host unreachable | `EHOSTUNREACH` |
| `0x05` connection refused, `0x01` general failure, or any other code | `ECONNREFUSED` |
| `0x06` TTL expired | `ETIMEDOUT` |
| `0x07` command not supported | `EOPNOTSUPP` |
| `0x08` address type not supported | `EAFNOSUPPORT` |
| Re-association failed after retry | as the underlying failure |
| No destination and socket not connected | `EDESTADDRREQ` |
| Address too short for its family / `NULL` buffer array | `EINVAL` / `EFAULT` |
| Malformed reply from proxy | `EPROTO` |
| Creating a non-UDP datagram socket (ICMP, UDP-Lite) | `EPROTONOSUPPORT` (D-29) |
| A descriptor that cannot be tracked | `EMFILE` |
| `close()` / `dup2()` on a shim-owned descriptor | `EBADF` / `EBUSY` (D-26) |

A failure never falls through to a direct send (SEC-01).

---

## 7. Configuration and the wrapper

### 7.1 Precedence (FR-C-02)

Command line → environment (`UDPCHAINS_PROXY`, `UDPCHAINS_CONFIG`) → config file → built-in default.

**Built-in defaults exist only for optional settings** — maximum datagram size (default 8192, D-12),
verbosity, timeouts, `strict_loopback`. There is **no built-in default proxy address** (D-10). If no
proxy is resolved, the wrapper prints a diagnostic and exits **without exec-ing the target**
(FR-C-03). Configuration is resolved before `exec` so failures are attributable to the wrapper rather
than emitted from inside the target's address space.

### 7.2 Wrapper (FR-C-01)

`udpchains [-f config] [-q] [-v] <program> [args…]`. Resolves configuration, checks it, sets
`LD_PRELOAD`, `exec`s the target.

**setuid/setgid check (SEC-06):** the wrapper `stat`s the resolved target and **refuses to run it**
if `S_ISUID`/`S_ISGID` is set. The loader drops `LD_PRELOAD` for such binaries, so running it would
mean running unproxied — the exact silent-leak failure the project exists to prevent. Refusing is the
only fail-closed option.

**Config permissions (SEC-04):** warn if the config file is group- or world-writable, since it
directs where traffic goes.

**Credentials (SEC-03):** readable from a file or environment variable only, never a command-line
flag, because `argv` is visible in `ps(1)`. The plumbing was built before the protocol exchange
existed (D-08) precisely so that adding authentication later would not tempt anyone into a
`--password` flag; RFC 1929 now consumes it (D-20).

### 7.3 Diagnostics (FR-C-05, FR-C-06, NFR-05)

stderr, prefixed `udpchains:`. Verbosity from `UDPCHAINS_QUIET`/`-q` and `UDPCHAINS_DEBUG`/`-v`.

At default verbosity: **one line per association established**, naming the destination and the
configured datagram limit (the latter so a D-12 mismatch is diagnosable), plus the D-05 R1/R2
diagnostics.

**NFR-05: payload bytes are never written to any log at any verbosity.** Not at `-v`, not at any
debug level, no hex dumps. Lengths, addresses and header fields only.

---

## 8. Non-goals restated

From §8 of the requirements, listed here because they constrain the design: statically-linked
binaries, Go binaries, setuid/setgid targets, system calls made without libc, faithful ancillary data,
GSO/GRO, QUIC performance, TCP proxying. Proxy chains were a non-goal for 0.1.0, and are now §12. D-04 once put the resolver's TCP fallback
outside scope as well; D-22 superseded that, and the shim's own resolver retries over SOCKS5
`CONNECT` (§11). An application's own TCP DNS is still not proxied. The README states these plainly (acceptance criterion 6, D-05 R4).

---

## 9. Test architecture

### 9.1 Fixture proxy (D-06)

A minimal SOCKS5 `UDP ASSOCIATE` server in C, built by the same `make`, test-only and never linked
into the shim. Paired with a trivial UDP echo server for the matrix. Fault-injection modes are listed
in D-06 — the reason the fixture exists rather than being borrowed is that a real proxy cannot be
made to expire an association or inject `FRAG != 0` on demand.

Interop against a real proxy remains a separate manual step (TST-04). A green fixture suite
is not evidence of interop.

### 9.2 Hook matrix (TST-01)

{`sendto`, `send`, `write`, `writev`, `sendmsg`, `sendmmsg`} × {`recvfrom`, `recv`, `read`, `readv`,
`recvmsg`, `recvmmsg`} = 36 cells, each asserting a byte-identical round-trip through the fixture
echo server. This is the primary regression gate and what distinguishes tier 2 from the existing
tools (§0.2). Run for both connected and unconnected sockets, and for IPv4 and IPv6.

### 9.3 Symbol check (TST-02)

`nm -D` asserts every symbol in §2.3 is exported. A missing receive hook **fails the build**, not the
test run. The check is aware of the `close_range` conditional (D-09) so it asserts the right set for
the build configuration.

### 9.4 Leak test (TST-03)

With the proxy stopped, assert **zero** UDP packets reach the destination by any path. Because there
is no bypass (D-05), this is an unqualified assertion with no whitelist — which is the property that
makes it trustworthy.

---

## 10. Build

`make` plus a C compiler, no third-party dependencies, no downloads (NFR-01, acceptance criterion 5).
C11, glibc ≥ 2.34 (D-09), Linux. `-Wall -Wextra -Werror` from the first commit (NFR-06) — cheap now,
painful to retrofit. ASan/UBSan/TSan variants for the test suite (TST-08).

The build fails with a clear message on an unsupported glibc rather than producing a shim with a
silently missing hook (NFR-01a).

---

## 11. Name resolution (D-22)

**Status:** implemented. The policy — what is answered where, and why — is D-22, including the
implementation notes at its end. This section covers how it fits the existing code.

### 11.1 Where it lives

| Module | Role |
|---|---|
| `src/dnshooks.c` | The exported symbols: `getaddrinfo`, `getnameinfo`, `gethostby*`, the `res_*` family and `getaddrinfo_a` (which fails closed). Thin wrappers, in the same spirit as `hooks.c`: every lookup funnels into one function in `resolve.c`. |
| `src/resolve.c` | The lookup order of D-22 (numeric, `localhost`, `/etc/hosts`, DNS), the `/etc/hosts` parser, the association pool, and the UDP and TCP transports. |
| `src/dns.c` | The DNS message codec: builds A, AAAA and PTR queries with an EDNS0 OPT record, and parses answers. Name decompression goes through libc's `dn_expand`/`dn_skipname`. No dependency on `libresolv`. |
| `src/socks5.c` | Gains `CONNECT` (CMD `0x01`) for the TCP fallback, sharing the existing method negotiation and RFC 1929 code with `UDP ASSOCIATE`. |
| `src/config.c` | Gains `dns`, `dns_timeout`, `dns_search` and `hosts_file`, with their `UDPCHAINS_*` variables and export. The wrapper validates `dns` as numeric before `exec` (FR-C-03). |

### 11.2 One lookup

```
getaddrinfo(name, service, hints)
  └─ dnshooks: in the shim (guard held)?   → real getaddrinfo, untouched
     └─ resolve: numeric?                   → real getaddrinfo + AI_NUMERICHOST
        ├─ localhost / *.localhost?         → loopback
        ├─ /etc/hosts match?                → those addresses
        ├─ dns unset?                       → EAI_FAIL + one diagnostic
        └─ take a pooled association        (create if none free, below the cap)
           ├─ send A + AAAA, SOCKS-wrapped, to dns via the relay
           ├─ wait for replies matching ID + question + source, or timeout
           ├─ TC set?                       → SOCKS5 CONNECT to dns, DNS over TCP
           └─ return the association to the pool
     └─ for each address: real getaddrinfo(ip, service, hints | AI_NUMERICHOST); chain
```

### 11.3 The association pool

- Entries are created lazily, up to a small cap (4). A lookup that finds none free waits on a
  condition variable. The resolver path may lock and allocate: `getaddrinfo` is not
  async-signal-safe anyway (D-22).
- Each entry holds its own control connection and UDP socket. Both are the shim's own descriptors,
  created under the re-entry guard with `SOCK_CLOEXEC`, and moved into the protected band (D-26).
- An entry idle long enough to have been expired is re-checked before use, as FR-P-08 does for
  application sockets.
- After `fork`, the child closes its copies of every entry's descriptors at once (D-31), which is
  safe for the same reason as §3.4: the parent holds its own references.

### 11.4 Replies

Datagrams arriving on a pool socket go through the existing SOCKS header decoder
(`udpc_socks_decode`). A reply is accepted only if all of the following hold:

- `FRAG` is 0;
- the SOCKS source is the configured resolver;
- the DNS ID matches the outstanding query;
- the question section echoes the query.

Anything else is discarded, and the wait continues until the deadline. A truncated answer (TC set)
is never used: the whole query is repeated over TCP.

### 11.5 Tests

- A DNS fixture, `tests/fixtures/dnsd.c`, answering A, AAAA, CNAME, PTR, NXDOMAIN and truncated
  responses.
- `CONNECT` support in `socks5d`.
- `tests/test_dns.c`: unit tests for the codec against hostile input.
- `tests/test_resolve.c`, driven by `tests/test_resolve.sh`: integration tests of every hooked
  function under the shim, in four modes: working, no `dns` set, proxy down, and a proxy that
  refuses `CONNECT`. The script counts what reached the fixture resolver, and uses `strace`, when
  installed, to check the process never addressed a resolver directly.
- A new leak-test scenario: with the proxy down, every lookup fails and nothing reaches the host's
  resolver.

---

## 12. Multi-hop chains (FR-P-10)

**Status:** implemented after 0.1.0. The requirements are §2a of the requirements document
(FR-CH-*); the choices are D-37 to D-47. A chain of one is 0.1.0 exactly: the same wire bytes,
errors, diagnostics and environment (FR-CH-01).

### 12.1 Configuration and handoff

`struct udpc_config` keeps hop 1 in its 0.1.0 fields (`proxy`, `username`, `password_file`, ...)
and adds `hops[7]` with a count, `nextra`, for hops 2 to 8 (D-42). The wrapper resolves hop 1
only, as D-27 does for the one proxy; later hops are checked for form and exported as written
(D-39), in `UDPCHAINS_PROXY` as a comma-separated list. Hop *n*'s credentials travel as
`UDPCHAINS_USERNAME_<n>` and the password's location as `UDPCHAINS_PASSWORD_FILE_<n>` or
`UDPCHAINS_PASSWORD_CONFIG_<n>` (D-25, D-38).

A proxychains.conf given to `-f` is read by the same reader (D-47). Its directives are applied,
refused or warned about one line at a time, and each `socks5` line of its `[ProxyList]` fills the
next hop's fields as a `[hop]` section does, so nothing after reading knows which form the chain
was written in. A shim re-reading the file for a password repeats none of the warnings.

### 12.2 Setup

`udpc_socks_associate_chain` (`src/socks5.c`) builds a `struct udpc_socks_chain`: for each hop *k*,
a control connection and the hop's relay.

```
hop 1:  connect(hop 1) → negotiate → UDP ASSOCIATE          → relay[0]
hop 2:  connect(hop 1) → negotiate → CONNECT hop 2
                       → negotiate with hop 2 → UDP ASSOCIATE → relay[1]
hop k:  connect(hop 1) → CONNECT through hops 1 … k−1
                       → negotiate with hop k → UDP ASSOCIATE → relay[k−1]
```

- **Every control connection is a TCP stream to hop 1,** extended by `CONNECT` through the hops
  before hop *k* (FR-CH-03). An *n*-hop chain therefore holds *n* streams and makes
  *n*(*n*+1)/2 negotiations. Each hop is negotiated with its own credentials.
- **A later hop is sent as written**: numeric as `ATYP 0x01` or `0x04`, a name as `ATYP 0x03`, for
  the hop before it to resolve (D-39).
- **Hop *k* ≥ 2 is declared the unspecified address** in its `UDP ASSOCIATE`, in the family of its
  own numeric address, else of the `CONNECT` reply's `BND.ADDR`, else IPv4 (D-44). Its datagrams
  arrive from the previous hop's relay, whose outbound port is not known.
- **The relay fixup is per hop** (D-40). Hop 1 keeps D-16. For hop *k* ≥ 2, a wildcard relay
  means hop *k*'s address as given, which may be a name; a loopback relay is kept only if hop *k*
  was given as a loopback address (`localhost` included). A relay returned as a name is refused at
  every hop.
- **All or nothing** (D-37). A failure at any hop closes the hops already up and fails the call
  with an `errno`, naming the hop (D-43). There is no skip or fallback.
- **Deadline** (D-45). Every wait keeps `connect_timeout`; the whole setup must also finish within
  `chain_timeout`, by default `connect_timeout` × hops for a chain of more than one, and none for
  a chain of one.

### 12.3 Codec

`udpc_socks_encode_chain` writes *n* headers into the per-thread header buffer, which grows to
`UDPC_SOCKS_CHAIN_HDR_MAX`. The outermost, read by hop 1, names `relay[1]`; each one inwards names
the next relay; the innermost names the destination (FR-CH-05). The payload is still sent from
the program's buffer with no copy (D-11).

`udpc_socks_decode_chain` strips the layers outermost first. Every layer but the innermost must
decode, have `FRAG` 0, and name as its source the relay of the next hop, by port alone when that
relay is a name (D-41). A datagram failing any check at any layer is dropped whole; the
diagnostic names the layer and the reason (`enum udpc_socks_drop`). The innermost layer is
handled as 0.1.0 handles its one header. `max_datagram` remains the payload (D-42); receive
buffers grow by the headers.

### 12.4 Association lifecycle

- **An association holds the whole chain.** All *n* control connections are shim descriptors,
  moved and marked (D-26), and a forked child closes all of them (D-31).
- **Liveness** (FR-CH-09): `udpc_socks_chain_alive` checks every control connection. Losing any
  one loses the association, and FR-P-08's re-association rebuilds the whole chain.
- **Descriptor range** (D-46): with *n* descriptors per socket, the range at 768 and up can fill.
  `udpc_fd_shim_adopt` then leaves the descriptor at the number it has, still marked, and warns
  once a second. With none at all, setup fails with `EMFILE`.
- **The loopback guard looks at the exit hop** (D-40): a loopback destination is resolved there,
  so for a chain of more than one it always warns, and `strict_loopback` refuses it.

### 12.5 Name resolution

The resolver's pool entries (§11.3) hold a `struct udpc_socks_chain` in place of one control
connection. Queries are encoded and replies decoded with the chain codec, so every layer of a
reply is checked as in §12.3. An entry idle long enough to have expired is replaced if any hop's
control connection is gone, and a query waits on every control connection as well as the relay. The
TCP fallback's `CONNECT` runs through every hop to the resolver (FR-CH-11).

### 12.6 Diagnostics

The association line names every hop's relay in order (`via relay A, then B, then C`), for
datagram and resolver associations alike. A setup failure names the hop and what failed —
`hop 2 of 3 (10.0.0.5:1080): hop 1's CONNECT to it failed: Connection refused` — at error level,
once a second, with no vaguer line after it (D-43). A dropped datagram names its layer.

### 12.7 Tests

- `unit-chain` (`tests/test_chain.c`) starts its own fixture proxies: setup, per-hop credentials,
  fixup, declared family, deadline, codec and hop-naming diagnostics.
- `tests/run.sh` runs the matrix, fidelity, port-switch, lifecycle and thread tests again through
  2- and 3-hop fixture chains (FR-CH-T2).
- `test_leak.sh` and `test_failclosed_capture.sh` repeat the leak test with each hop of a 3-hop
  chain dead (FR-CH-T1), for datagrams and lookups.
- `test_faults.sh` adds expiry at a middle hop, `FRAG` at a middle and the innermost layer, a
  forged inner source, a hop refusing `CONNECT`, and a full descriptor range (FR-CH-T3, FR-CH-10).
- `make interop` builds chains of the seven real proxies (FR-CH-T4,
  [`INTEROP-CHECKLIST.md`](INTEROP-CHECKLIST.md) §13).

---

## 13. Supervisor mode (FR-SV-*), in progress

**Status:** step 6 of [`FUTURE-STATIC-BINARIES.md`](FUTURE-STATIC-BINARIES.md) §7. The decisions are
D-48 to D-54, the requirements §2b. The supervisor carries a static program's UDP through the
proxy or chain, from sockets it makes in a reserved range. Calls on those sockets are carried
while their thread is stopped by `ptrace`, so a signal can never part what was done for a call
from what it returns (D-54). Threads, `fork`, `vfork`, `clone` and `exec` are followed (step 5), and
queries to the system resolver are redirected to `dns` (step 6, D-52). Not yet: aarch64.

### 13.1 Where it lives

Linked into the wrapper only, never into the shim:

| File | Holds |
|---|---|
| `supervise.c` | the filter, start-up, the loop, exit status and signals |
| `svtrace.c` | the program's threads under `ptrace`: each stop, the native wait of a receive, signals handed back, group-stops (D-54) |
| `svcall.c` | answering each call, notified or traced: `socket()`, sends, receives, names, the `dup` family, refusals |
| `svsock.c` | the sockets the supervisor carries, their associations, and the sweep for closed ones |
| `svdns.c` | which addresses are the system resolver: loopback, and `/etc/resolv.conf`'s nameservers (D-52) |
| `svint.h` | what the four share |

The supervisor reuses the SOCKS5 client and chain codec (`socks5.c`), and the datagram rules both
front ends apply (`dgram.c`): the multicast and broadcast refusal, `MSG_MORE` and GSO, the loopback
guard, and the checks and stripping of a received datagram's headers (D-41).

`udpchains --supervise` (or `supervise = yes`, or `UDPCHAINS_SUPERVISE=1`, D-49) resolves the
configuration as usual and removes `libudpchains.so` from `LD_PRELOAD`. If the shim was there, it
is already loaded into `udpchains` itself, so `udpchains` runs itself again without it first. It
then calls `udpc_supervise()` with the configuration, password included, instead of `exec`: the
supervisor, not the program, speaks to the proxy.

### 13.2 Start-up

```
wrapper: kernel ≥ 5.14? inherited UDP/raw/packet socket?        → refuse (D-53, D-50)
         the range's start: 768, or half the soft RLIMIT_NOFILE below 1024
         block forwarded signals + SIGCHLD; signalfd; subreaper
         fork
  child: restore the signal mask; no_new_privs
         seccomp(SET_MODE_FILTER, NEW_LISTENER) → listener
         tell the parent the listener's number; wait for its ack
         close the listener; exec the program
 parent: pidfd_open(child); pidfd_getfd(listener) → its own copy
         PTRACE_SEIZE(child): seccomp stops, syscall-exit stops, threads,
           forks and execs followed, EXITKILL                    (D-54)
         ack
         raise its own RLIMIT_NOFILE to the hard limit, for control connections
         serve until no supervised process is left; the exec's errno, if it
           fails, arrives on the pipe meanwhile
```

Every failure before the `exec` refuses to run the program (FR-SV-02): no seccomp, a filter the
kernel or a container refuses, a listener the parent cannot copy (Yama `ptrace_scope` above 1), or
a child it cannot trace (already traced, as under `strace -f`, or `ptrace` forbidden). The program
never holds the listener: it is closed before the `exec`, and close-on-exec besides. The pipe is
read inside the loop rather than waited on, since a signal reaching the traced child before its
`exec` stops it until the loop hands the signal on.

### 13.3 The filter

Built at run time, x86-64 only so far, by a small assembler that resolves forward jumps to labels.
A call from another ABI, or with `__X32_SYSCALL_BIT`, fails with `ENOSYS` in the kernel. Traced
(`SECCOMP_RET_TRACE`, D-54):

- when the descriptor is in the range: `read`, `write`, `readv`, `writev`, `preadv2`, `pwritev2`,
  `recvfrom`, `recvmsg`, `recvmmsg`, `bind`, `getsockname`, `getpeername`, `close`, `dup`;
- always: `connect`, `sendto`, `sendmsg`, `sendmmsg`, `sendfile`, `splice`, `io_uring_setup`,
  `pidfd_getfd`;
- `socket()` for `AF_INET`, `AF_INET6` and `AF_PACKET`; `dup2` and `dup3` from or to the range;
  `close_range` reaching it; `fcntl`'s `F_DUPFD` and `F_DUPFD_CLOEXEC` of a descriptor in it.

Notified (`SECCOMP_RET_USER_NOTIF`): `socket()`, `dup()` and `fcntl(F_DUPFD*)` carrying the
install mark (`SV_INSTALL_MARK`) in their sixth argument, which they do not use. The supervisor
sets it at a traced call's stop when the call must install a descriptor, and the re-check the
kernel makes after the stop sends the marked call by notification, the only way to install one
at a chosen number.

Everything else runs in the kernel, so file and TCP I/O below the range never reaches the
supervisor, nor does any other `fcntl`. With no tracer attached, a traced call fails with `ENOSYS`
and never runs (`seccomp(2)`). The assembler refuses a jump to a label placed before it, as BPF
jumps only forward, and the kernel then refuses the empty filter. `pread64`, `pwrite64`, `preadv` and `pwritev` are not sent: the kernel refuses them on
a socket itself. A descriptor is compared unsigned, so a negative one counts as in the range and
gets the kernel's own `EBADF`.

### 13.4 The sockets it carries

A UDP `socket()` is made by the supervisor, in its own process, keeping `SOCK_NONBLOCK`. The
supervisor finds the lowest free number at or above the range's start in the caller's process,
asking for each in turn with `pidfd_getfd`, and installs the socket there while answering the call
(`SECCOMP_ADDFD_FLAG_SETFD | SECCOMP_ADDFD_FLAG_SEND`). Its own descriptor is then closed: the
program's is the only one kept open (FR-SV-05), so closing it frees the port as natively.

Each socket's entry (`struct sv_sock`) is keyed by the kernel's socket cookie. It holds the family,
the destination the program connected to, the address it bound, and the association: the chain,
each hop's control connection in the supervisor, and the time of last use (FR-P-08). Every call on
a descriptor in the range starts with a fresh copy of it (`pidfd_getfd`) and its cookie, so a
`dup`, a `fork`, an `exec` or a passed socket all find the same entry, and a closed and reused
number is never mistaken for the socket that was there.

The program's own socket is pointed at hop 1's relay when the association is set up, through the
supervisor's copy (the same open file), so replies arrive on it and `poll`, `select` and `epoll`
work unaided (FR-I-07).

**The sweep.** The kernel does not say when the last descriptor for a socket closes. 200 ms after
a `close`, `close_range`, `dup2` or `dup3` in the range, a child's exit or an `exec`, and every 5 s
while any socket is carried, the supervisor lists `/proc`, picks its descendants by their parent
links, and reads the socket inodes in their descriptors at or above the range's start. It reads
the tables of their threads with tables of their own too (`/proc/<pid>/task/<tid>/fd`, for each
thread `kcmp(KCMP_FILES)` says differs). An entry nothing holds has its association closed. If a
table cannot be read, nothing is forgotten that time.

**Which table.** A call names its thread. Its descriptors are looked up through a pidfd for its
process, kept in a small cache. A thread whose table is not its process's (`unshare(CLONE_FILES)`,
as `kcmp` tells) is reached through a pidfd for the thread itself (`PIDFD_THREAD`, Linux 6.9),
opened for the call. Before 6.9, its calls that need its table are refused with `EPERM` (D-50).

### 13.5 Answering

One call at a time, in one thread, through the same code whichever way it came (`decide()` in
`svcall.c`). Before using anything read from a notified call's memory or descriptors, the
supervisor checks the notification is still pending, so a call the program abandoned, or a thread
number reused, is never acted on. A traced call's thread is stopped until the supervisor resumes
it, so it cannot be abandoned.

**A traced call** (`svtrace.c`) stops its thread at its entry. The supervisor reads its registers,
decides it, and then:

- **skips it, returning a result:** the call number set to -1 and the result where a result goes;
- **lets it run** as the program made it: `close`, `close_range`, `dup2` and `dup3` into the range,
  calls below the range on anything but a UDP socket it did not make, and calls on a descriptor in
  the range that it does not carry;
- **makes it again,** after any signal waiting has been handled, by stepping back over the
  two-byte `syscall` instruction: when an association's setup was abandoned for a signal;
- **lets a receive wait natively,** when nothing is queued and the call may block. The call is
  rewritten as a zero-length `recvfrom(fd, NULL, 0, MSG_PEEK | MSG_TRUNC)` on the same
  descriptor, and the thread resumed until the call returns (`PTRACE_SYSCALL`). The peek blocks
  until a datagram is queued, takes nothing, and has the receive's own `SO_RCVTIMEO`, `EINTR` and
  `SA_RESTART`. Linux checks the rewritten call against the filter again; on the same descriptor
  it is traced again, and runs. When it returns, the program's registers are put back, call number
  included. The datagram is then taken and delivered while the thread is stopped; if another
  reader took it, the call is made again. Otherwise the peek's own result stands, and a restart is
  the kernel's, of the program's own call.

- **installs a descriptor through a notification:** a UDP `socket()`, and a `dup` or `F_DUPFD` of
  a carried socket. It saves the thread's signal mask and blocks every signal
  (`PTRACE_GETSIGMASK`, `PTRACE_SETSIGMASK`), sets the install mark, and resumes the thread until
  the call returns. The marked call is then notified, and answered as below with
  `SECCOMP_ADDFD_FLAG_SETFD | SECCOMP_ADDFD_FLAG_SEND`. At the exit stop the program's registers
  and mask are put back. If the call was interrupted before it was answered -- by `SIGSTOP`, or a
  signal pending from before the mask was set -- nothing was installed, and it is made again.

**Abandoning a setup.** While a traced call sets up an association, the SOCKS client's waits are
cut into 50 ms slices (`udpc_socks_set_cancel`). Between slices the supervisor reads the thread's
`/proc/<tid>/status`. A signal pending for the thread or its process, not blocked, and not
ignored either explicitly or by default, abandons the setup with `EINTR`. The call is then made
again, so the signal is handled at once and nothing has been sent.

- **`socket()`:** raw and packet sockets `EPERM`, ICMP and UDP-Lite `EPROTONOSUPPORT`; UDP as
  above; anything else continues. Its arguments are values, so continuing cannot be raced.
- **Sends** on a carried socket: the message header, iovecs, address and control data are read
  with `process_vm_readv`, checked as in shim mode (`EMSGSIZE`, `EDESTADDRREQ`, multicast,
  `MSG_MORE`, GSO), wrapped, and sent on the supervisor's copy to the relay, never blocking the
  supervisor for long. `sendmmsg` reports partial success as the kernel does.
- **Receives** on a carried socket (D-54), while the thread is stopped: peek, check and strip
  every layer, write the payload, sender and message fields into the program, and consume.
  `recvmmsg` takes as many as are queued, up to its `vlen`. With nothing queued, a non-blocking
  receive gets `EAGAIN`; a blocking one waits natively, as above. A buffer that cannot be written
  loses the datagram, as natively.
- **`connect`, `bind`, `getsockname`, `getpeername`** on a carried socket: as the shim answers
  them (FR-F-08, FR-P-05, FR-I-05). `bind` is performed on the supervisor's copy, so the address
  checked is the one bound.
- **The `dup` family:** `dup` and `F_DUPFD` of a carried socket are installed in the range;
  `dup2` and `dup3` of one below the range are refused with `EPERM`.
- **Any other descriptor:** a UDP, raw or packet socket the supervisor did not make is refused for
  anything that would send, connect or move data, with `EPERM` (`EINVAL` for `sendfile` and
  `splice`). Anything else continues. A descriptor that cannot be classified is refused; when the
  kernel denies the access, as for a non-dumpable process, the diagnostic says so (D-48).
- `io_uring_setup` `ENOSYS`, `pidfd_getfd` `EPERM`.

Each refusal is reported once a second for each reason (D-33). Each association is reported as in
shim mode, naming the process and descriptor (FR-C-06).

### 13.5a Name lookups (D-52)

The program's own resolver runs. In a send on a carried socket (`send_one`), a destination that
`svdns_system_resolver()` says is the system resolver is replaced by `dns`. It is the system
resolver if it is port 53 of a loopback address, or of a `nameserver` in `/etc/resolv.conf`,
re-read when its device, inode, size or time changes. The address the program sent to is kept
with the socket. With `dns` unset the send fails with `ENETUNREACH`.

- `peer_of()` gives a socket connected to the system resolver `dns` as its peer, so the
  connected-peer check accepts `dns`'s replies (`udpc_dgram_unwrap`).
- `deliver()` reports a reply from `dns` as from the address the program asked.
- The loopback guard checks `dns`, where such a socket's datagrams go.
- In `decide_other`, a `connect()` of an inet stream socket to the system resolver's port 53, or a
  `sendto()`/`sendmsg()` naming it with `MSG_FASTOPEN`, goes to `dns_over_tcp()`. On a TCP socket
  in `TCP_CLOSE` (`TCP_INFO`), it connects the supervisor's copy of the program's socket to hop 1
  and makes the SOCKS5 `CONNECT` to `dns` through the chain (`udpc_socks_connect_on`, which makes
  the socket non-blocking for the handshake and restores its flags), then answers 0, or, for Fast
  Open, sends the call's data on it and answers the count. The program then uses the socket
  natively. A failure dissolves the connection (`connect(AF_UNSPEC)`) and returns its error; a
  signal does the same, and the call is made again (D-54). A socket in any other state goes to the
  kernel. A stream socket that is not TCP is refused with `ECONNREFUSED`; with `dns` unset,
  `ENETUNREACH`.

### 13.6 Exit and signals

- **Signals** sent to `udpchains` by another process — `SIGHUP`, `SIGINT`, `SIGQUIT`, `SIGTERM`,
  `SIGUSR1`, `SIGUSR2`, `SIGALRM`, `SIGWINCH` — are forwarded to the program. One from the
  terminal (`si_code` `SI_KERNEL`) is not: the terminal has sent it to the program already.
- **The program's signals** stop it, as its tracer's, before they are delivered. Each is handed
  back unchanged. A group-stop (`SIGSTOP`, `SIGTSTP`, `SIGTTIN`, `SIGTTOU`) is held with
  `PTRACE_LISTEN`, so the program stays stopped until `SIGCONT`, as unsupervised. A stop reported
  for a new thread or process, or at the end of a group-stop, is simply continued.
- **Stops and exits** both arrive as `SIGCHLD`, on the signalfd. `svtrace_reap()` takes each with
  `waitpid(-1, WNOHANG | __WALL)`. A stop is handled, and an exit asks for a sweep.
- **If the supervisor dies,** `PTRACE_O_EXITKILL` kills every traced process with it. So it
  ignores `SIGPIPE`, set after the fork so the program keeps its own disposition: a write to a
  proxy that has reset the connection, or to a stderr whose reader has gone, fails with `EPIPE`
  instead of killing both.
- **Descendants.** The supervisor is a child subreaper, so a descendant the program leaves running
  becomes its child, and stays supervised. It serves until the listener reports end of file, or
  no child is left.
- **Status.** It exits with the program's status; if the program was killed by a signal, the
  supervisor dies of the same one, with core dumps off, so a shell sees what it would have seen.
  Waiting for that status, it reaps every traced thread (`waitpid(-1, __WALL)`), since a traced
  leader's exit is not reported until its other threads' have been.

### 13.7 Tests

- `unit-supervise`: the kernel-floor check against release strings of several distributions.
- `FR-SV-supervise` (`tests/test_supervise.sh`): exit statuses and death by signal; the filter
  present and the shim absent; the flag, the setting and the variable; the shim in an inherited
  `LD_PRELOAD` not wrapping twice; signals forwarded and handled; a descendant waited for and
  supervised; a static probe checking every refusal, the x32 and 32-bit ABIs, and that TCP, Unix
  sockets and files work; a non-dumpable process refused its connect and UDP socket, with the
  cause named, while files and pipes work; a static probe (`test_supervise range`) for the range,
  the `dup` family, names, refused sends, receives that wait, time out and are interrupted,
  `poll`, and a socket inherited across `fork`, including by a child that outlives the parent's
  descriptor; 40 sockets used and closed, after which the supervisor holds no control
  connection; the signal tests (`test_supervise signals`, FR-SV-T4): receives under storms of
  signals with and without `SA_RESTART` losing nothing and sends never failing with `EINTR` or
  repeated, `SO_RCVTIMEO` and `SIGSTOP`/`SIGCONT` as signal(7) describes them, 2,000 `close`s
  under a storm none left open, `fcntl(F_GETFD)` never interrupted, 2,000 UDP `socket()`,
  `F_DUPFD`, `close_range` and TCP sends under a storm never failing with `EINTR` and leaving no
  descriptor behind, and the program traced by
  `udpchains` and refused `PTRACE_TRACEME`; a signal during a hung handshake handled at once and
  the send made again (`test_supervise abandon`, against `test_supervise silent`), and `SIGTERM`
  then ending the program at once; the program killed with the supervisor; a refusal to start
  under `strace -f`; the lifecycle probe (`test_supervise lifecycle`, FR-SV-11, FR-SV-T3):
  threads each with a socket, four waiting on one, threads under a storm of signals, a thread with
  its own table (its socket placed by its own table, and a socket only it holds kept by the sweep),
  `clone(CLONE_FILES)`, `close_range` with and without `CLOSE_RANGE_CLOEXEC`, `posix_spawn`, `exec`
  from the first thread and from another, and the close-on-exec socket's association let go after
  an `exec`; the leak client, static and dynamic, against a dead proxy sending nothing; a UDP
  socket received from an unsupervised process refused on every send route but D-50's `write()`
  gap, which delivers its one byte; and an inherited UDP socket refusing the run.
- `FR-SV-T1-matrix`: the hook matrix, built `-static`, under the supervisor, directly and through
  two hops.
- `FR-SV-fidelity`: TST-05 built `-static`, checking the two documented differences as such:
  `recvmmsg` returns the datagrams already queued without waiting for more, and stdio on a UDP
  socket is carried.
- Under ASan and UBSan in `run_sanitizers.sh`: the script, and the static matrix and fidelity
  tests, with the supervisor instrumented.
- The DNS probe (`test_supervise dns`, under `dnsd` as `dns`, and `nodns`), with `dnsd`'s log
  showing the redirected queries arrived, by UDP and by TCP, and the one to port 53 elsewhere did
  not. The same probe through a chain of two, whose second hop logs the `CONNECT`s;
  `dnsrefused`, through a proxy that refuses `CONNECT`, with no TCP query reaching `dnsd`; and
  `tcpabandon`, a signal during the tunnel's setup with the silent proxy. A static Go client
  (`tests/goclient`, built when Go is installed), its own resolver included, by UDP and by TCP.
- `make interop`: the static matrix, fidelity, DNS and Go programs supervised, through each of the
  seven proxies.
- By hand, as root, `tests/test_failclosed_capture.sh` (FR-SV-T2): the static probe unsupervised
  as a positive control, then supervised with the proxy unreachable, refusing `ASSOCIATE`, and
  each hop of three dead, and `udpchains` killed while the program sends through a proxy that
  drops every datagram; no packet to the destination on the wire in any.

# Design — `udpchains`

How the shim is built. Requirements live in [`UDP-PRELOAD-REQUIREMENTS.md`](../UDP-PRELOAD-REQUIREMENTS.md);
the choices behind this design and their rationale live in [`DECISIONS.md`](../DECISIONS.md).
Requirement IDs are cited inline so [`TRACEABILITY.md`](TRACEABILITY.md) can map each one to a section
here.

**Status:** as built in 1.0.0. Where the first draft changed, the decision record that changed it is
cited.

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
| Lifecycle via `syscall()` | `syscall` — only its `close`, `close_range`, `dup`, `dup2`, `dup3`, `fcntl` and `socket` numbers, routed to the hooks above; every other number goes straight to the kernel (D-23) |
| Introspection | `getpeername`, `getsockname` |

The fortified variants are what a `_FORTIFY_SOURCE` build calls in place of `recvfrom`, `recv` and
`read`. glibc implements them with internal calls that no preload can see, so they are hooked
separately and funnel into the same receive path. `fcntl` is hooked only for `F_DUPFD` and
`F_DUPFD_CLOEXEC`, which duplicate a descriptor exactly as `dup` does; every other command passes
through.

A UDP socket can also enter the process without passing through any of these hooks: it can be
inherited across `exec`, or received as `SCM_RIGHTS` ancillary data. Inherited sockets are adopted at
start-up, from `/proc/self/fd` or, without `/proc`, by probing the descriptor table. Received
sockets are adopted by the `recvmsg`/`recvmmsg` hooks before the call returns. A socket that cannot
be tracked is closed, never left to send directly (D-21).

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
binaries, Go binaries, setuid/setgid targets, direct `syscall()` users, faithful ancillary data,
GSO/GRO, QUIC performance, TCP proxying, proxy chains. D-04 once put the resolver's TCP fallback
outside scope as well; D-22 superseded that, and the shim's own resolver retries over SOCKS5
`CONNECT` (§11). An application's own TCP DNS is still not proxied. The README states these plainly (acceptance criterion 6, D-05 R4).

---

## 9. Test architecture

### 9.1 Fixture proxy (D-06)

A minimal SOCKS5 `UDP ASSOCIATE` server in C, built by the same `make`, test-only and never linked
into the shim. Paired with a trivial UDP echo server for the matrix. Fault-injection modes are listed
in D-06 — the reason the fixture exists rather than being borrowed is that a real proxy cannot be
made to expire an association or inject `FRAG != 0` on demand.

Interop against the real `dtun-client` remains a separate manual step (TST-04). A green fixture suite
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

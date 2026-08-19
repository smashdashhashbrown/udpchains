# udpchains

An `LD_PRELOAD` shim that routes a dynamically-linked program's **UDP** traffic through a SOCKS5
proxy supporting `UDP ASSOCIATE` — transparently, without modifying or recompiling the program.

```
udpchains -p 127.0.0.1:1080 dig @9.9.9.9 example.com
```

## Why

`proxychains` is the standard tool for forcing an unmodified program through a proxy, and it is
**TCP-only**. Programs that use UDP get no proxying — and, critically, no error either: the traffic
silently goes direct. Any workflow that assumes "I ran it under proxychains, therefore it went
through the proxy" is wrong for UDP.

`udpchains` carries UDP, and **fails closed**: if a datagram cannot be proxied, the call fails with
an appropriate `errno`. It never falls back to sending directly. There is a test for exactly this —
with the proxy stopped, zero packets reach the destination by any path.

## Build and install

No dependencies beyond a C compiler. Linux, glibc ≥ 2.34.

```sh
make
sudo make install          # /usr/local/bin/udpchains, /usr/local/lib/libudpchains.so
```

Run the suite:

```sh
make test                  # unit + integration, against an in-repo fixture proxy
tests/run_sanitizers.sh    # ASan/UBSan, TSan, Valgrind, Helgrind
```

## Usage

```
udpchains [options] <program> [args...]

  -f <file>    config file
  -p <addr>    proxy as host:port or [v6]:port
  -q           quiet: errors only
  -v           verbose: protocol steps (never payload)
```

Configuration is read from, in precedence order: command line, environment, config file. **There is
no built-in default proxy** — if none is configured, `udpchains` prints a diagnostic and refuses to
run the program rather than running it unproxied.

| Environment | Meaning |
|---|---|
| `UDPCHAINS_PROXY` | `host:port` of the SOCKS5 proxy |
| `UDPCHAINS_CONFIG` | config file path |
| `UDPCHAINS_MAX_DATAGRAM` | maximum payload, default 8192 |
| `UDPCHAINS_STRICT_LOOPBACK` | make the loopback warning below an error |
| `UDPCHAINS_CONNECT_TIMEOUT` | proxy connect timeout in ms |
| `UDPCHAINS_USERNAME`, `UDPCHAINS_PASSWORD_FILE` | credentials (see below) |

Config file:

```ini
# ~/.udpchains.conf
proxy = 127.0.0.1:1080
max_datagram = 8192
strict_loopback = no
```

Credentials are never accepted on the command line, because `argv` is visible in `ps`. Use a file or
the environment. (SOCKS5 username/password authentication itself is not implemented in v1 — see
below.)

## What does not work

This section is the honest part. Read it before deciding whether this tool suits your problem.

### Programs it cannot help at all

| | Why |
|---|---|
| **Statically-linked binaries** | No libc to interpose on. Unfixable by this approach. |
| **Go binaries** | Go issues raw syscalls, bypassing libc entirely. Unfixable by this approach. |
| **setuid/setgid binaries** | The loader ignores `LD_PRELOAD` for them. `udpchains` detects this and **refuses to run them** rather than running them unproxied. Binaries with file capabilities are refused for the same reason. |
| **Programs calling `syscall()` directly** | Same reason. `ptrace`-based interception is the only answer, and is out of scope. |
| **Programs using raw sockets** | `SOCK_RAW` is not intercepted, and SOCKS5 has no way to carry a raw IP packet. Such traffic goes **direct** — see the warning below. `nmap`, `traceroute` and similar tools are in this category. |

### Traffic it deliberately refuses

**There is no bypass in v1.** Every intercepted datagram is either proxied or fails. That is what
makes the leak test meaningful — a bypass rule set would need its own list of expected direct
traffic, and that list is exactly where a leak hides.

> **The one exception, and it is a real one: raw sockets.** The shim intercepts `SOCK_DGRAM` in
> `AF_INET`/`AF_INET6` and nothing else. A program that opens a `SOCK_RAW` socket gets unproxied
> network access, with no diagnostic and nothing in the logs — the shim never sees it. SOCKS5 cannot
> express a raw IP packet, so there is no honest way to proxy it, but "cannot proxy" should mean
> "refuse", and today it means "pass through". Raw sockets need `CAP_NET_RAW`, so this is not
> reachable by an ordinary unprivileged program — but if you are relying on this tool to guarantee
> that a **privileged** process cannot reach the network directly, it does not. Deferred rather than
> dropped; refusing raw socket creation the way multicast and broadcast sends already fail is the
> obvious v2 change.

Consequences you will actually notice:

- **Local UDP services break or reach the wrong host.** `127.0.0.1` in a SOCKS5 request is resolved
  *at the proxy*, so a datagram addressed to a local daemon is delivered to the **proxy host's**
  loopback. With a proxy on the same machine this works and looks correct; with a remote proxy it
  fails, or worse, succeeds against a different machine's daemon. `udpchains` warns when it sees a
  loopback destination and the proxy is not local; `strict_loopback` turns that warning into an
  error. Affected: statsd/DogStatsD on 8125, syslog over UDP, a local `chrony`, and
  `systemd-resolved` at `127.0.0.53`.

- **Service discovery hard-fails.** mDNS (5353), SSDP (1900), LLMNR, DHCP broadcast, NetBIOS. SOCKS5
  cannot express a multicast or broadcast destination, so these fail with `ENETUNREACH` and a
  diagnostic naming the reason. Note that `setsockopt(SO_BROADCAST)` and `IP_ADD_MEMBERSHIP` still
  *succeed* — those are not hooked — and the subsequent send is what fails.

- **The datagram size ceiling applies everywhere**, including to loopback traffic that would
  otherwise carry up to 64 KB. Payloads over `max_datagram` (default 8192) fail with `EMSGSIZE`
  rather than being silently dropped or fragmented.

### Behaviour that is deliberately approximate

- **DNS is proxied as ordinary UDP**, with no special case: glibc's resolver uses UDP through libc,
  so it is intercepted like anything else. No DNS leak. Two consequences: each resolution burst
  creates its own association, and **resolver TCP fallback is not proxied** — when an answer is too
  large for UDP and glibc retries over TCP, that traffic is outside this project's scope. Compose
  with `proxychains-ng` if you need both.

- **The proxy's own hostname is resolved directly** if you configure it by name rather than by
  address. Configure a numeric address if that matters to you.

- **Ancillary data (`msg_control`) is returned empty.** `IP_PKTINFO`, `IP_RECVERR`, ECN and friends
  would describe a socket the application does not actually own, and there is no honest emulation.
  A program that depends on them will misbehave, and the cause will not be obvious — this is the
  most likely source of a confusing failure.

- **A socket closed by a route that bypasses libc keeps its association until the descriptor number
  is reused.** The shim releases its per-socket state from the `close()` hook, and not every runtime
  goes through it — `dig`, via libuv, makes 64 `close` syscalls of which 4 reach the hook. A stranded
  entry is detected and recycled when the kernel hands the same descriptor number to a new socket
  (D-17), so nothing breaks; but a program that closes such a socket and never reuses the number
  holds that association open until it exits. Bounded by the number of UDP sockets opened, not
  unbounded, and invisible in normal use.

- **After `fork()`, a child that keeps using an inherited UDP socket gets a fresh socket.** The child
  must not share the parent's association, and parent and child share one open file description, so
  the child's socket is replaced with a private one. `O_NONBLOCK`, close-on-exec and a concrete
  `bind()` are carried over; other socket options are not.

- **GSO/GRO (`UDP_SEGMENT`, `UDP_GRO`) are not supported.** Modern QUIC stacks use them and will fall
  back or fail. Even when QUIC works, a UDP flow through a TCP-based tunnel inherits
  retransmit-and-wait behaviour that fights QUIC's own loss recovery.

- **TCP is not proxied.** `proxychains-ng` already does that well. Composing the two is fine.

### Protocols that depend on your proxy's inbound policy

Some protocols have the server reply from a **different port** than the one it was addressed on —
TFTP most visibly, and also SIP/RTP and various game protocols. Whether these work is decided by the
proxy, not by udpchains:

| Proxy inbound policy | Result |
|---|---|
| Port-restricted — only accept from an `address:port` already sent to | These protocols **fail**. The reply is dropped at the proxy and never reaches the shim. |
| Address-restricted — accept from any port at a host already sent to | They work. This is the usual middle ground. |
| Association-scoped — accept anything once associated | They work, but the relay is effectively open. |

A port-restricted proxy is a defensible choice: it stops the relay being used as an open reflector,
and RFC 1928 does not require otherwise. But the failure is invisible from the client side — the
send succeeds, the association stays healthy, and nothing arrives. If a protocol like this hangs
after the first exchange, check the **proxy's** logs for dropped inbound datagrams before suspecting
the shim. `udpchains -v` will show the request leaving with the correct destination and `ATYP`, which
is usually enough to place the fault at the far end.

Note that udpchains applies its own filter only for sockets the application has `connect()`-ed, and
only to match what the kernel does natively (D-15). An unconnected socket — which is what TFTP
clients use, precisely because of the port switch — is not filtered by the shim at all.

### Not implemented in v1

- SOCKS5 username/password authentication (RFC 1929). The credential plumbing exists; the protocol
  exchange does not. A proxy requiring authentication will be refused with a clear message.
- `proxychains.conf`-style `[ProxyList]` config. A `[ProxyList]` line produces a message pointing
  here rather than a generic parse error.
- Proxy chains (multi-hop UDP).
- Loopback and multicast bypass. Deferred rather than dropped; see `DECISIONS.md` D-05.

## How it works

The shim interposes on libc's socket calls and **redirects the application's own descriptor to the
proxy's relay**. There is no shadow socket, which is why `poll`, `select`, `epoll` and every socket
option keep working untouched — they are not hooked, and must not be.

On first use of a UDP socket the shim opens a TCP control connection to the proxy, negotiates, and
issues `UDP ASSOCIATE`. Outbound datagrams get an RFC 1928 §7 header prepended; inbound ones have it
parsed and stripped, so the application sees the true source address and its own byte counts.

Every send variant funnels into one send path and every receive variant into one receive path. That
is deliberate: it makes it structurally hard to ship a version where a program can send successfully
but read back data with the SOCKS header still attached. A 36-cell test matrix
(`{sendto, send, write, writev, sendmsg, sendmmsg} × {recvfrom, recv, read, readv, recvmsg,
recvmmsg}`) asserts byte-identical round-trips, across IPv4 and IPv6, connected and unconnected.

Per-descriptor state lives in a lock-free two-level radix table: no allocation, no locks and no
syscalls on the datagram path, so a send from a signal handler cannot deadlock.

## Documentation

| | |
|---|---|
| [`UDP-PRELOAD-REQUIREMENTS.md`](UDP-PRELOAD-REQUIREMENTS.md) | the requirements baseline, unmodified |
| [`DECISIONS.md`](DECISIONS.md) | every design decision, with consequences and revisit conditions |
| [`docs/DESIGN.md`](docs/DESIGN.md) | how it is built |
| [`docs/TRACEABILITY.md`](docs/TRACEABILITY.md) | every requirement mapped to design section and test |
| [`docs/INTEROP-CHECKLIST.md`](docs/INTEROP-CHECKLIST.md) | manual tests against a real proxy, and what each one proves |

## Licence

MIT — see [`LICENSE`](LICENSE).

Implemented clean-room from RFC 1928 §7 and the relevant man pages. `proxychains-ng` and `Proxando`
are cited in the requirements as evidence about their *behaviour*; no code was taken from either, and
contributions must not derive from them — both are GPL-2.0, and doing so would silently relicense
this project.

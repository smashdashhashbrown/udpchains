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
with the proxy stopped, zero packets reach the destination by any of the send paths it exercises.
A few routes the shim cannot see are listed under
[Traffic it deliberately refuses](#traffic-it-deliberately-refuses).

## Build and install

No dependencies beyond a C compiler. Linux, glibc ≥ 2.34.

```sh
make
sudo make install          # bin/udpchains, lib/libudpchains.so, man1/udpchains.1
man udpchains
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

**Set a DNS resolver too, if the program looks up names.** Name lookups go through the proxy to the
resolver named by `dns` (`UDPCHAINS_DNS`), and there is no default. Without one, the program still
runs, but any lookup that needs DNS fails. See [Name resolution](#name-resolution).

```sh
udpchains -p 127.0.0.1:1080 dig @9.9.9.9 example.com              # no dns needed: dig asks 9.9.9.9 itself
UDPCHAINS_DNS=9.9.9.9 udpchains -p 127.0.0.1:1080 nc -u example.com 53
```

| Environment | Meaning |
|---|---|
| `UDPCHAINS_PROXY` | `host:port` of the SOCKS5 proxy |
| `UDPCHAINS_CONFIG` | config file path |
| `UDPCHAINS_MAX_DATAGRAM` | maximum payload, default 8192 |
| `UDPCHAINS_STRICT_LOOPBACK` | make the loopback warning below an error |
| `UDPCHAINS_CONNECT_TIMEOUT` | proxy timeout in ms, default 5000, applied to each handshake step |
| `UDPCHAINS_USERNAME`, `UDPCHAINS_PASSWORD_FILE` | credentials (see below) |
| `UDPCHAINS_PASSWORD` | the password itself; inherited by everything the program starts, so prefer the file |
| `UDPCHAINS_DNS` | resolver for name lookups, as a numeric `ip[:port]` — see [Name resolution](#name-resolution) |
| `UDPCHAINS_DNS_TIMEOUT` | whole-lookup timeout in ms, default 5000 |
| `UDPCHAINS_DNS_SEARCH` | search domains for single-label names; none by default |
| `UDPCHAINS_HOSTS_FILE` | hosts file consulted before DNS, default `/etc/hosts` |
| `UDPCHAINS_QUIET`, `UDPCHAINS_DEBUG` | as `-q` and `-v`; take a boolean (`1`/`0`, `yes`/`no`, `true`/`false`, `on`/`off`) |
| `UDPCHAINS_LIB` | path to `libudpchains.so`, if not the installed one |

`udpchains` also sets `UDPCHAINS_RESOLVED` and `UDPCHAINS_PASSWORD_CONFIG` for the program it runs,
to pass on what it resolved (D-25, D-27). They are not meant to be set by hand.

Config file: the first of `-f <file>`, `UDPCHAINS_CONFIG`, `~/.udpchains.conf` and
`/etc/udpchains.conf` that exists. Only that one file is read.

```ini
# ~/.udpchains.conf
proxy = 127.0.0.1:1080
dns = 9.9.9.9
max_datagram = 8192
strict_loopback = no
```

| Key | Meaning | Default |
|---|---|---|
| `proxy` | `host:port` or `[v6]:port` of the SOCKS5 proxy | none — required |
| `max_datagram` | largest payload, 1–65507 bytes | 8192 |
| `strict_loopback` | make the loopback warning an error | `no` |
| `connect_timeout` | ms, 1–600000, for each step of the proxy handshake | 5000 |
| `dns` | resolver as numeric `ip[:port]`, queried through the proxy | none — lookups needing DNS fail |
| `dns_timeout` | ms, 100–600000, for a whole lookup | 5000 |
| `dns_search` | search domains for single-label names, space- or comma-separated | none |
| `hosts_file` | hosts file consulted before DNS | `/etc/hosts` |
| `username` | RFC 1929 username | none |
| `password_file` | file holding the password; a relative path is relative to the current directory | none |
| `password` | the password inline; the file then must not be readable by others | none |
| `quiet`, `debug` | as `-q` and `-v` | `no` |

Booleans take `1`/`0`, `yes`/`no`, `true`/`false` or `on`/`off`. **Comments are whole lines only,**
starting with `#` or `;`. A `#` after a value (`proxy = 10.0.0.1:1080 # office`) is an error rather
than being read as part of the value; a `#` inside a value (`abc#def`) is kept. A password that
really contains " #" belongs in `password_file`. An unknown key is an error.

Credentials are never accepted on the command line, because `argv` is visible in `ps`. Use a file or
the environment:

```sh
UDPCHAINS_USERNAME=alice UDPCHAINS_PASSWORD_FILE=~/.udpchains.pw \
    udpchains -p proxy.example:1080 dig @9.9.9.9 example.com
```

The password itself never enters the environment of the program you run, or of anything it
starts: `udpchains` passes on *where* the password is — the password file, or the config file that
holds `password =` — and the shim reads it from there (D-25). The one exception is a password you
put in `UDPCHAINS_PASSWORD` yourself, which is inherited as you set it. Prefer a file.

RFC 1929 username/password authentication is supported. Method `0x02` is offered **only** when
credentials are configured, so a proxy that accepts either is not pushed into an authenticated
exchange you did not ask for. If authentication fails, the send fails — there is no fallback to an
unauthenticated or direct send.

## Name resolution

`udpchains` resolves names itself, through the proxy. glibc's own resolver cannot be intercepted —
since glibc 2.34 it makes its socket calls through internal functions no preload can see — so a
program resolving a name through `getaddrinfo`, `gethostbyname`, `getnameinfo` or `res_query` would
otherwise send that lookup straight to the host's resolver, however carefully every datagram was
proxied. The shim answers these calls before glibc's resolver runs (D-22):

1. a numeric address answers itself;
2. `localhost` and `*.localhost` are loopback;
3. the hosts file (`/etc/hosts`);
4. a DNS query to the resolver named by `dns`, **sent through the proxy** — over UDP, and repeated
   over TCP with SOCKS5 `CONNECT` if the answer is too large for a datagram.

**Configure a resolver.** There is no default, for the same reason there is no default proxy: the
tool does not choose where your traffic goes. Without `dns`, any lookup that needs DNS fails with
`EAI_FAIL` and one diagnostic. Numeric addresses and the hosts file still work.

```sh
udpchains -p proxy.example:1080 ...        # with dns = 9.9.9.9 in the config file, or
UDPCHAINS_DNS=9.9.9.9 udpchains -p ...     # in the environment
```

The resolver must be given as a numeric address; a name would need resolving first. It sees
queries arriving from the proxy, not from this host. If the proxy is unreachable, or the resolver
does not answer, lookups fail with `EAI_AGAIN` — they are never retried directly.

**Search domains are not applied** unless you ask: `/etc/resolv.conf` is not read at all. Its
`search` line usually names a local domain (`localdomain`, a corporate suffix) that means nothing to
a remote resolver, and appending it sends internal names there. Set `dns_search = example.com` to
have single-label names tried with those suffixes.

What this changes, compared with running unproxied:

- **Only `files` and DNS.** The other sources on your `hosts:` line in `/etc/nsswitch.conf` —
  mDNS (`.local` names), `systemd-resolved`, `myhostname` — are skipped, because each resolves
  through a local daemon the shim cannot proxy. Your own hostname resolves only if it is in
  `/etc/hosts`.
- **Address order** is simpler than glibc's RFC 6724 sort: IPv6 first only when this host has a
  usable IPv6 address.
- **Not supported, and refused rather than resolved directly:** non-ASCII names (`AI_IDN`) fail with
  `EAI_IDN_ENCODE`, and `getaddrinfo_a` fails with `EAI_SYSTEM`.
- **Programs with their own resolver** — `dig`, `host`, curl built with c-ares, Node — do not use
  these calls. Their queries are ordinary UDP to the nameserver in `/etc/resolv.conf`, which the
  shim proxies like any other datagram; on a `systemd-resolved` host that is `127.0.0.53`, which is
  resolved *at the proxy host* (see the loopback caveat below). Give such tools a resolver address
  explicitly (`dig @9.9.9.9 ...`).

## Security considerations

`udpchains` keeps a program's UDP from bypassing the proxy. It does not make the path to the proxy
private.

- **Credentials cross the network in cleartext.** RFC 1929 sends the username and password
  unencrypted, so anyone on the path to a remote proxy can read them. Reach a remote proxy over a
  VPN you trust, such as WireGuard, or use a proxy on this host. An SSH port forward is not enough:
  it carries the TCP control connection, but not the UDP relay traffic.
- **Datagrams to and from the proxy's relay are neither authenticated nor encrypted.** SOCKS5 has
  no way to protect them. Anyone on that path can read them. Anyone who can send a packet that
  appears to come from the relay's address can inject a datagram claiming any source, and the shim
  reports that source to the program as the sender. Only the program's own protocol (DNSSEC, QUIC,
  DTLS) protects against that.
- **The proxy sees everything,** including every name looked up through `dns`. Use one you trust.
- **UDP servers do not work through it.** A server's socket is pointed at the proxy's relay, so it
  no longer receives datagrams sent to this host. Its clients cannot use the relay instead: its
  address is known only to `udpchains`, and most proxies accept inbound datagrams only from hosts
  the program has already sent to. This fails closed — nothing arrives directly either — but a
  server that only receives looks healthy while receiving nothing.
- **A few routes bypass the shim:** raw sockets, `io_uring`, `sendfile`/`splice`, stdio on a UDP
  socket, and sockets taken from another process with `pidfd_getfd`. See below.

To report a vulnerability, see [`SECURITY.md`](SECURITY.md).

## What does not work

This section is the honest part. Read it before deciding whether this tool suits your problem.

### Programs it cannot help at all

| | Why |
|---|---|
| **Statically-linked binaries** | No libc to interpose on. Unfixable by this approach. |
| **Go binaries** | Go issues raw syscalls, bypassing libc entirely. Unfixable by this approach. |
| **setuid/setgid binaries** | The loader ignores `LD_PRELOAD` for them. `udpchains` detects this and **refuses to run them** rather than running them unproxied. Binaries with file capabilities are refused for the same reason. |
| **Programs sending through `syscall()` directly** | Same reason. `ptrace`-based interception is the only answer, and is out of scope. (Creating, duplicating and closing descriptors through `syscall()` *is* tracked, which is how libuv closes them; sends and receives through it are not.) |
| **`ping`, and other non-UDP datagram sockets** | An unprivileged `ping` uses an ICMP datagram socket, which SOCKS5 cannot carry. `udpchains` refuses to create one (`EPROTONOSUPPORT`, with a diagnostic) rather than send it directly or wrap it as UDP (D-29). UDP-Lite is refused the same way. |
| **Programs using raw sockets** | `SOCK_RAW` is not intercepted, and SOCKS5 has no way to carry a raw IP packet. Such traffic goes **direct** — see the warning below. `nmap`, `traceroute` and similar tools are in this category. |

### Traffic it deliberately refuses

**There is no bypass in v1.** Every intercepted datagram is either proxied or fails. That is what
makes the leak test meaningful — a bypass rule set would need its own list of expected direct
traffic, and that list is exactly where a leak hides.

> **Exceptions, and they are real ones.** The first is **raw sockets.** The shim intercepts
> `SOCK_DGRAM` in `AF_INET`/`AF_INET6` and nothing else. A program that opens a `SOCK_RAW` socket gets unproxied
> network access, with no diagnostic and nothing in the logs — the shim never sees it. SOCKS5 cannot
> express a raw IP packet, so there is no honest way to proxy it, but "cannot proxy" should mean
> "refuse", and today it means "pass through". Raw sockets need `CAP_NET_RAW`, so this is not
> reachable by an ordinary unprivileged program — but if you are relying on this tool to guarantee
> that a **privileged** process cannot reach the network directly, it does not. Deferred rather than
> dropped; refusing raw socket creation the way multicast and broadcast sends already fail is the
> obvious v2 change.
>
> The others are routes by which a program can send on a UDP socket without calling any function
> the shim interposes on. On a socket not yet used through the shim, each sends **directly**, with
> no diagnostic; on one already pointed at the relay, the data arrives there without a header and
> is lost (D-21):
>
> - **`io_uring`.** Sends submitted through an `io_uring` ring go straight to the kernel. Event
>   loops increasingly use it.
> - **`sendfile` and `splice`** onto a UDP socket.
> - **stdio on a UDP socket** (`fdopen`, then `fwrite`): glibc writes through internal calls.
>   Reading that way (`fread`) returns the SOCKS header as data.
> - **`pidfd_getfd`**, which copies a socket out of another process. The copy is never tracked,
>   so even ordinary sends on it go directly.
>
> None of these needs root (`pidfd_getfd` needs permission to trace the other process). They are
> unusual for UDP, but if you rely on this tool to guarantee that a program cannot reach the
> network directly, check that it uses none of them.

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

- **Name lookups go through the proxy, but only as far as libc's API.** See
  [Name resolution](#name-resolution). A program with its own resolver sends ordinary UDP, which
  is proxied, but its TCP fallback for large answers is TCP and is not.

- **The proxy's own hostname is resolved directly, once,** by `udpchains` itself, if you configure
  it by name rather than by address. Every program it starts is then given that address, not the
  name, so none of them looks it up again (D-27). Configure a numeric address if even the one
  lookup matters to you.

- **Configuration is resolved once, by `udpchains`.** The programs it runs use exactly what it
  resolved, and do not read the config files themselves (D-27). Only a program started with
  `LD_PRELOAD` directly, without `udpchains`, reads them.

- **Ancillary data (`msg_control`) is returned empty.** `IP_PKTINFO`, `IP_RECVERR`, ECN and friends
  would describe a socket the application does not actually own, and there is no honest emulation.
  A program that depends on them will misbehave, and the cause will not be obvious — this is the
  most likely source of a confusing failure.

- **A socket closed by a route no hook sees keeps its association until the number is touched
  again.** `close()`, `close_range()`, `closefrom()` and `syscall(SYS_close)` all release a socket's
  state at once. `fclose()` on an `fdopen()`ed socket, and anything issuing the raw system call,
  do not. Every intercepted call checks that its descriptor is still the socket the shim tracked
  (D-23), so whatever the kernel puts at that number next is never mistaken for it. But a number
  that is never used again holds its association until the program exits.

- **The shim's own descriptors sit at 768 and up** (lower if your file limit is under 1024): the
  proxy connections, and the resolver's sockets. The program cannot close them. `close()` on one
  fails with `EBADF`, a close-all loop or `close_range` goes around them, and `dup2()` onto one
  fails with `EBUSY` (D-26). They are close-on-exec.

- **After `fork()`, a child that keeps using an inherited UDP socket gets a fresh socket.** The child
  must not share the parent's association, and parent and child share one open file description, so
  the child's socket is replaced with a private one. `O_NONBLOCK`, close-on-exec and a concrete
  `bind()` are carried over; other socket options are not. The child drops its copies of the
  parent's proxy connections at fork, so the parent's associations end when the parent closes them
  (D-31).

- **A socket shared with another process is re-pointed.** When a socket inherited across `exec`, or
  passed over a Unix socket, is also still held by another process, the shim's first use points it
  at a new proxy relay, and that redirects the other holder's traffic too. There is no safe general
  fix: the shim cannot tell who else holds a socket (D-32). Avoid sharing a UDP socket between a
  proxied and an unproxied process.

- **`strict_loopback` is checked when a socket's association is set up, and only for a connected
  socket.** An unconnected `sendto()` to loopback, or a `connect()` to loopback after the socket has
  already sent, is not caught, and goes to the *proxy host's* loopback (D-32).

- **The first send or receive on a socket blocks while the proxy handshake runs,** even on a
  non-blocking socket, which can stall an event loop. `connect_timeout` applies to each step of the
  handshake rather than to the whole, and a send whose association cannot be set up tries once more
  before failing (D-32).

- **Sending from a signal handler is safe only on a socket already in use.** The steady-state path
  takes no locks and allocates nothing. But a socket's first send, a thread's first datagram, and
  `socket()`, `dup()` and `close()` all allocate or free memory, so doing any of those inside a
  signal handler that interrupted `malloc` can deadlock.

- **`MSG_MORE`, `UDP_CORK`, GSO and GRO (`UDP_SEGMENT`, `UDP_GRO`) corrupt data.** They are not
  refused. Each call is sent with its own SOCKS header, so a datagram built up over several calls
  arrives with a header in its middle, and a coalesced receive is misread (D-32). Modern QUIC stacks
  use GSO/GRO; their encryption rejects the damage, so QUIC fails rather than delivering garbage,
  but a plain UDP program does not. Even when QUIC works, a UDP flow through a TCP-based tunnel
  inherits retransmit-and-wait behaviour that fights QUIC's own loss recovery.

- **A proxy given by hostname is reached at its first address only.** If the name resolves to
  several, the others are not tried when the first fails (D-35). Configure the address you want
  numerically.

- **A forked child cannot always keep its parent's bound port.** A child using an inherited socket
  binds its private replacement to the same address and port, but while the parent still holds the
  port that fails. The child then sends from another port, and warns once (D-34).

- **A bad pointer inside a message crashes, as it would without the shim.** A `NULL` `msg_iov`, a
  too-short address, or more than `IOV_MAX` buffers fail with the `errno` the kernel gives. The
  shim copies a message before the kernel sees it, so a non-`NULL` pointer to unmapped memory
  faults inside the shim instead of returning `EFAULT`.

- **Warnings are rate-limited and go only to the original stderr.** A repeated warning (a refused
  multicast send, an oversized inbound datagram) prints at most once a second, with a count of those
  held back. If the program closes stderr and something else takes descriptor 2, the shim stays
  silent rather than write into it (D-33). `-q` prints errors only.

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

### How far it has been tested against real proxies

The automated suite runs against an in-repo proxy fixture. Against a real proxy, 1.0.0 has been
checked with one SOCKS5 proxy, running on the same host, with `nc -u`, TFTP, `dig`, `iperf` and
`ntpdate` (see [`docs/INTEROP-CHECKLIST.md`](docs/INTEROP-CHECKLIST.md)). **Not yet tested:** a
proxy on another host, other proxies such as Dante, IPv6 destinations sent as `ATYP 0x04`, and name
resolution through a real proxy. Reports from those setups are welcome.

### Not implemented in v1

- SOCKS5 GSSAPI authentication (method `0x01`), and any method other than `0x00` and `0x02`. A proxy
  selecting one is refused with a diagnostic naming what is supported. Username/password (RFC 1929)
  **is** implemented — see above.
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
but read back data with the SOCKS header still attached. A 108-cell test matrix
asserts byte-identical round-trips for every pair of `{sendto, send, write, writev, sendmsg,
sendmmsg} × {recvfrom, recv, read, readv, recvmsg, recvmmsg}` over IPv4 and IPv6, with the three
senders that name a destination run both connected and unconnected.

Per-descriptor state lives in a lock-free two-level radix table, with no allocation and no locks on
the datagram path once a socket's association is up (see the signal-handler caveat above). Each intercepted call makes one extra system
call, a `getsockopt`, to confirm its descriptor is still the socket the shim recorded (D-23).
Associations are type-stable, so a thread reading one while another tears it down reads valid
memory (D-24).

## Documentation

| | |
|---|---|
| [`UDP-PRELOAD-REQUIREMENTS.md`](UDP-PRELOAD-REQUIREMENTS.md) | the requirements baseline |
| [`DECISIONS.md`](DECISIONS.md) | every design decision, with consequences and revisit conditions |
| [`docs/DESIGN.md`](docs/DESIGN.md) | how it is built |
| [`docs/TRACEABILITY.md`](docs/TRACEABILITY.md) | every requirement mapped to design section and test |
| [`docs/INTEROP-CHECKLIST.md`](docs/INTEROP-CHECKLIST.md) | manual tests against a real proxy, and what each one proves |
| [`CHANGELOG.md`](CHANGELOG.md) | what changed, and what is known not to work |
| [`SECURITY.md`](SECURITY.md) | how to report a vulnerability |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | how to contribute, and the clean-room rule |

## Licence

MIT — see [`LICENSE`](LICENSE).

Implemented clean-room from RFC 1928 §7 and the relevant man pages. `proxychains-ng` and `Proxando`
are cited in the requirements as evidence about their *behaviour*; no code was taken from either, and
contributions must not derive from them — both are GPL-2.0, and doing so would silently relicense
this project.

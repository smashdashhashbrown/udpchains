# udpchains

Routes a dynamically linked program's **UDP** through a SOCKS5 proxy that supports
`UDP ASSOCIATE`, using `LD_PRELOAD`. The program is not modified or recompiled.

```
udpchains -p 127.0.0.1:1080 dig @9.9.9.9 example.com
```

## Why

`proxychains` proxies TCP only. Under it, a program's UDP is sent directly, with no error.

`udpchains` proxies UDP and **fails closed**: a datagram that cannot be proxied fails with an
`errno`, and is never sent directly. A test checks that, with the proxy stopped, no packet
reaches the destination by any send path it covers. The routes the shim cannot see are listed
under [Traffic that bypasses the shim](#traffic-that-bypasses-the-shim).

## Build and install

Linux, glibc 2.34 or later, a C compiler. No other dependencies.

```sh
make
sudo make install          # bin/udpchains, lib/libudpchains.so, man1/udpchains.1
make test                  # unit and integration tests, against an in-repo fixture proxy
tests/run_sanitizers.sh    # ASan/UBSan, TSan, Valgrind, Helgrind
```

## Usage

```
udpchains [options] <program> [args...]

  -f <file>    config file
  -p <addr>    proxy as host:port or [v6]:port
  -q           errors only
  -v           protocol steps (never payload)
```

- Precedence: command line, then environment, then config file.
- **There is no default proxy.** Without one, `udpchains` refuses to run the program.
- **There is no default DNS resolver.** Without `dns`, the program runs, but lookups that need
  DNS fail. See [Name resolution](#name-resolution).

```sh
udpchains -p 127.0.0.1:1080 dig @9.9.9.9 example.com              # dig queries 9.9.9.9 itself
UDPCHAINS_DNS=9.9.9.9 udpchains -p 127.0.0.1:1080 nc -u example.com 53
```

### Configuration

The config file is the first of these that exists: `-f <file>`, `UDPCHAINS_CONFIG`,
`~/.udpchains.conf`, `/etc/udpchains.conf`. Only that file is read.

```ini
proxy = 127.0.0.1:1080
dns = 9.9.9.9
```

| Key | Environment | Meaning | Default |
|---|---|---|---|
| `proxy` | `UDPCHAINS_PROXY` | SOCKS5 proxy, `host:port` or `[v6]:port` | none; required |
| `dns` | `UDPCHAINS_DNS` | resolver, numeric `ip[:port]`, queried through the proxy | none |
| `max_datagram` | `UDPCHAINS_MAX_DATAGRAM` | largest payload, 1–65507 bytes | 8192 |
| `connect_timeout` | `UDPCHAINS_CONNECT_TIMEOUT` | ms per proxy handshake step, 1–600000 | 5000 |
| `dns_timeout` | `UDPCHAINS_DNS_TIMEOUT` | ms per lookup, 100–600000 | 5000 |
| `dns_search` | `UDPCHAINS_DNS_SEARCH` | search domains for single-label names, space- or comma-separated | none |
| `hosts_file` | `UDPCHAINS_HOSTS_FILE` | hosts file read before DNS | `/etc/hosts` |
| `strict_loopback` | `UDPCHAINS_STRICT_LOOPBACK` | make the loopback warning an error | `no` |
| `username` | `UDPCHAINS_USERNAME` | RFC 1929 username | none |
| `password_file` | `UDPCHAINS_PASSWORD_FILE` | file holding the password; relative to the current directory | none |
| `password` | `UDPCHAINS_PASSWORD` | the password itself (see below) | none |
| `quiet`, `debug` | `UDPCHAINS_QUIET`, `UDPCHAINS_DEBUG` | as `-q` and `-v` | `no` |
| — | `UDPCHAINS_CONFIG` | config file path | — |
| — | `UDPCHAINS_LIB` | path to `libudpchains.so`, if not the installed one | — |

- Booleans: `1`/`0`, `yes`/`no`, `true`/`false`, `on`/`off`.
- Comments are whole lines starting with `#` or `;`. A `#` after a value
  (`proxy = 10.0.0.1:1080 # office`) is an error. A `#` inside a value (`abc#def`) is kept, so
  put a password containing ` #` in `password_file`.
- An unknown key is an error.
- `udpchains` sets `UDPCHAINS_RESOLVED` and `UDPCHAINS_PASSWORD_CONFIG` for the program it runs.
  Do not set them by hand.

### Authentication

RFC 1929 username/password is supported.

- Credentials are not accepted on the command line, which `ps` shows. Use a file or the
  environment:

  ```sh
  UDPCHAINS_USERNAME=alice UDPCHAINS_PASSWORD_FILE=~/.udpchains.pw \
      udpchains -p proxy.example:1080 dig @9.9.9.9 example.com
  ```

- The password is not put in the program's environment. `udpchains` passes on where it is (the
  password file, or the config file), and the shim reads it there. A password set in
  `UDPCHAINS_PASSWORD` is inherited by everything the program starts; prefer a file.
- A config file containing `password =` must not be readable by others.
- Username/password is offered to the proxy only when credentials are configured.
- If authentication fails, the send fails. There is no unauthenticated or direct fallback.

## Compatible proxies

The proxy must implement `UDP ASSOCIATE`; many SOCKS5 servers implement only `CONNECT`. Each proxy
below was tested on the same host as the client, covering the full call matrix, IPv6
destinations, name resolution with its TCP fallback, authentication, idle expiry, and the proxy
dying mid-stream. No proxy-specific udpchains defect was found.

| Proxy | Version | Licence | UDP setup | Largest datagram | Notes |
|---|---|---|---|---|---|
| [Dante](https://www.inet.no/dante/) | 1.4.3 | BSD-style | `udpassociate` and `udpreply` in `socks pass` rules | ≥ 65 497 | Port-restricted unless `udp.connectdst: no` |
| [3proxy](https://github.com/3proxy/3proxy) | 1.0.1 | BSD-style | On in the `socks` service | 16 326 | Drops zero-length datagrams; a refused login gives `ECONNRESET` |
| [gost](https://github.com/go-gost/gost) | 3.3.1 | MIT | `?udp=true` on the listener | 4 086; ≥ 65 497 with `udpBufferSize=65535` | |
| [Xray](https://github.com/XTLS/Xray-core) | 26.3.27 | MPL-2.0 | `"udp": true` on the `socks` inbound | 8 182 | Drops zero-length datagrams |
| [sing-box](https://github.com/SagerNet/sing-box) | 1.14.3 | GPL-3.0 | On by default on the `socks` inbound | 16 122 | |
| [hev-socks5-server](https://github.com/heiher/hev-socks5-server) | 2.13.1 | MIT | On by default | 1 490 | Drops zero-length datagrams |
| [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust) `sslocal` | 1.25.0 | MIT | `-U` on `sslocal` and `ssserver` | ≥ 65 000 | Drops zero-length datagrams; authentication not tested |

- Also tested: the reference proxy used during development.
- Datagram limits are payload bytes to an IPv4 destination. To IPv6 they are 12 bytes lower.
- **Set `max_datagram` no higher than the proxy's limit.** A proxy silently truncates a datagram
  larger than its buffer. With `max_datagram` at or below the limit, an oversized send fails with
  `EMSGSIZE` instead. hev, gost at its default, and Xray are below the default of 8192.
- Configurations and full results: [`docs/INTEROP-CHECKLIST.md`](docs/INTEROP-CHECKLIST.md) §12.
  `make interop` repeats the runs (needs Docker). Proxies are tested as black boxes; do not read
  GPL source while working on udpchains ([`CONTRIBUTING.md`](CONTRIBUTING.md)).

## Name resolution

glibc's resolver cannot be intercepted, so the shim answers `getaddrinfo`, `gethostbyname`,
`getnameinfo` and `res_query` itself, in this order:

1. a numeric address;
2. `localhost` and `*.localhost` (loopback);
3. the hosts file;
4. a DNS query to the `dns` resolver, **through the proxy**: over UDP, then over TCP with SOCKS5
   `CONNECT` if the answer is truncated.

- `dns` has no default. Without it, lookups that need DNS fail with `EAI_FAIL`. Numeric addresses
  and the hosts file still work.
- `dns` must be a numeric address. The resolver sees queries from the proxy, not this host.
- If the proxy or resolver does not answer, lookups fail with `EAI_AGAIN`. They are not retried
  directly.
- `/etc/resolv.conf` is not read, so its search domains are not applied. Set `dns_search` to apply
  some.
- Only the hosts file and DNS are used. Other `hosts:` sources in `/etc/nsswitch.conf`, such as mDNS
  (`.local`), `systemd-resolved` and `myhostname`, are skipped. The local hostname resolves only if
  it is in `/etc/hosts`.
- Address order: IPv6 first only when this host has a usable IPv6 address (simpler than glibc's
  RFC 6724 sort).
- Refused: non-ASCII names (`AI_IDN`, `EAI_IDN_ENCODE`) and `getaddrinfo_a` (`EAI_SYSTEM`).
- Programs with their own resolver (`dig`, `host`, curl built with c-ares, Node) send ordinary
  UDP to the nameserver in `/etc/resolv.conf`, which is proxied. Their TCP fallback is not. On a
  `systemd-resolved` host that nameserver is `127.0.0.53`, which is resolved at the proxy host;
  give such tools a resolver explicitly (`dig @9.9.9.9`).

## Security considerations

`udpchains` keeps UDP from bypassing the proxy. It does not protect the path to the proxy.

- **Credentials are sent in cleartext** (RFC 1929). For a remote proxy, use a trusted VPN such as
  WireGuard, or a proxy on this host. An SSH port forward carries the TCP control connection but
  not the UDP relay traffic.
- **Relay datagrams are neither encrypted nor authenticated.** Anyone on the path can read them. A
  spoofed packet from the relay's address can claim any source, and the program is told that
  source. Only the program's own protocol (DNSSEC, QUIC, DTLS) protects against this.
- **The proxy sees all traffic,** including every name looked up through `dns`.
- **UDP servers do not work.** The server's socket is pointed at the relay, so it receives nothing
  sent to this host. Nothing arrives directly either, but a receive-only server looks healthy.
- **Some routes bypass the shim.** See [below](#traffic-that-bypasses-the-shim).

To report a vulnerability, see [`SECURITY.md`](SECURITY.md).

## What does not work

### Programs it cannot help

| Program | Reason |
|---|---|
| Statically linked binaries | No libc to interpose on. Planned after 0.1.0 as a supervisor mode ([`docs/FUTURE-STATIC-BINARIES.md`](docs/FUTURE-STATIC-BINARIES.md)). |
| Go binaries | Go makes system calls directly, not through libc. Planned with static binaries. |
| Programs making system calls without libc (inline assembly) | Same reason. Planned with static binaries. Calls through libc's `syscall()` are proxied. |
| setuid, setgid and file-capability binaries | The loader ignores `LD_PRELOAD` for them. `udpchains` refuses to run them. |
| `ping` (ICMP datagram sockets), UDP-Lite | SOCKS5 cannot carry them. Socket creation fails with `EPROTONOSUPPORT`. |
| Raw and packet sockets (`nmap`, `traceroute`) | SOCKS5 cannot carry them. Socket creation fails with `EPERM`, as it does without `CAP_NET_RAW`. |

### Traffic that bypasses the shim

Every intercepted datagram is proxied or fails; there is no bypass list. Two routes are not
intercepted:

- **`io_uring`.** Sends submitted through a ring go straight to the kernel. glibc has no wrapper to
  interpose on.
- **System calls made without libc** (inline assembly, Go, static binaries).

Calls that move data without a send or receive call are handled instead:

| Call | On a UDP socket |
|---|---|
| `syscall()` with a socket, send or receive number | proxied, as the call itself |
| `dprintf`, `vdprintf` | proxied, as one datagram |
| `pwritev2`, `preadv2` at offset −1 | proxied, as `writev` and `readv` |
| `__write`, `__send` and glibc's other public aliases | proxied, as the call itself |
| `sendfile`, `splice`, `fdopen` (stdio) | refused with `EINVAL` |
| `pidfd_getfd` | the copy is tracked like any other socket |

### Refused or limited traffic

- **Loopback destinations are resolved at the proxy host.** A datagram to `127.0.0.1` reaches the
  proxy host's loopback: correct with a local proxy, wrong with a remote one. Affects statsd
  (8125), syslog over UDP, a local `chrony`, and `systemd-resolved` (`127.0.0.53`). A warning is
  printed when the proxy is not local; `strict_loopback` makes it an error, but is checked only
  when a connected socket's association is set up. An unconnected `sendto()` to loopback, or a
  `connect()` to loopback after the socket has sent, is not caught.
- **Multicast and broadcast fail** with `ENETUNREACH`: mDNS (5353), SSDP (1900), LLMNR, DHCP,
  NetBIOS. `setsockopt(SO_BROADCAST)` and `IP_ADD_MEMBERSHIP` still succeed; the send fails.
- **Payloads over `max_datagram` fail** with `EMSGSIZE`, including loopback traffic that could
  otherwise carry 64 KB.
- **TCP is not proxied**, except the shim's own DNS fallback. `proxychains-ng` can be combined
  with `udpchains` for TCP.

### Behaviour that differs from an unproxied program

- **Ancillary data** (`msg_control`: `IP_PKTINFO`, `IP_RECVERR`, ECN) is returned empty.
- **`MSG_MORE` and a `UDP_SEGMENT` control message are refused** with `EOPNOTSUPP`: each send
  needs its own SOCKS header.
- **`UDP_CORK`, `UDP_SEGMENT` and `UDP_GRO` set with `setsockopt` corrupt data.** `setsockopt` is
  not intercepted, so they are not refused. QUIC rejects the damaged datagrams; plain UDP programs
  do not.
- **QUIC** through a TCP-based tunnel performs poorly even when it works.
- **The first send or receive blocks** during the proxy handshake, even on a non-blocking socket.
  `connect_timeout` applies to each handshake step. A failed association setup is retried once.
- **Signal handlers:** sending is safe only on a socket already in use. A socket's first send, a
  thread's first datagram, `socket()`, `dup()` and `close()` allocate memory and can deadlock if
  the signal interrupted `malloc`.
- **After `fork()`,** a child using an inherited socket gets a new socket. `O_NONBLOCK`,
  close-on-exec and a specific `bind()` are kept; other socket options are not. If the parent
  still holds the port, the child sends from another port and warns once.
- **A socket shared with another process** (inherited across `exec`, or passed over a Unix socket)
  is redirected for both processes on first use.
- **A socket closed without a hook seeing it** (a `close` system call made without libc) keeps its
  association until its descriptor number is used again, or the program exits. `close()`,
  `close_range()`, `closefrom()` and `syscall(SYS_close)` release it at once.
- **The shim's own descriptors are at 768 and up** (lower if the file limit is under 1024). The
  program cannot close them: `close()` gives `EBADF`, `close_range` skips them, `dup2()` onto one
  gives `EBUSY`. They are close-on-exec.
- **The proxy's hostname is resolved directly, once,** by `udpchains`. Use a numeric address to
  avoid that lookup. Only the first address is used.
- **Configuration is read once,** by `udpchains`. A program started with `LD_PRELOAD` directly
  reads the config files itself.
- **A non-`NULL` invalid pointer** inside a message faults in the shim instead of returning
  `EFAULT`. A `NULL` `msg_iov`, a short address, or more than `IOV_MAX` buffers give the kernel's
  `errno`.
- **Warnings** are rate-limited to once a second, with a count of those suppressed, and are not
  written if descriptor 2 is no longer the original stderr.

### Behaviour that depends on the proxy

Some protocols reply from a different port than the one addressed: TFTP, SIP/RTP, some games.

| Proxy inbound policy | Result |
|---|---|
| Port-restricted: accepts only from an `address:port` already sent to | These protocols fail. The send succeeds and nothing arrives. |
| Address-restricted: accepts any port at a host already sent to | They work. |
| Association-scoped: accepts anything | They work; the relay is open. |

- Dante 1.4.3 is port-restricted by default (`udp.connectdst: no` in `sockd.conf` changes it). The
  other six tested proxies accept a reply from a different port.
- udpchains filters by peer only on `connect()`ed sockets, as the kernel does. Unconnected sockets
  are not filtered.
- If such a protocol hangs after the first exchange, check the proxy's logs. `udpchains -v` shows
  each request's destination and `ATYP`.
- A datagram larger than the proxy's buffer is truncated without error (see
  [Compatible proxies](#compatible-proxies)).
- Some proxies drop zero-length datagrams.
- A proxy that closes the connection on a refused login, as 3proxy does, gives `ECONNRESET`
  instead of `EACCES`.

### Testing against real proxies

The automated suite uses an in-repo fixture proxy. 0.1.0 was also tested on the same host against
the reference proxy (`nc -u`, TFTP, `dig`, `iperf`, `ntpdate`) and against the seven
[compatible proxies](#compatible-proxies). **Untested:** a proxy on another host, and an IPv6
destination beyond this host's loopback.

### Not implemented

- SOCKS5 authentication methods other than none (`0x00`) and username/password (`0x02`),
  including GSSAPI (`0x01`). A proxy selecting one is refused with a diagnostic.
- `proxychains.conf`-style `[ProxyList]` configuration. A `[ProxyList]` line is an error that
  says so.
- Proxy chains (multi-hop UDP). Planned after 0.1.0
  ([`docs/FUTURE-UDP-CHAINS.md`](docs/FUTURE-UDP-CHAINS.md)).
- Static and Go binaries, and system calls made without libc. Planned after 0.1.0
  ([`docs/FUTURE-STATIC-BINARIES.md`](docs/FUTURE-STATIC-BINARIES.md)).
- Loopback and multicast bypass. Deferred ([`DECISIONS.md`](DECISIONS.md) D-05).

## Comparison with similar tools

| Tool | Approach | Licence | Also does |
|---|---|---|---|
| [Dante `socksify`](https://www.inet.no/dante/) | `LD_PRELOAD` | BSD-style | TCP |
| [proxychains-ng PR #570](https://github.com/rofl0r/proxychains-ng/pull/570) | `LD_PRELOAD` | GPL-2.0 | TCP; UDP through a chain of proxies. Unmerged pull request |
| [Proxando](https://github.com/NULLhere/Proxando) | `LD_PRELOAD` | GPL-2.0 | TCP; proxychains-style configuration |
| [graftcp](https://github.com/hmgle/graftcp) | `ptrace` | GPL-3.0 | TCP; static and Go binaries; HTTP proxies |

udpchains does UDP only, through one proxy, for dynamically linked programs.

### UDP behaviour, measured

Measured 2026-10-19 in a Docker lab: client, SOCKS5 proxy (gost 3.3.1) and server on separate
addresses. The server logged the source of every datagram and DNS query. A control run with no
tool showed every datagram arriving directly. Versions: `dante-client` 1.4.3 (Ubuntu 24.04),
PR #570 at `04f6622`, Proxando at `c7ff4ac`, graftcp v0.8.3.

| | udpchains | Dante `socksify` | PR #570 | Proxando | graftcp |
|---|---|---|---|---|---|
| IPv4 send × receive round trips through the proxy, of 54 | 54 | 35 | 0 | 20 | 24 |
| The same, IPv6 | 54 | 0 | 0 | 20 | 23–24 |
| `sendmmsg` | through the proxy | sent directly | — | sent directly | sent directly |
| Sender address the program sees | the real sender | the real sender | — | the real sender | another address |
| `dig` with its own resolver | through the proxy | no answer | through the proxy | no answer | through the proxy |
| `getaddrinfo` | queried through the proxy | placeholder address | placeholder address | placeholder address | queried through the proxy |
| Static Go binary | sent directly | sent directly | sent directly | sent directly | through the proxy |
| Proxy stopped: datagrams that reached the server directly | none | IPv6, `sendmmsg` | none | `sendto`, `sendmmsg` | `sendmmsg` |

- The 54 combinations: `sendto`, `sendmsg`, `sendmmsg` (each with and without `connect`),
  `send`, `write`, `writev` × `recvfrom`, `recv`, `read`, `readv`, `recvmsg`, `recvmmsg`. A cell
  counts only if the reply came back byte for byte through the proxy.
- IPv4 results were the same with a warmed-up socket and with `_FORTIFY_SOURCE`.
- graftcp ran in `auto` and `only_socks5` modes with the same results, except for at most one
  crashed cell per matrix (hence the IPv6 range).
- Placeholder addresses come from Dante's `resolveprotocol: fake` and proxychains' `proxy_dns`,
  where the proxy resolves the name on TCP connect.

Per tool:

- **Dante `socksify`:** IPv6 UDP is sent directly (its log: "unsupported af 10"). `recvmmsg`
  returns the 10-byte SOCKS header as data. `sendmmsg` bypasses the proxy.
- **PR #570:** datagrams reach the proxy, but sends report failure (`EINPROGRESS`, then `EAGAIN`).
  Programs that retry, such as `dig`, work. `sendto` on a connected socket crashed the client.
  Nothing was sent directly.
- **Proxando:** `readv` and `recvmmsg` return the SOCKS header as data. `sendmsg` and `sendmmsg`
  on a connected socket fail with `EDESTADDRREQ`. `sendmmsg` is sent directly. With the proxy
  stopped, `sendto` was sent directly.
- **graftcp:** reports another address as the sender and does not handle `sendmmsg`, both listed in
  its README. With the proxy stopped, other sends report success without delivery. `auto` mode
  falls back to direct DNS; `--select_proxy_mode only_socks5` prevents it. The only tool here
  that handles a static Go binary.

Limits:

- The tests come from udpchains' own requirements. TCP, chains, static binaries, HTTP proxies and
  other platforms were not measured.
- udpchains' authors wrote the tests and configured every tool from its documentation.
- One proxy, one host, one run per tool. graftcp ran with Docker's seccomp filter disabled; with
  it, graftcp failed intermittently with ptrace errors.
- Corrections are welcome as issues with a better configuration.

`make compare` reruns the comparison ([`tests/compare/`](tests/compare/); needs Docker and
Python 3). Tool configurations are in `tests/compare/conf/`.

## How it works

- The shim interposes on libc's socket calls, for `SOCK_DGRAM` sockets in `AF_INET` and `AF_INET6`
  only, and points the program's own UDP socket at the proxy's relay. There is no second socket, so
  `poll`, `select`, `epoll` and socket options work unchanged and are not hooked.
- On a socket's first use, the shim opens a TCP control connection to the proxy and issues
  `UDP ASSOCIATE`. Outgoing datagrams get an RFC 1928 §7 header; incoming ones have it checked and
  removed, so the program sees the real sender and its own byte counts.
- All send calls share one send path and all receive calls one receive path. A 108-cell test
  matrix checks byte-identical round trips for `{sendto, send, write, writev, sendmsg, sendmmsg}` ×
  `{recvfrom, recv, read, readv, recvmsg, recvmmsg}` over IPv4 and IPv6, connected and
  unconnected.
- Per-descriptor state is in a lock-free radix table. Once a socket's association is up, the
  datagram path takes no locks and allocates nothing. Each intercepted call makes one
  `getsockopt` to confirm its descriptor is still the tracked socket.

## Documentation

| | |
|---|---|
| [`UDP-PRELOAD-REQUIREMENTS.md`](UDP-PRELOAD-REQUIREMENTS.md) | requirements |
| [`DECISIONS.md`](DECISIONS.md) | design decisions (D-nn) |
| [`docs/DESIGN.md`](docs/DESIGN.md) | design |
| [`docs/TRACEABILITY.md`](docs/TRACEABILITY.md) | requirements mapped to design and tests |
| [`docs/INTEROP-CHECKLIST.md`](docs/INTEROP-CHECKLIST.md) | tests against real proxies |
| [`docs/FUTURE-UDP-CHAINS.md`](docs/FUTURE-UDP-CHAINS.md) | planned: multi-hop UDP chains |
| [`docs/FUTURE-STATIC-BINARIES.md`](docs/FUTURE-STATIC-BINARIES.md) | planned: static and Go binaries |
| [`CHANGELOG.md`](CHANGELOG.md) | changes and known limitations |
| [`SECURITY.md`](SECURITY.md) | reporting a vulnerability |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | contributing, and the clean-room rule |

## Licence

MIT; see [`LICENSE`](LICENSE).

Written clean-room from RFC 1928, RFC 1929 and the Linux man pages. No code was taken from
`proxychains-ng` or `Proxando` (both GPL-2.0), and contributions must not derive from them.

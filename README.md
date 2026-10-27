# udpchains

Routes a program's **UDP** through a SOCKS5 proxy that supports `UDP ASSOCIATE`, or through a
[chain](#chains) of them. A dynamically linked program is given a shim with `LD_PRELOAD`; any
other, static and Go programs included, can be run in [supervisor mode](#supervisor-mode-static-and-go-programs),
which carries its UDP from outside it. The program is not modified or recompiled.

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

Linux, glibc 2.34 or later, a C compiler. No other dependencies. Supervisor mode also needs Linux
5.14 or later, on x86-64.

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
  -p <addr>    proxy as host:port or [v6]:port; repeat for a chain
  --supervise  supervisor mode, for static and Go programs
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
| `proxy` | `UDPCHAINS_PROXY` | SOCKS5 proxy, `host:port` or `[v6]:port`. In the environment, a comma-separated list is a [chain](#chains) | none; required |
| `dns` | `UDPCHAINS_DNS` | resolver, numeric `ip[:port]`, queried through the proxy | none |
| `max_datagram` | `UDPCHAINS_MAX_DATAGRAM` | largest payload, 1–65507 bytes | 8192 |
| `connect_timeout` | `UDPCHAINS_CONNECT_TIMEOUT` | ms per proxy handshake step, 1–600000 | 5000 |
| `chain_timeout` | `UDPCHAINS_CHAIN_TIMEOUT` | ms for a whole association setup, every hop included, 0–4800000; 0 is no limit. Set, it applies to a single proxy too | `connect_timeout` × hops for a chain; none for a single proxy |
| `dns_timeout` | `UDPCHAINS_DNS_TIMEOUT` | ms per lookup, 100–600000 | 5000 |
| `dns_search` | `UDPCHAINS_DNS_SEARCH` | search domains for single-label names, space- or comma-separated | none |
| `hosts_file` | `UDPCHAINS_HOSTS_FILE` | hosts file read before DNS | `/etc/hosts` |
| `strict_loopback` | `UDPCHAINS_STRICT_LOOPBACK` | make the loopback warning an error | `no` |
| `supervise` | `UDPCHAINS_SUPERVISE` | [supervisor mode](#supervisor-mode-static-and-go-programs), as `--supervise` | `no` |
| `allow_resolver_daemons` | `UDPCHAINS_ALLOW_RESOLVER_DAEMONS` | supervised, let lookups reach systemd-resolved, nscd and avahi, which resolve outside the proxy | `no` |
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
- `[hop]` sections configure a [chain](#chains). A `proxychains.conf` can be given to `-f` as
  it is; see [proxychains.conf](#proxychainsconf).
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

## Chains

A chain sends each datagram through several SOCKS5 proxies in turn. The first proxy listed is
hop 1, the one this host talks to; the last is the exit hop, which sends the datagram to its
destination.

```sh
udpchains -p 10.0.0.1:1080 -p 10.1.0.5:1080 dig @9.9.9.9 example.com
UDPCHAINS_PROXY=10.0.0.1:1080,10.1.0.5:1080 udpchains dig @9.9.9.9 example.com
```

```ini
proxy = 10.0.0.1:1080
username = alice
password_file = ~/.hop1.pw

[hop]
proxy = inner.example:1080
username = bob
password_file = ~/.hop2.pw
```

- **Up to 8 hops.** Each `[hop]` section adds the next one, and may hold only `proxy`,
  `username`, `password_file` and `password`. Every other setting applies to the whole chain.
- **Hop 2's credentials** are `UDPCHAINS_USERNAME_2`, `UDPCHAINS_PASSWORD_FILE_2` and
  `UDPCHAINS_PASSWORD_2`, and so on for later hops. Hop 1 keeps the unsuffixed names.
- **`-p` replaces the whole chain** from the environment or the config file; it does not add to
  it. Each hop's credentials still come from wherever they are set.
- **Strict.** Every hop must be up, in order, or the send fails, and the error names the hop.
  There is no mode that skips a dead hop or picks hops at random: a skipped hop is a different
  path to the destination.
- **Later hops are not resolved on this host.** Each one is asked for by name, if given by name,
  from the hop before it. A misspelt later hop is reported when the program first sends, not
  when `udpchains` starts.
- **Each hop after the first is reached by SOCKS5 `CONNECT` through the hops before it.** Every
  hop but the exit must allow `CONNECT` to the next hop, and must relay UDP to it.
- **Setup takes longer.** A chain of *n* hops makes *n*(*n*+1)/2 handshakes, and the program's
  first send waits for all of them. `chain_timeout` bounds the whole setup; by default it is
  `connect_timeout` × the number of hops.
- **Name lookups** (`dns`) go through the chain too. The resolver sees queries from the exit hop.
- **A loopback destination is resolved at the exit hop,** so with a chain it always warns, and
  `strict_loopback` refuses it.

### proxychains.conf

`udpchains -f /etc/proxychains.conf <program>` reads a proxychains configuration as it is, for the
strict chain of `socks5` proxies it lists. It is never read unless named.

```
strict_chain
proxy_dns
tcp_connect_time_out 8000

[ProxyList]
socks5  10.0.0.1     1080
socks5  10.1.0.5     1080  bob  secret
```

- **Each `socks5` line is a hop,** in order, with its login if it has one. `socks4`, `http` and
  `raw` proxies cannot carry UDP and are errors.
- **`strict_chain` is accepted.** `dynamic_chain`, `random_chain` and `round_robin_chain` are
  errors: chains are strict.
- **`quiet_mode` and `tcp_connect_time_out`** become `quiet` and `connect_timeout`.
- **The other directives are not applied,** and a warning names each: `proxy_dns` (set `dns`),
  `localnet` (there is no bypass; that traffic goes through the proxies or fails), `chain_len`,
  `tcp_read_time_out`, `remote_dns_subnet`, `dnat`. udpchains' own settings, such as
  `dns = 9.9.9.9`, can be added before `[ProxyList]`.
- **A login on a line is treated like `password =`:** a warning if others can read the file, and
  the password is never put in the program's environment. One containing a space or starting with
  `#` needs `[hop]` sections and `password_file` instead.
- A file has either `[ProxyList]` or `proxy =` and `[hop]` sections, not both. `-p` and
  `UDPCHAINS_PROXY` still replace the file's chain.

### Datagram size through a chain

Hop *i* of *n* carries, besides the payload, the headers of the *n* − *i* hops after it, so it
truncates that many headers sooner than it does alone. The exit hop's limit is unchanged. A header
is 10 bytes for an IPv4 relay and 22 for IPv6. With IPv4 relays, set `max_datagram` no higher than
the smallest, over all the hops, of:

> (hop *i*'s limit alone) − 10 × (*n* − *i*)

For example, Xray (8 182 alone) as hop 1 of 2 carries 8 172 whole, and hev-socks5-server (1 490)
as hop 6 of 7 carries 1 480; `make interop` measured exactly these. A later hop given by name,
whose relay is its own loopback or wildcard address, is named in the header that reaches the hop
before it: 7 bytes plus the name. `max_datagram` is still the program's payload; the shim adds the
headers. Above the smallest limit, a datagram is truncated without error, as with one proxy.

### Descriptors

The shim holds one TCP connection per hop for every UDP socket in use. Its connections are kept at
descriptor 768 and up, where the program cannot close them; that range holds 256, so about 85
sockets through 3 hops, or 32 through 8. Beyond that, a connection stays at whatever lower number
it was given, still protected, and a warning says so. A program that `dup2`s onto that number then
gets `EBUSY`. With no descriptors left at all, the send fails with `EMFILE`.

### Security of a chain

The destination, and every hop after the first, see the address of the hop before them, not this
host's. Nothing is encrypted, so the hops themselves see more:

- **Every hop can read every datagram,** and every hop before the exit sees the destination in
  the inner headers.
- **Hop *k*'s credentials pass through hops 1 to *k*−1** in cleartext, inside the `CONNECT`
  tunnel. Any of them can read the password.
- A hop can forge a reply claiming to come from any hop after it. The shim checks each layer's
  source, which stops packets injected from elsewhere, not a hop that lies.

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
- **In a chain,** each of the seven worked as a middle hop and as the exit hop, with a later hop
  given by name, and seven of them together. What only the exit hop decides — zero-length
  datagrams, a reply from another port — follows the exit hop's row.
- **In supervisor mode,** each carried the static matrix, the fidelity test, the DNS redirect and a
  static Go client, with the same results as the shim. Chains were not run supervised.
- Configurations and full results: [`docs/INTEROP-CHECKLIST.md`](docs/INTEROP-CHECKLIST.md) §12,
  and §13 for chains.
  `make interop` repeats the runs (needs Docker). Proxies are tested as black boxes; do not read
  GPL source while working on udpchains ([`CONTRIBUTING.md`](CONTRIBUTING.md)).

## Name resolution

This section is about the shim. In supervisor mode the program's own resolver runs; see
[Name lookups when supervised](#name-lookups-when-supervised).

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

## Supervisor mode: static and Go programs

A shim cannot see a statically linked program, a Go program, or one making system calls without
libc. `--supervise` (or `supervise = yes`, or `UDPCHAINS_SUPERVISE=1`) runs such a program, or any
other, under a supervisor instead:

```sh
UDPCHAINS_DNS=9.9.9.9 udpchains --supervise -p 127.0.0.1:1080 ./static-client
```

- **It is never chosen automatically.** The same configuration, chains and credentials apply, and
  the program is not given the shim.
- **Requirements:** Linux 5.14 or later, x86-64, Yama `ptrace_scope` of 1 or less (the default),
  a container runtime that allows a seccomp filter and `ptrace`, and a program not already being
  traced. Otherwise `udpchains` refuses to run the program; it never runs it unsupervised.
- **Fail-closed:** if `udpchains` is killed, the program is killed with it. A test captures the
  wire while that happens, and sees nothing sent.
- **How it works:** the program runs under a seccomp filter that selects its socket calls.
  `udpchains`, attached as its tracer, handles each one while the calling thread is stopped, so a
  signal cannot come between what is done for a call and what it returns: no datagram is lost to
  a signal, no send is repeated, no `close` left undone. The supervisor makes each UDP socket
  itself, at descriptor 768 and up, and wraps and unwraps its datagrams as the shim does. A
  receive with nothing queued waits in the program's own kernel, so `SO_RCVTIMEO`, `EINTR` and
  `SA_RESTART` behave exactly as on an unproxied socket. Threads, `fork`, `vfork`, `clone` and
  `exec` are followed.

### Name lookups when supervised

The program runs its own resolver (glibc's, musl's, Go's), which reads `/etc/resolv.conf`.

- **A query to the system resolver** — port 53 of a loopback address, or of a nameserver listed in
  `/etc/resolv.conf`, which is read again when it changes — goes through the proxy to `dns`
  instead. Its reply is reported as coming from the address the program asked, so the resolver
  accepts it.
- **Without `dns`,** such a query fails with `ENETUNREACH`, so lookups fail; nothing goes
  anywhere directly.
- **Port 53 anywhere else** (`dig @9.9.9.9`) is proxied as addressed.
- **TCP to the system resolver's port 53** — how resolvers ask again after a truncated answer,
  and how they always ask with `options use-vc` — goes to `dns` too, by SOCKS5 `CONNECT` through
  the proxy. The program's own socket is connected through the proxy and then used natively;
  `getpeername()` on it names the proxy. If the proxy refuses `CONNECT`, the connection fails, and
  the query goes nowhere.
- A resolver configured elsewhere than `/etc/resolv.conf` on a non-loopback address is proxied as
  addressed. A local DNS server's own entries (dnsmasq) are not used; `/etc/hosts` is.
- **Lookups handed to a local daemon** — systemd-resolved (`nss-resolve`), `nscd`, avahi
  (`mdns`) — would be resolved by the daemon, outside the proxy. The daemons' sockets are refused,
  as when a daemon is not running, so the lookup falls through to DNS and so to `dns`. This loses
  what the daemon adds (resolved's per-VPN routing of names, its cache, `.local` by multicast).
  `allow_resolver_daemons = yes` lets them through. Lookups resolved receives over D-Bus are not
  refused.

### How supervisor mode differs from the shim

| | Shim | Supervisor mode |
|---|---|---|
| Programs | dynamically linked | any, static and Go ones included |
| `io_uring` | bypasses the shim | refused with `ENOSYS`, for files too |
| System calls made without libc | bypass the shim | carried |
| Name lookups | answered by the shim, through `dns` | the program's own; queries to the system resolver go to `dns` |
| Cost of a UDP call | about 1 µs | tens of µs: a round trip to the supervisor |
| Debuggers, `strace` | work | cannot attach; `strace -f udpchains` refuses to start |

### What supervisor mode cannot do

- **It is not a sandbox.** A call let through after a check can be changed in between, from
  another thread. Like the shim, it keeps a program from leaking by accident; it does not contain
  one trying to escape.
- **A UDP socket received already connected from an unsupervised process, then written with
  `write`, `writev` or `pwritev2`, is sent directly.** Sends and connects on such a socket are
  refused with `EPERM`; those writes cannot be told apart from file writes without trapping every
  write.
- **An inherited UDP socket stops the program from starting,** so a service handed one by its
  service manager cannot be supervised.
- **A process that makes itself non-dumpable** (`ssh-agent`, `gpg-agent`) cannot be inspected: its
  connects and sends fail with `EPERM`, TCP included, with a diagnostic naming the cause.
- **No `gdb` or `strace` inside the supervision,** and a program that uses `ptrace` itself gets
  `EPERM`. A program built with LeakSanitizer cannot run its leak check.
- **Every send and connect, UDP or not,** and every call on a UDP socket, costs a round trip to the
  supervisor. While an association is set up, the program's other supervised calls wait.
- **A blocking `recvmmsg`** returns the datagrams already queued, at least one, rather than waiting
  for as many as asked.
- **Before Linux 6.9,** a thread with a descriptor table of its own (`unshare(CLONE_FILES)`) is
  refused its UDP calls.
- **x86-64 only** so far.
- Everything the shim refuses is refused here too: raw, packet, ICMP and UDP-Lite sockets,
  multicast and broadcast, `MSG_MORE` and GSO, `sendfile` and `splice` onto a UDP socket, and
  setuid and setgid programs.

## Security considerations

`udpchains` keeps UDP from bypassing the proxy. It does not protect the path to the proxy.

- **Credentials are sent in cleartext** (RFC 1929). For a remote proxy, use a trusted VPN such as
  WireGuard, or a proxy on this host. An SSH port forward carries the TCP control connection but
  not the UDP relay traffic.
- **A chain adds hops, not encryption.** See [Security of a chain](#security-of-a-chain).
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
| Statically linked binaries | No libc to interpose on. Use [supervisor mode](#supervisor-mode-static-and-go-programs). |
| Go binaries | Go makes system calls directly, not through libc. Use supervisor mode. |
| Programs making system calls without libc (inline assembly) | Same reason. Use supervisor mode. Calls through libc's `syscall()` are proxied by the shim. |
| setuid, setgid and file-capability binaries | The loader ignores `LD_PRELOAD` for them. `udpchains` refuses to run them. |
| `ping` (ICMP datagram sockets), UDP-Lite | SOCKS5 cannot carry them. Socket creation fails with `EPROTONOSUPPORT`. |
| Raw and packet sockets (`nmap`, `traceroute`) | SOCKS5 cannot carry them. Socket creation fails with `EPERM`, as it does without `CAP_NET_RAW`. |

### Traffic that bypasses the shim

Every intercepted datagram is proxied or fails; there is no bypass list. Two routes are not
intercepted:

- **`io_uring`.** Sends submitted through a ring go straight to the kernel. glibc has no wrapper to
  interpose on.
- **System calls made without libc** (inline assembly, Go, static binaries).

Supervisor mode sees both: it refuses `io_uring` and carries system calls made without libc.

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

- **Loopback destinations are resolved at the proxy host** (a chain's exit hop). A datagram to `127.0.0.1` reaches the
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
  gives `EBUSY`. They are close-on-exec. A chain can fill that range; see
  [Descriptors](#descriptors).
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
[compatible proxies](#compatible-proxies), which have since been tested as the hops of chains,
and with supervisor mode.
**Untested:** a proxy on another host, a chain across hosts, and an IPv6 destination beyond this
host's loopback.

### Not implemented

- SOCKS5 authentication methods other than none (`0x00`) and username/password (`0x02`),
  including GSSAPI (`0x01`). A proxy selecting one is refused with a diagnostic.
- Chains that skip a dead hop or pick hops at random (proxychains' `dynamic_chain` and
  `random_chain`). Chains are strict ([`DECISIONS.md`](DECISIONS.md) D-37).
- Supervisor mode on architectures other than x86-64 (aarch64 is planned).
- Loopback and multicast bypass. Deferred ([`DECISIONS.md`](DECISIONS.md) D-05).

## Comparison with similar tools

| Tool | Approach | Licence | Also does |
|---|---|---|---|
| [Dante `socksify`](https://www.inet.no/dante/) | `LD_PRELOAD` | BSD-style | TCP |
| [proxychains-ng PR #570](https://github.com/rofl0r/proxychains-ng/pull/570) | `LD_PRELOAD` | GPL-2.0 | TCP; UDP through a chain of proxies. Unmerged pull request |
| [Proxando](https://github.com/NULLhere/Proxando) | `LD_PRELOAD` | GPL-2.0 | TCP; proxychains-style configuration |
| [graftcp](https://github.com/hmgle/graftcp) | `ptrace` | GPL-3.0 | TCP; static and Go binaries; HTTP proxies |

udpchains does UDP only, through one proxy or a strict chain: for dynamically linked programs
with its shim, and for static and Go programs in supervisor mode.

### UDP behaviour, measured

Measured 2026-10-19 in a Docker lab: client, SOCKS5 proxy (gost 3.3.1) and server on separate
addresses. The server logged the source of every datagram and DNS query. A control run with no
tool showed every datagram arriving directly. Versions: `dante-client` 1.4.3 (Ubuntu 24.04),
PR #570 at `04f6622`, Proxando at `c7ff4ac`, graftcp v0.8.3. udpchains' supervisor mode was added
on 2026-10-23, in the same lab, under Docker's default seccomp filter; the others were not run
again.

| | udpchains | udpchains `--supervise` | Dante `socksify` | PR #570 | Proxando | graftcp |
|---|---|---|---|---|---|---|
| IPv4 send × receive round trips through the proxy, of 54 | 54 | 54 | 35 | 0 | 20 | 24 |
| The same, IPv6 | 54 | 54 | 0 | 0 | 20 | 23–24 |
| `sendmmsg` | through the proxy | through the proxy | sent directly | — | sent directly | sent directly |
| Sender address the program sees | the real sender | the real sender | the real sender | — | the real sender | another address |
| `dig` with its own resolver | through the proxy | through the proxy | no answer | through the proxy | no answer | through the proxy |
| `getaddrinfo` | queried through the proxy | queried through the proxy | placeholder address | placeholder address | placeholder address | queried through the proxy |
| Static Go binary | sent directly | through the proxy | sent directly | sent directly | sent directly | through the proxy |
| Proxy stopped: datagrams that reached the server directly | none | none | IPv6, `sendmmsg` | none | `sendto`, `sendmmsg` | `sendmmsg` |

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
  falls back to direct DNS; `--select_proxy_mode only_socks5` prevents it. With udpchains'
  supervisor mode, the only tools here that handle a static Go binary.
- **udpchains `--supervise`:** the same results as the shim, and the static Go binary carried
  too; with the proxy stopped, its sends failed and nothing arrived. Its `getaddrinfo` is glibc's
  own resolver, its query to the lab's nameserver sent through the proxy to `dns`.

Limits:

- The tests come from udpchains' own requirements. TCP, chains, HTTP proxies and other platforms
  were not measured, and static binaries only as the one Go client.
- udpchains' authors wrote the tests and configured every tool from its documentation.
- One proxy, one host, one run per tool. graftcp ran with Docker's seccomp filter disabled; with
  it, graftcp failed intermittently with ptrace errors.
- Corrections are welcome as issues with a better configuration.

`make compare` reruns the comparison ([`tests/compare/`](tests/compare/); needs Docker and
Python 3). Tool configurations are in `tests/compare/conf/`.

## How it works

The shim; supervisor mode is described [above](#supervisor-mode-static-and-go-programs).

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
- Through a chain, the shim reaches each later hop with `CONNECT` through the hops before it, and
  each datagram carries one header per hop, nested, every layer checked on the way back.
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
| [`docs/FUTURE-UDP-CHAINS.md`](docs/FUTURE-UDP-CHAINS.md) | background to multi-hop chains |
| [`docs/FUTURE-STATIC-BINARIES.md`](docs/FUTURE-STATIC-BINARIES.md) | background to supervisor mode |
| [`CHANGELOG.md`](CHANGELOG.md) | changes and known limitations |
| [`SECURITY.md`](SECURITY.md) | reporting a vulnerability |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | contributing, and the clean-room rule |

## Licence

MIT; see [`LICENSE`](LICENSE).

Written clean-room from RFC 1928, RFC 1929 and the Linux man pages. No code was taken from
`proxychains-ng` or `Proxando` (both GPL-2.0), and contributions must not derive from them.

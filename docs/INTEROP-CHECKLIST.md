# Interop checklist — manual tests against a real proxy

TST-04 and acceptance criterion 4 are the open items in
[`TRACEABILITY.md`](TRACEABILITY.md). The automated suite proves conformance to the RFC *as this
project reads it*, against a fixture that shares an author with the code under test — which is
exactly how the D-14 (v4-mapped `ATYP`) defect survived 108 green matrix cells. Everything here has
to be run by hand against a real proxy.

Tests are grouped by **what property they exercise**, not by tool, because several tools prove the
same thing and one is usually enough.

Run everything with `-v` and keep the output. The per-datagram debug line names the destination, the
`ATYP` byte and the relay, which is what makes a silent non-delivery diagnosable.

---

## 0. Already done

| | Result |
|---|---|
| `nc -u` to a remote listener | ✅ passed — found D-14 |
| TFTP, 10 MB file | ✅ passed — port switch, ~20 000 datagrams each way, strictly sequential so any loss or reordering would have stalled or corrupted it |
| `dig myip.opendns.com` (§1) | ✅ passed 2026-08-18 — the resolver reported the **proxy's** egress address, not the host's. First proof the traffic traverses the tunnel rather than merely arriving |
| `iperf -u` rate sweep (§2) | ✅ passed 2026-08-18 — 0% loss to 15 Mbit/s; the cliff above it is the proxy's tunnel ceiling, attributed by kernel counters on both hosts. Closes the burst gap. A direct (unproxied) run to the same host saturated at ~17.5 Mbit/s, so the tunnel delivers ~94% of raw path capacity |
| `ntpdate -q` (§4) | ✅ passed 2026-08-19 — stratum-2 offsets accepted. The only test so far run by a client that validates a reply's **source address** rather than just its port |
| dual-stack → v4-mapped (§6a) | ✅ passed 2026-08-19 — `ATYP 0x01` with a 10-byte header from an `AF_INET6` socket. D-14 confirmed fixed against the real proxy, outbound direction |
| Seven other proxies, on this host (§12) | ✅ run 2026-10-19 — Dante, 3proxy, gost, Xray, sing-box, hev-socks5-server and shadowsocks-rust. No proxy-specific udpchains defect; one general `errno` bug found and fixed. Found per-proxy datagram limits, above which the proxy silently truncates; four proxies that drop zero-length datagrams; and Dante port-restricted by default. Also covers `ATYP 0x04` to `::1`, the resolver's `CONNECT` fallback, and idle expiry |

TFTP is **lockstep**: one block, wait for the ACK. It never has more than one datagram in flight, so
despite the volume it says nothing about burst behaviour, receive-queue pressure, or batching. That
is the main gap the tests below close.

---

## 1. Prove the traffic is genuinely proxied

Everything so far proves datagrams *arrive*. Nothing yet proves they took the tunnel.

First the baseline, **without** the shim, so you know the target is reachable at all:

```sh
dig +short myip.opendns.com @208.67.222.222        # returns this host's egress address
```

Then through the shim:

```sh
./udpchains -v -p <proxy-host>:<port> dig +short myip.opendns.com @208.67.222.222
```

**Pass:** the two answers differ, and the second is the **proxy's** egress address. This is the
cheapest possible end-to-end proof of proxying, and it is worth running first — everything below
assumes it holds.

✅ **Passed 2026-08-18.** The addresses are deliberately not recorded here; the observation is that
they differed and the proxied one was the VPS. Together with FR-F-02 (the application sees the true
remote source, not the relay) this closes the loop: the datagram left through the tunnel *and* was
reported back honestly.

Use the resolver's **numeric** address, not `@resolver1.opendns.com`. A hostname makes `dig` consult
the system resolver first, and on a systemd-resolved host that means a datagram to `127.0.0.53` —
which under the shim is resolved *at the proxy* and hits the loopback caveat in the README. The test
then fails before it has begun, for a reason that has nothing to do with what it is measuring.

If OpenDNS is unreachable from your network, any of these answer the same question (all numeric):

```sh
dig +short TXT o-o.myaddr.l.google.com @216.239.32.10    # ns1.google.com
dig +short whoami.akamai.net @193.108.88.1               # ns1-1.akamaitech.net
dig +short ch txt whoami.cloudflare @1.1.1.1
```

A STUN client (`stunclient`, `turnutils_stunclient`) gives the same answer if one is available.

---

## 2. Burst and throughput — the gap TFTP leaves

Sweep the rate rather than picking one — a single number cannot distinguish a defect from a
saturation ceiling, and the shape of the curve can:

```sh
for b in 5M 10M 15M 20M; do
  echo "== $b =="
  ./udpchains -p $P iperf -u -c <host> -b $b -l 1200 -t 10 -i 1
done
```

Do **not** add `-v`: it emits a debug line per datagram, and tens of thousands of them distort the
measurement.

Loss alone does not attribute blame, so bracket the run with kernel UDP counters on **both** hosts.
There are three places a datagram can die and each is visible somewhere different:

| Where | Drop point | Seen by |
|---|---|---|
| A — client | shim's `sendto` → the proxy's local relay socket overflows | client `netstat -su` |
| B — tunnel | the proxy discards internally rather than backpressuring | **neither** |
| C — server | the proxy's `sendto` → the receiving app's socket overflows | server `netstat -su` |

```sh
netstat -su | grep -iE 'receive buffer errors|packet receive errors'   # before, on both hosts
# ...run the sweep...
netstat -su | grep -iE 'receive buffer errors|packet receive errors'   # after, on both hosts
```

Counters are system-wide, so take the baseline immediately before the run on an otherwise idle box.

**Watch for:** loss climbing sharply with rate, or the association dropping under load. Some loss is
normal for UDP; a cliff is not. A cliff with *zero* loss below it is a capacity ceiling, not a defect.

✅ **Passed 2026-08-18**, against the reference proxy with `iperf` 2 (not iperf3):

| offered | delivered | loss |
|---|---|---|
| 5M | 5.26 Mbit/s | 0/5465 (0%) |
| 10M | 10.5 Mbit/s | 0/10926 (0%) |
| 15M | 15.4 Mbit/s | 0/16387 (0%) |
| 20M | 16.5 Mbit/s | 3922/21848 (18%) |

Zero loss up to 15 Mbit/s, then a hard cliff at a ~16.5 Mbit/s ceiling. Client UDP error counters did
not move at all (0 → 0) and the server's moved by 16, so the ~3900 missing datagrams are accounted
for by neither kernel: case **B**, discarded inside the proxy's tunnel. The shim absorbed 21 Mbit/s
of offered load and wrote every datagram into the relay socket without that socket backing up.

Combined with the fail-closed property — `udpc_core_send` has no silent-drop branch, every failure
returns `-1` with an errno — the accounting closes: iperf handed the shim 21 849 datagrams, the shim
reported no errors, the client kernel dropped none, therefore all 21 849 reached the proxy. This is
the first test to exercise sustained concurrent datagrams rather than lockstep request/response.

---

## 3. Datagram size boundary (D-12)

`max_datagram` defaults to 8192. TFTP used 512-byte blocks, so this is untested territory.

```sh
udpchains curl -o out --tftp-blksize 8192 tftp://<host>/<file>   # large blocks, known-good path
udpchains iperf3 -u -c <host> -l 8192 -b 5M -t 10                # exactly at the limit
udpchains iperf3 -u -c <host> -l 9000 -b 5M -t 10                # over it
```

**Pass:** 8192 works; 9000 fails with `EMSGSIZE` rather than being silently dropped. If your proxy's
real limit is below 8192, datagrams in between vanish silently — set `UDPCHAINS_MAX_DATAGRAM` to the
proxy's actual limit. The association log line reports the configured value for exactly this reason.

The limits of seven proxies are measured in §12. Three of them truncate below the default 8192:
hev-socks5-server at 1 490, gost at 4 086 unless `udpBufferSize` is raised, and Xray at 8 182.

---

## 4. A client that validates the source address

`nc` ignores the source entirely; TFTP only uses the port. NTP checks that the reply came from the
server it asked.

```sh
dig +short pool.ntp.org | head -1                       # use a NUMERIC server below

./udpchains -v -p $P /usr/sbin/ntpdate -q <ntp-ip>      # note /usr/sbin, not on the user PATH
./udpchains -v -p $P ntpdig -d <ntp-ip>                 # same thing, one less layer
```

A numeric server address matters: a hostname is resolved through the shim against `127.0.0.53`,
which is resolved *at the proxy*. That happens to work with a local proxy and will mislead you with
a remote one.

**Pass:** a plausible offset. A rejection here means FR-F-02 is reporting something subtly wrong that
neither previous test could see.

✅ **Passed 2026-08-19.** Two runs against a stratum-2 server returned consistent offsets
(+0.126 s and +0.116 s, error bounds ~0.25 s). The offset itself is the assertion: NTP validates a
response's source address against the address it queried and discards a mismatch silently, so a
wrong source would have produced a timeout rather than a bad number.

Two incidental confirmations from the same `-v` output:

- `sent 48 payload bytes ... 58 bytes on the wire` — 48 is exactly an SNTP client packet and the
  10-byte delta is precisely the `ATYP 0x01` header (2 RSV + 1 FRAG + 1 ATYP + 4 addr + 2 port), so
  header construction is right and not merely tolerated.
- `association up: fd 3 via relay ...` names no destination, where iperf's named one. `ntpdig` uses
  an **unconnected** socket, so there is no destination at association time — a small confirmation
  that associations are per-socket, not per-destination (D-13).

`ntpdate` here is a `/bin/sh` shim that execs `ntpdig`, a Python script, so `shim ready` appears
twice: two `execve`s in one process, not double initialisation. `LD_PRELOAD` survives both and
CPython uses libc sockets, so interception works — but the process being proxied is `python3`.

---

## 4b. A genuinely remote proxy (D-05 R2, D-16)

Every other test here can be run with the proxy on this host. This one cannot: it needs the SOCKS5
listener reachable at the **proxy's own address**, which is usually a proxy config change rather than
a different `-p`. It is the only way `proxy_is_local` becomes false.

```sh
# precondition -- must NOT print "(local)"
./udpchains -v -p <remote-ip>:<port> true

# it still proxies at all
./udpchains -v -p <remote-ip>:<port> dig +short myip.opendns.com @208.67.222.222

# the loopback guard, warning form
./udpchains -v -p <remote-ip>:<port> nc -u 127.0.0.1 9999

# the loopback guard, error form
UDPCHAINS_STRICT_LOOPBACK=1 ./udpchains -v -p <remote-ip>:<port> nc -u 127.0.0.1 9999
```

**Pass:** no `(local)`; the guard warns, then refuses with `ENETUNREACH` under `strict_loopback`; and
the `dig` returns the proxy's egress address. The guard fires only on `connect()`-ed sockets, which
`nc -u` uses.

**Watch the relay address in every `association up` line.** If it is `127.0.0.1` while the proxy is
remote, the datagrams are going to *this* host's loopback and nothing will arrive — that is D-16.
The shim now substitutes the proxy address in that case; seeing a loopback relay from a remote proxy
after the fix means the substitution has regressed.

⚠️ **First attempted 2026-08-19: the guard passed, the run failed.** `proxy_is_local` was correctly
false and the guard produced exactly the right message — its first end-to-end exercise. But the proxy
advertised `BND.ADDR = 127.0.0.1`, which the shim took literally (**D-16**), so every datagram went
to local loopback. The resulting ICMP port-unreachable read as an expired association, and the
repeated re-association exposed a second defect (**D-17**): entries stranded by closes the shim never
saw, refused on reuse with a spurious `EMFILE`.

✅ **Re-run 2026-08-19 after the fixes: both are confirmed against the real proxy.** The substitution
fires (`proxy returned loopback relay 127.0.0.1:52711 ... using the proxy address instead`, and the
association line then names `<vps>:52711`), and the stale-entry reclaim produces exactly one line
with no `EMFILE` — dig retries three times and gives up honestly. The loopback guard passes in both
forms: it warns, and under `strict_loopback` it refuses with `ENETUNREACH`. Note the refusal surfaces
on the first **send**, not on `connect()`, because `connect()` on a UDP socket transmits nothing.

❌ **Still blocked, and now on the proxy side.** Datagrams reach `<vps>:52711` and nothing comes back.
The proxy's own log shows three associations opened and **zero datagrams received**, then an idle
close. It advertised `127.0.0.1` because that is where it actually bound its relay socket, so the
substituted public address is correct in principle and still has nothing listening on it.

SOCKS5 `UDP ASSOCIATE` requires the relay port to be reachable *from the client*. To locate it, run
this on the proxy host while an association is open:

```sh
ss -uanp
```

A relay bound to `127.0.0.1:NNNNN` means the proxy must bind `0.0.0.0` and advertise a routable
`BND.ADDR`. Bound to `0.0.0.0:NNNNN` means a firewall is dropping inbound UDP on ephemeral ports.
Neither is something the shim can work around.

---

## 5. Many short-lived sockets — association churn

Every UDP socket gets its own association and control connection (D-13). TFTP used one.

```sh
for i in $(seq 1 100); do udpchains dig +short +tries=1 @<resolver> test$i.example.com & done; wait
```

**Watch for:** the proxy's connection limit, file-descriptor exhaustion, or associations not being
released. Check the proxy log for opens without matching closes.

---

## 6. IPv6 destination — `ATYP 0x04` for real

Everything so far has been IPv4, so the 16-byte address form has only been exercised against the
fixture.

Two halves, and they are independent.

**(a) Dual-stack socket to an IPv4 destination — the D-14 fix from the other side.** Needs no IPv6
connectivity at all, and is the half that actually broke against a real proxy:

```sh
# listener
nc -u -l 5001

# client
./udpchains -v -p $P python3 -c '
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.sendto(b"PING\n", ("::ffff:<dest-ip>", 5001))
s.settimeout(3)
print(s.recvfrom(1500))' 2>&1 | grep -E 'ATYP|PING'
```

**Pass:** `ATYP 0x01`, **and** a 10-byte wire overhead. Check both — the byte count is independent of
the ATYP field, so a regression that encoded the 16-byte form would show 22 bytes of overhead even if
the ATYP byte looked right.

✅ **Passed 2026-08-19.** `sent 5 payload bytes ... (ATYP 0x01) ... 15 bytes on the wire`, and the
payload arrived. Destination and relay both printed as `[::ffff:...]`, which is correct and is worth
distinguishing from the bug: the shim *reports* addresses in the socket's own family, as the kernel
would, but *encodes* the family the address actually denotes. D-14 was those two being conflated.

Only the outbound direction was covered, since `nc -u -l` does not echo. Inbound v4-mapped source
*reporting* remains covered by TST-05 alone. To close that too, type a line into the listener after
the PING arrives — `nc -u -l` connects back to its first sender — and the client should print a
source of `('::ffff:...', 5001, 0, 0)` rather than timing out.

**(b) A genuine IPv6 destination.** Blocked on this host: it has no global IPv6 address, so the
16-byte form is still only exercised against the fixture.

```sh
./udpchains -v -p $P dig -6 +short myip.opendns.com @2620:119:35::35
./udpchains -v -p $P nc -6 -u <ipv6-host> <port>
```

**Pass:** `-v` shows `ATYP 0x04`, 22 bytes of overhead, and the exchange completes.

---

## 7. Idle longer than the proxy's expiry (FR-P-08)

Your proxy closes idle associations. That path has only been tested against the fixture.

```sh
udpchains -v nc -u <host> <port>
# send a line, confirm arrival
# wait ~90s, past the idle timeout
# send another
```

**Pass:** the second line arrives, and `-v` reports re-associating. **Fail:** it silently vanishes —
the pre-send liveness probe did not detect your proxy's teardown.

---

## 8. Fail-closed under real conditions (SEC-01/SEC-02)

The security property the project exists for, observed on the **wire** rather than at the
destination. TST-03 already asserts that zero datagrams arrive, by watching the destination; that
cannot see a datagram which leaves this host and goes somewhere else, because a leak to the wrong
address looks identical to no leak at all.

Automated, since getting this right by hand turns out to be harder than it looks:

```sh
sudo tests/test_failclosed_capture.sh [dest_ip] [dest_port]
```

**The positive control is the point.** The first case runs the client with **no shim** and requires
the capture to see traffic. A capture that sees nothing because the filter, interface or buffering is
wrong would pass every fail-closed assertion while proving nothing — and for a test whose purpose is
to prove *nothing was sent*, an artefact that looks like proof is the worst available failure. If the
control fails the script aborts and says the rest is meaningless.

✅ **Passed 2026-08-20.** Positive control captured 11 packets, exactly the datagram count
`leakclient` sends. Then, at the wire:

| scenario | sends | packets on the wire |
|---|---|---|
| proxy never existed | all fail | **0** |
| TCP accepted, `UDP ASSOCIATE` refused | all fail | **0** |
| shim loaded, unconfigured | all fail | **0** |

These three do not depend on which proxy implementation is in use — they are about what the shim does
when no working proxy is available — so this is evidence about `udpchains` itself rather than about
the fixture.

Three things cost real time getting here, and are worth knowing before running it elsewhere:

- **`--immediate-mode` is required.** libpcap on Linux uses a TPACKET_V3 ring that retires blocks on
  a timer. Stopping the capture shortly after the traffic discards unretired blocks and reports
  `0 packets captured, 0 dropped` — which reads exactly like a clean run. This produced three
  consecutive false failures of the positive control, which is the only reason it was noticed.
- **Capture broadly, filter offline.** An in-kernel filter that silently matches nothing is
  indistinguishable from a clean run. The script captures all UDP and applies the destination match
  when reading the file back, so a miss shows up as captured-but-unmatched packets it can print.
- **Capture on the route's real interface**, not the `any` pseudo-device.

### What this still cannot show

A shim that sends a datagram **both** ways round — correctly to the relay *and* directly — is not
detectable with a proxy on this host, because a co-located proxy relays the datagram onward from the
same interface. A packet to the destination is then expected behaviour, indistinguishable from a
leak. Asserting zero there fails against a correctly working system.

It needs a proxy on another host, where any packet leaving this one for the destination is
unambiguous:

```sh
REMOTE_PROXY=<host:port> sudo tests/test_failclosed_capture.sh <dest> <port>
```

Still outstanding. It is the last thing TST-03 structurally cannot see.

---

## 9. Negative tests — verify the failures are clean

These are **expected** to fail. What matters is that they fail promptly and legibly rather than
hanging or corrupting data.

```sh
udpchains -v curl --http3 -sS -o /dev/null https://cloudflare-quic.com/   # QUIC: §8 non-goal
udpchains -v traceroute -U <host>                                        # needs ICMP back
udpchains -v avahi-browse -at                                            # multicast
```

QUIC is the most valuable of the three: it is the busiest `sendmmsg`/`recvmmsg` path any real client
produces, so even its failure exercises code nothing else reaches. Multicast must fail with
`ENETUNREACH` and a diagnostic naming the reason, never a hang.

---

## 10. Long-lived, high-volume, userspace VPN

The most demanding realistic workload, if you have somewhere to point it:

```sh
udpchains openvpn --config <client.ovpn>     # UDP mode
```

Long-lived association, continuous bidirectional traffic, MTU-sized datagrams, and its own keepalive
and rekeying. Note that **WireGuard is not a substitute** — it runs in the kernel and never touches
libc, so the shim cannot see it at all.

---

## 11. Name resolution through a real proxy (D-22)

The shim now answers libc lookups itself, sending DNS through the proxy. That path has run only
against the fixture resolver and fixture proxy, on one host.

```sh
# a random name, so no cache along the way answers it
N=udpc-$RANDOM.example.org

./udpchains -v -p $P env UDPCHAINS_DNS=9.9.9.9 getent ahosts example.org
UDPCHAINS_DNS=9.9.9.9 ./udpchains -v -p $P getent ahosts $N    # NXDOMAIN, through the proxy
```

Meanwhile, on this host:

```sh
sudo tcpdump -ni any port 53
```

**Pass:** `example.org` resolves; `-v` shows a `resolver association up` line naming the relay; and
tcpdump shows **no** packet to port 53 from this host. Every query leaves inside a SOCKS datagram
to the relay. The capture script's D-22 case (`sudo tests/test_failclosed_capture.sh`) automates the
leak half of this.

**Also worth running:** a lookup whose answer exceeds 1232 bytes, which exercises the TCP fallback
through the proxy's `CONNECT`. `dig +short TXT` of a large SPF record from outside the shim will
find one. Then `getent ahosts` of a name with many A records. Record whether the proxy supports
`CONNECT` at all: D-22 fails such lookups when it does not.

---

## 12. Other proxies, on this host (2026-10-19)

Seven more SOCKS5 implementations, each run on the same host as the client. This covers proxy
*diversity*: each was written by different people from the reference proxy and from each other.
It does not cover a proxy on another host (§4b), which is still owed.

| Proxy | Version | How it was run |
|---|---|---|
| Dante (`danted`) | 1.4.3 (Ubuntu 24.04 `dante-server`) | Docker, `ubuntu:24.04` plus the package |
| 3proxy | 1.0.1 | Docker, `3proxy/3proxy` |
| gost | 3.3.1 | Docker, `gogost/gost` |
| Xray | 26.3.27 | Docker, `ghcr.io/xtls/xray-core`, `socks` inbound and `freedom` outbound |
| sing-box | 1.14.3 | Docker, `ghcr.io/sagernet/sing-box`, `socks` inbound and `direct` outbound |
| hev-socks5-server | 2.13.1 | Release binary for `linux-x86_64`, in an `alpine` container |
| shadowsocks-rust | 1.25.0 | Docker, `sslocal` (SOCKS5, `-U`) in front of `ssserver` (`-U`), both on this host |

Every container used `--network host`, so the proxies relayed to the fixtures on this host's
loopback. Each was black-box tested: only its configuration and its own documentation were read,
never its source (D-01).

### What was run against each

Each proxy got the same runs. The integration binaries from `make test` were pointed at the real
proxy with `-p` instead of at `socks5d`, and the fixture echo and DNS servers stayed the
destinations:

- `test_matrix` (108 cells, IPv4 and IPv6), `test_fidelity`, `test_portswitch`, `test_lifecycle`,
  `test_thread`, and `tests/test_realtools.sh` (`dig`, `nc -u`);
- `test_resolve main` against `dnsd`, which counted 110 UDP queries arriving through the relay and
  one TCP query through the proxy's `CONNECT`;
- a size sweep of one datagram each of 0 to 65 497 bytes, with `max_datagram` at its default and at
  65 507;
- username/password authentication with each proxy that supports it (all but shadowsocks-rust's
  `sslocal`): the right password passes the matrix, and a wrong password or no credentials
  fails the send;
- fail-closed: a steady sender at 10 datagrams a second, with the proxy container killed after 2 s.
  Then the same with the proxy started again 3 s later (gost);
- idle expiry (FR-P-08): a round-trip, 75 s of silence, then a round-trip on the same socket. Also
  10 s of silence against a 4 s UDP timeout, where the proxy has a setting for one;
- `dig @9.9.9.9` and `UDPCHAINS_DNS=9.9.9.9 getent ahosts example.org`, out to the internet
  through the proxy.

### Results

| | Dante | 3proxy | gost | Xray | sing-box | hev | ss-rust |
|---|---|---|---|---|---|---|---|
| Matrix, 108 cells | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Lifecycle, threads, `dig`, `nc -u` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Fidelity | ✅ | zero-length ✗ | ✅ | zero-length ✗ | ✅ | zero-length ✗ | zero-length ✗ |
| Port switch (TFTP pattern) | ✗ by default, ✅ with `udp.connectdst: no` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Largest payload delivered whole | ≥ 65 497 | 16 326 | 4 086 by default, ≥ 65 497 with `udpBufferSize=65535` | 8 182 | 16 122 | 1 490 | 65 000 |
| Over `max_datagram`: `EMSGSIZE` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| IPv6 destination, `ATYP 0x04`, 22-byte header | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Resolver: UDP, and TCP fallback over `CONNECT` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Authentication: accepted / refused | ✅ / `EACCES` | ✅ / `ECONNRESET` | ✅ / `EACCES` | ✅ / `EACCES` | ✅ / `EACCES` | ✅ / `EACCES` | not tested |
| Proxy killed: nothing arrives afterwards | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Idle 75 s | ✅ | ✅ | ✅ | ✅ | ✅ | ✅, re-associated | ✅ |
| Idle 10 s against a 4 s UDP timeout | ✅, re-associated | — | — | ✅ | ✅, re-associated | ✅, re-associated | ✅ |
| `dig @9.9.9.9`, `getent` through `9.9.9.9` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

Every ✗ is the proxy's own behaviour, and is explained below. The one udpchains defect the runs
found is not specific to any proxy, and is described under *A killed proxy leaks nothing*.

### What differs between proxies

**Each proxy has its own largest datagram, and silently truncates anything bigger.** Each proxy
reads the client's datagram into a fixed buffer. A datagram larger than that buffer is cut down to
fit and forwarded, with no error to anyone. The receiver gets a shorter datagram, and the shim
cannot detect it, because the cut happens after the datagram has left. The truncation was seen at
the destination, not only in the echo:

| Proxy | Largest IPv4 payload forwarded whole | Notes |
|---|---|---|
| hev-socks5-server | 1 490 | A 1 500-byte buffer, less the 10-byte header. 1 478 for an IPv6 destination |
| gost, default | 4 086 | `udpBufferSize` defaults to 4 096. Set `udpBufferSize=65535` and nothing was cut |
| Xray | 8 182 | 8 192 less the header, so the default `max_datagram` of 8 192 is 10 bytes too large |
| sing-box | 16 122 back, 16 374 out | the return direction is the smaller |
| 3proxy | 16 326 | |
| Dante, gost (65 535), shadowsocks-rust | ≥ 65 000 | 65 497 also passed, except through shadowsocks-rust, where it got no reply. Its encrypted framing between `sslocal` and `ssserver` probably pushes that datagram past the 65 507 limit |

**Set `max_datagram` no higher than the proxy's limit** (D-12). Then an oversized send fails with
`EMSGSIZE` instead of arriving truncated. With the default 8 192, hev, gost at its default and Xray
will truncate. This is what §3 warns about, and it is now measured.

**Zero-length datagrams** (FR-F-06) are dropped by 3proxy, Xray, hev and shadowsocks-rust. The
shim sends the 10-byte header-only datagram, and nothing reaches the destination. Dante, gost and
sing-box forward it. A protocol that uses empty datagrams as keepalives will not work through the
four that drop them.

**Dante 1.4.3 is port-restricted by default.** Its debug log shows it `connect()`ing its outbound
UDP socket to the first destination, so the kernel discards a reply from any other port, and the
TFTP pattern fails exactly as the README's inbound-policy table predicts. With
`udp.connectdst: no` in `sockd.conf`, the reply from the switched port is delivered and
`test_portswitch` passes all 12 checks. The six other proxies accepted it by default.

**3proxy closes the connection on an authentication failure,** rather than replying with a
failure status, so a wrong password or a missing one fails the send with `ECONNRESET`, not
`EACCES`. As §6.4 of DESIGN.md says, `ECONNRESET` is what a proxy closing mid-handshake gives. It
also gives no diagnostic naming authentication as the cause.

**Idle expiry differs, and both kinds work.** Dante (`timeout.io.udp`), hev (its default 60 s,
or `udp-read-write-timeout`) and sing-box (`udp_timeout`) close the control connection when the
association goes idle. The shim saw that before the next send and re-associated (FR-P-08). Xray
(`policy.levels.0.connIdle`) and shadowsocks-rust (`--udp-timeout`) kept the association, and the
send after the silence went straight through.

**A killed proxy leaks nothing.** In all seven cases, every send after the kill failed and no
datagram reached the destination. With gost started again, the same socket re-associated and
carried traffic again.

One finding was about udpchains itself, though it was not a leak: with the proxy down, sends
failed with `ECONNRESET`, where §6.4 of DESIGN.md says the `errno` should be the connect's own
(`ECONNREFUSED`). It happened with no proxy listening at all, so it was not specific to any proxy.
It is now fixed: the shim reads `SO_ERROR` once the connect's poll reports an error, and a test in
`unit-socks5` covers it.

### What this does not show

- **A proxy on another host.** Each relay was on this host's loopback, so §4b, D-16's `BND.ADDR`
  substitution and the loopback guard were not exercised.
- **A global IPv6 destination.** The `ATYP 0x04` runs were to `::1`, through each proxy's IPv6
  loopback. This host has no global IPv6 address.
- **Throughput.** No rate sweep (§2) was run against these proxies.

### Configurations used

Dante, `sockd.conf`. For the authenticated instance, `socksmethod: username`, with a system user
added in the container:

```
logoutput: stderr
internal: 127.0.0.1 port = 11080
external: lo
external: ens33
external.rotation: route
clientmethod: none
socksmethod: none
user.privileged: root
user.unprivileged: nobody
client pass {
	from: 0/0
	to: 0/0
}
socks pass {
	from: 0/0
	to: 0/0
	command: bind connect udpassociate
	log: error
}
socks pass {
	from: 0/0
	to: 0/0
	command: udpreply
	log: error
}
```

Add `udp.connectdst: no` at the top for the port-switch case, or `timeout.io.udp: 4` for the
idle case. Each rule keyword must be on its own line; Dante 1.4.3 rejects `log:` on the same line
as `command:`.

3proxy, `3proxy.cfg` (`auth strong`, `users alice:CL:<password>` and `allow alice` for the
authenticated instance):

```
log
auth none
allow *
socks -p11081 -i127.0.0.1
```

gost. UDP is off unless `udp=true` is given:

```sh
gost -L 'socks5://127.0.0.1:11082?udp=true&udpBufferSize=65535'
gost -L 'socks5://alice:<password>@127.0.0.1:12082?udp=true&udpBufferSize=65535'
```

Xray. UDP is off unless `"udp": true` is set:

```json
{"inbounds": [{"listen": "127.0.0.1", "port": 11083, "protocol": "socks",
   "settings": {"auth": "noauth", "udp": true, "ip": "127.0.0.1"}}],
 "outbounds": [{"protocol": "freedom"}]}
```

For authentication, `"auth": "password", "accounts": [{"user": "alice", "pass": "<password>"}]`.

sing-box. The `socks` inbound carries UDP with no extra setting:

```json
{"inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": 11084}],
 "outbounds": [{"type": "direct"}]}
```

For authentication, `"users": [{"username": "alice", "password": "<password>"}]`.

hev-socks5-server, `main.yml` (`auth: {username: alice, password: <password>}` for the
authenticated instance):

```yaml
main:
  workers: 4
  port: 11085
  listen-address: '127.0.0.1'
misc:
  log-level: warn
```

shadowsocks-rust. `-U` enables UDP on both ends:

```sh
ssserver -s 127.0.0.1:18388 -m aes-256-gcm -k <key> -U
sslocal  -b 127.0.0.1:11086 -s 127.0.0.1:18388 -m aes-256-gcm -k <key> -U
```

## Reporting a failure

Capture, in this order:

1. `udpchains -v` stderr — especially the `sent N payload bytes to <dst> (ATYP 0x..)` lines.
2. The **proxy's** log for the same window. Several failures so far have been visible only there.
3. `tcpdump` on loopback for the relay port, if the question is whether the datagram left at all.

The pattern to watch for is a send that succeeds, an association that stays healthy, and nothing
arriving. That signature has now appeared twice — once as a shim defect (D-14) and once as a proxy
policy (port-restricted inbound filtering) — and only the proxy's log distinguishes them.

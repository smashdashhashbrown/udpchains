# Future requirement — multi-hop UDP chains (FR-P-10)

**Status:** in progress after 0.1.0. The requirements in §4 have moved to §2a of
[`UDP-PRELOAD-REQUIREMENTS.md`](../UDP-PRELOAD-REQUIREMENTS.md), which is now the reference for them,
and the design questions in §5 are decided in D-37 to D-42. Steps 1 to 3 of §7 are done: the
records, chain configuration with its handoff to the shim, and chain setup in `socks5.c`. This
document stays as the background and estimate.
**Written:** 2026-10-19, against the 0.1.0 candidate (`aa30ddf`). Line counts and file references
are as of that commit; recheck them before starting.

This is FR-P-10 worked out far enough to start from: what the feature is, who it is for, draft
requirements, what it changes in the current design, and an estimate. When the work begins, the
draft requirements move into [`UDP-PRELOAD-REQUIREMENTS.md`](../UDP-PRELOAD-REQUIREMENTS.md), and
each design question below gets a decision record in [`DECISIONS.md`](../DECISIONS.md).

---

## 1. What it is

Today every datagram goes through one proxy:

```
app ──UDP──▶ A's relay ──▶ target
   [hdr: target | payload]
```

A chain sends it through several, in order. For A → B → target:

1. Open TCP to A, `CONNECT` through it to B's control port, negotiate with B inside that tunnel,
   and issue `UDP ASSOCIATE` to B. B returns its relay address.
2. Issue `UDP ASSOCIATE` to A on a control connection of its own. A returns its relay.
3. Wrap each datagram twice: an inner header for B naming the target, and an outer header for A
   naming B's relay.
4. Unwrap each reply twice, checking at each layer that it came from the relay it should have.

```
app ──▶ A's relay ──▶ B's relay ──▶ target
[hdr: B-relay | hdr: target | payload]
              [hdr: target | payload]
```

With n hops there are n control connections, hop k's tunnelled through hops 1 to k-1, and n
layers of header.

## 2. Who it is for

- **Pivoting**, in penetration tests and red-team work: reaching a network that is reachable only
  through a series of footholds. This is the main use, and where most of proxychains' users are. It
  lets UDP tools (DNS, SNMP, NTP, IKE) reach networks that today they can reach only by leaking, or
  not at all.
- **Operations behind jump hosts,** for the same reason.

**Not for anonymity.** SOCKS5 encrypts nothing. The first hop sees the inner headers, so it learns
the target as well as the sender, and it sees the tunnelled control connection to the next hop in
the clear, including that hop's RFC 1929 credentials. A chain hides the sender from the later
hops and the target, and nothing more. The documentation must say so.

## 3. Prior art

Checked 2026-10-19, from each project's own description only (D-01).

- **proxychains-ng PR #570** ("Support for SOCKS5 UDP_ASSOCIATE command", Synacktiv, presented at
  SSTIC 2025): client-side UDP chains through `LD_PRELOAD`. Open since June 2024, not merged. Its
  stated limits: SOCKS5 only, strict chains only, no Go binaries. GPL-2.0, so it must not be read.
- **Proxy-side chaining:** gost forwards UDP through a chain of its own nodes. That serves users
  who control the proxies. Client-side chaining is for when you do not, which is the pivoting case.

No released client-side tool chains UDP. Shipping this would make udpchains the first, and make
the name accurate.

## 4. Draft requirements

Priorities as in the requirements document, but within this feature: **M** means the feature is
not done without it.

| ID | Pri | Requirement | Verify |
|---|---|---|---|
| FR-CH-01 | M | The configuration SHALL accept an ordered list of proxies. A list of one SHALL behave exactly as 0.1.0 does: same wire bytes, same errors, same diagnostics. | integration |
| FR-CH-02 | M | **Strict chains only.** If any hop cannot be reached, negotiated or associated, the call SHALL fail with an `errno`. There SHALL be no mode that skips a dead hop (proxychains' `dynamic_chain`, `random_chain`): it silently changes the path (D-05). | integration |
| FR-CH-03 | M | Hop k (k ≥ 2) SHALL be reached by SOCKS5 `CONNECT` through hops 1 to k-1, and negotiated inside that tunnel, each hop with its own credentials. Credentials SHALL NOT be accepted on the command line (SEC-03), and the wrapper SHALL pass on where each password is, never the password (D-25). | integration |
| FR-CH-04 | M | The address of hop k (k ≥ 2) SHALL be sent to hop k-1 as given, a name as `ATYP 0x03`, and SHALL NOT be resolved on this host. A local lookup leaks which proxies are in use, and an internal name may resolve only inside the remote network. | integration |
| FR-CH-05 | M | A sent datagram SHALL carry n headers: the target innermost, then each hop's relay outwards. The payload SHALL still not be copied (D-11). | unit |
| FR-CH-06 | M | On receive, every layer SHALL be checked: `FRAG` is 0, the header is well formed, and its source is the relay the next layer belongs to. A datagram failing any check at any layer SHALL be dropped and never partly delivered. Only the innermost source SHALL be reported to the program. | unit |
| FR-CH-07 | M | The D-16 relay fixup SHALL apply per hop. A wildcard relay from hop k means hop k's own address. A loopback relay from hop k (k ≥ 2) is usable only if hop k was itself given as a loopback address, so on the same host as hop k-1; otherwise it SHALL be replaced by hop k's address. | unit |
| FR-CH-08 | M | The loopback guard (D-05 R2) SHALL consider the **exit** hop: a loopback destination is resolved there. | unit |
| FR-CH-09 | M | All n control connections SHALL be checked for liveness. The loss of any one SHALL count as the loss of the association, and re-association (FR-P-08) SHALL rebuild the whole chain. | integration |
| FR-CH-10 | M | A forked child SHALL close its copies of all n control connections (D-31). All n SHALL be protected shim descriptors (D-26), and running out of protected descriptors SHALL be diagnosed, never become a direct send. | integration |
| FR-CH-11 | M | Name resolution (D-22) SHALL use the chain: UDP queries through the chained relays, and the TCP fallback through a chained `CONNECT`. | integration |
| FR-CH-12 | M | Diagnostics SHALL name the hop that failed. `-v` SHALL show the full path of each association. Never payload (NFR-05). | manual |
| FR-CH-13 | S | Chains SHALL be limited in length (8 is suggested), and the README SHALL explain that the smallest buffer of any hop limits the datagram size (INTEROP-CHECKLIST.md §12), on top of 10 to 22 bytes of header per hop. | unit, inspection |
| FR-CH-14 | S | The `[ProxyList]` stanza of FR-C-04 SHALL be accepted, so proxychains configurations carry over, for the strict-chain parts it shares. | unit |
| FR-CH-T1 | M | The leak test (SEC-02) SHALL be repeated with each hop of a 3-hop chain dead in turn, also on the wire (`test_failclosed_capture.sh`). Nothing may reach the destination. | integration |
| FR-CH-T2 | M | The hook matrix and the fidelity, lifecycle and thread tests SHALL pass through 2- and 3-hop fixture chains. | integration |
| FR-CH-T3 | M | Fault tests SHALL cover: expiry at a middle hop, `FRAG` set at an inner layer, a forged inner source behind a genuine outer one, and a hop refusing `CONNECT`. | integration |
| FR-CH-T4 | S | `make interop` SHALL run chains of real proxies, and record which can serve as an intermediate hop. | manual |

## 5. What changes in the current design

The central commitment holds. The program's own socket stays the only data socket (FR-I-07),
now pointed at the first hop's relay. The hook layer, the descriptor table, `poll`/`epoll`
transparency and the hook matrix do not change. `socks5d`'s `CONNECT` already relays any TCP
stream, so fixture chains need no new fixture.

| Module (lines at `aa30ddf`) | Change | Estimate |
|---|---|---|
| `socks5.c`/`.h` (823) | Negotiation runs over an existing stream as well as a new connection. New chain setup: for each hop, a stream to hop 1 extended by `CONNECT` through the hops before it. That is O(n²) handshakes, each step with its own timeout. An n-layer header codec. Per-hop relay fixup. `udpc_socks_connect` tunnels through the chain. | +300–450 |
| `assoc.c`/`.h` (571) | An association holds n control connections. Liveness, teardown, fork handling, protected descriptors and FR-P-08 re-association all handle n. | +120–180 |
| `core.c` (571) | **Send:** n headers in the thread-local header buffer, and in the `IOV_MAX` fallback copy. **Receive:** strip n headers with per-layer checks. Scratch becomes `max_datagram + n × 262`. | +100–150 |
| `config.c`/`.h` (819), `wrapper.c` (502) | A list of hops, each with an address and credentials, from repeated `proxy =` lines or `-p`, and possibly `[ProxyList]`. Handing configuration to the shim (D-27) and passing password locations (D-25) become per hop. | +250–350 |
| `resolve.c` (989) | The resolver pool wraps DNS headers itself (`resolve.c:314`, `:354`). Both move to the chain codec. | +60–120 |
| `fdtable.c` (515) | The protected band starts at 768, which leaves about 256 descriptors under the default limit of 1024. With n hops per socket, at most 256/n proxied sockets. Diagnose exhaustion, or raise the soft limit. | +20–40 |

**Decisions this revisits:** D-05 R2 (loopback guard), D-16 (relay fixup), D-25 (password
locations), D-26 (protected descriptors), D-27 (configuration resolved once, proxy resolved
locally), D-31 (fork), and FR-P-05 (declared address; for hops 2 to n it is always `0.0.0.0:0`).

**Decision records to write before coding:**

1. Strict chains only (FR-CH-02).
2. Hops after the first are resolved remotely (FR-CH-04), and how that amends D-27.
3. Relay fixup per hop, and the split of `proxy_is_local` into "the first hop is local" (D-16)
   and "the exit hop is local" (D-05 R2) (FR-CH-07, FR-CH-08).
4. Checking every layer on receive (FR-CH-06). This is where a mistake brings back the class of
   defect Proxando shipped: headers delivered as payload.
5. Chain length and the meaning of `max_datagram` (FR-CH-13).

## 6. Estimate

- **Production code:** 800–1,300 lines added or changed, out of about 8,700 (10–15%).
- **Tests:** about as much again: unit tests for the codec, fixup and configuration; the existing
  integration tests run through fixture chains; fault and leak scenarios; interop chains.
- **Documents:** the five decision records, a DESIGN.md section, README, man page, TRACEABILITY.
- **Time:** about two to three focused weeks, to the 0.1.0 standard: a failing test for each
  change, the sanitisers, interop.

## 7. Suggested order

1. The decision records. Move §4 into the requirements document.
2. Configuration and its handoff to the shim, where a chain of one is exactly 0.1.0, with the
   whole suite green. A safe point to stop.
3. Chain setup in `socks5.c`, unit-tested against chained fixtures.
4. The n-layer codec in `core.c` and the association lifecycle. Then the matrix through two hops.
5. The resolver, protected descriptors, and the leak and fault tests.
6. Interop chains, then documentation.

## 8. Risks and open questions

- **Real proxies as intermediate hops.** An intermediate hop must allow `CONNECT`, and it sees UDP
  arriving from the previous hop's outbound port rather than its control connection's, so a
  port-restricted hop drops it. Dante needs `udp.connectdst: no` (INTEROP-CHECKLIST.md §12). The
  Synacktiv slides list "Dante (no tunneling)" without explaining it. Only interop will tell.
- **Per-layer checking on receive** has to be exactly right; see decision 4 above.
- **D-27 was only recently settled.** Remote resolution of later hops changes it again.
- **Testing a real chain across hosts** needs at least two remote machines. D2 already needs one.
- **The name.** The requirements call `udpchains` a working name. If this feature is not built,
  the name promises something the tool does not do.

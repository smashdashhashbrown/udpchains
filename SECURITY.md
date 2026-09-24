# Security policy

`udpchains` exists to guarantee one thing: a program's UDP traffic goes through the proxy or
fails, and never goes out directly. A way around that guarantee is a vulnerability, and so is
anything that exposes credentials or corrupts memory.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | Yes |

## Reporting a vulnerability

**Please do not open a public issue.** Report it privately through GitHub:

1. Open the repository's **Security** tab.
2. Choose **Report a vulnerability**, or go straight to
   <https://github.com/smashdashhashbrown/udpchains/security/advisories/new>.

Only you and the maintainer can see the report. The fix is prepared in private, and the advisory,
with a CVE where one is warranted, is published when the fix is released. You will be credited
unless you ask not to be.

A useful report says:

- what happens, and what should have happened instead;
- the `udpchains` version or commit, the glibc version and the distribution;
- the proxy used, if one was involved;
- the smallest program or command that shows it. For a leak, a packet capture showing the datagram
  leaving directly is the strongest evidence.

## In scope

- Any path by which a datagram from an intercepted socket leaves **without** going through the
  proxy (SEC-01), including name lookups (D-22).
- A setuid, setgid or capability-endowed program run unproxied (SEC-06).
- The password reaching the command line, the environment of the program run, or a log.
- Memory corruption, use-after-free or crashes caused by input from the network: the proxy's
  replies, relayed datagrams or DNS answers.
- A way for a program to make the shim act on a descriptor that is not the socket it tracks.

## Known limitations, not vulnerabilities

These are documented in the README's *Security considerations* and *What does not work* sections.
They are design limits, not defects. A report showing one is worse than documented is welcome.

- RFC 1929 credentials cross the network in cleartext.
- Datagrams to and from the proxy's relay are not authenticated or encrypted.
- Raw sockets (`SOCK_RAW`) are not intercepted (D-18).
- `io_uring`, `sendfile`/`splice`, stdio on a UDP socket (`fdopen`), and sockets copied from
  another process with `pidfd_getfd` bypass the hooks and can send directly (D-21).
- A target confined by an LSM on `exec` may be denied the shim and run unproxied (D-19).
- Statically linked binaries, Go binaries and programs issuing raw system calls are not covered.

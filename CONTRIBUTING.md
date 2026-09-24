# Contributing to udpchains

Bug reports, fixes and interop reports are welcome. For a security problem, follow
[`SECURITY.md`](SECURITY.md) instead of opening an issue.

## The clean-room rule

`udpchains` is MIT-licensed and written clean-room (DECISIONS.md, **D-01**). The SOCKS5 client is
implemented from RFC 1928 and RFC 1929, and the rest from the Linux man pages.

- **Do not open, read, copy or paste from the source of `proxychains-ng` or `Proxando`,** or of any
  other GPL-licensed proxy tool, while working on this project. Describing what those tools *do*
  is fine. Reading their code to check an approach is not, because it taints the clean-room claim
  after the fact.
- **Every contribution must include this statement,** in the pull request description or in each
  commit message:

  > I wrote this contribution myself, and it is not derived from proxychains-ng, Proxando or any
  > other GPL-licensed source. I license it under the MIT licence.

A pull request without the statement cannot be merged.

## Building and testing

Linux with glibc 2.34 or later, and a C compiler. Nothing else is needed to build.

```sh
make                      # the shim and the wrapper
make test                 # unit and integration tests, against an in-repo fixture proxy
tests/run_sanitizers.sh   # ASan/UBSan, TSan, Valgrind and Helgrind
```

`tests/run_sanitizers.sh` runs `make clean`, so run it on a separate copy of the tree if you want to
keep your build. Without `valgrind` installed, the Valgrind and Helgrind stages are skipped, so
install it to run them. Some real-tool tests are also skipped when a tool is missing; the output
says which.

`sudo tests/test_failclosed_capture.sh` checks the fail-closed guarantee on the wire with
`tcpdump`. It needs root, so it is not part of `make test`. Run it for any change to the send path,
the resolver or descriptor tracking.

## What a change needs

- **A test that fails without it.** For a bug, show it failing against the code before the fix.
  Tests use the TAP helpers in `tests/tap.h`.
- **The whole suite passing,** and the sanitizers clean for anything touching threads, the fd
  table or memory ownership.
- **Documentation that matches.** A behaviour change updates the README, and the man page
  (`docs/udpchains.1`) if it is user-visible. A design choice gets a decision record in
  `DECISIONS.md`. A change to what a requirement's test covers updates `docs/TRACEABILITY.md`.
  Add a line under the next release in `CHANGELOG.md`.
- **Code that matches its surroundings:** C11, tabs, kernel-style braces, and the compiler
  warnings in the `Makefile`, which are errors.

## Fail closed

A change must never let a datagram out directly because something went wrong. If the shim cannot
proxy a datagram, the call fails with an `errno`. There is no bypass list and no fallback (D-05). A
change that adds one will not be accepted.

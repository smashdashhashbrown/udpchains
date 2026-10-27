# Working on udpchains

`udpchains` routes a program's UDP through a SOCKS5 proxy or chain, failing closed: an
`LD_PRELOAD` shim for dynamically linked programs, and a seccomp/`ptrace` supervisor
(`--supervise`) for static and Go ones.

## Where things are

- `README.md`: what it does, for users, and every known limitation.
- `DECISIONS.md`: every design decision, D-01 onwards, with its status, what was rejected, known
  limitations and how it was tested. Read the relevant record before changing a design.
- `docs/DESIGN.md`: how the code is built; §13 is supervisor mode.
- `UDP-PRELOAD-REQUIREMENTS.md` and `docs/TRACEABILITY.md`: the requirements, and the evidence
  each is met, including mutations tried.
- `CONTRIBUTING.md`: the clean-room rule, and how to run every kind of test.
- `docs/REVIEW-BACKLOG.md`: review findings, by ID, ticked with the commit that fixes them.
- `docs/FUTURE-STATIC-BINARIES.md`: supervisor mode's plan and history; §9 lists its accepted
  limitations.
- `CHANGELOG.md`: what changed, by release.

## Rules from the maintainer

- **Clean room** (D-01, `CONTRIBUTING.md`). Never open the source of proxychains-ng, Proxando,
  graftcp, sing-box, the proxies in `tests/interop/` and `tests/compare/`, or any other GPL tool.
  Design from man pages and RFCs. Kernel behaviour has so far been established from man pages and
  by experiment, not from kernel source.
- **No change to the code without the maintainer's approval.** A request such as "start on step 4"
  is approval for that work; a design change beyond it is proposed, not built. In a review,
  findings are recorded, not fixed, until the maintainer says which to fix.
- **Commit only when the maintainer says so,** after they have reviewed the change. End each
  commit message with a `Co-Authored-By:` line naming the model that wrote it, for example
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Do not push unless asked.
- **Stop processes by PID,** never with `pkill -f` or `killall`.
- **Interop with a second host is deferred** until every planned feature is built; there is no
  second host yet.
- **Report faithfully:** a skipped test is not a pass, and a claim made in the docs needs a test
  or a measurement behind it.

## Testing notes

- `make test` runs 26 groups; `tests/run.sh` prints each. The totals in `docs/TRACEABILITY.md` are
  copied from a run, never edited by hand.
- `tests/run.sh` exports `UDPCHAINS_QUIET=1`. A check that depends on what `udpchains` writes to
  stderr must run it with `-v`, or it passes vacuously. Try a mutation under `make test`, not only
  by running a script on its own.
- `tests/run_sanitizers.sh` runs `make clean`: rebuild afterwards, and do not run anything else
  from `build/` while it runs.
- `make interop` needs Docker; `tests/test_failclosed_capture.sh` needs root, so the maintainer
  runs it.
- Wrap supervised runs in `timeout -k`: the supervisor answers `SIGTERM` by passing it to its
  program, so a run that hangs may need `SIGKILL`.
- LeakSanitizer cannot run in a supervised program, which is traced; the tests turn it off there.
- New behaviour is checked with mutations: break it, show a test fails, restore it, and record the
  result in `docs/TRACEABILITY.md`.

## Where things stand (2026-10-26)

- 0.1.0 and 0.2.0 (multi-hop chains) are released. Supervisor mode (D-48 to D-55) is built for
  x86-64 and merged into `develop`, not yet released.
- `release_review` holds the comprehensive review of all code, documentation and tests before
  the next tag. Record findings in `docs/REVIEW-BACKLOG.md`, in a new section for this release,
  with IDs and severities as in the 0.1.0 review.
- Deferred by the maintainer: supervisor mode on aarch64 (FR-SV-16), and interop across hosts.

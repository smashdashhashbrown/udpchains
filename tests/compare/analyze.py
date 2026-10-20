"""analyze.py -- the verdicts for tests/compare/run.sh.

Each cell's verdict combines what the test client saw (did the reply come
back byte for byte, from the right sender?) with what the server logged (did
the datagram arrive from the proxy, or straight from the client?).  The
second is the one that cannot be taken on a tool's word.

usage: analyze.py <log directory> none <tool>...

Exits 1 if the control, "none", was not seen as direct: the lab could not
have detected a leak.
"""
import collections
import re
import sys

PROXY = {"10.77.0.20", "fd77::20"}
CLIENT = {"10.77.0.30", "fd77::30"}


def load_echo(path):
    """(tag, cell) -> the set of source addresses it arrived from."""
    seen = collections.defaultdict(set)
    for line in open(path):
        parts = line.split(None, 3)
        if len(parts) == 4 and parts[0] == "ECHO":
            m = re.match(r"T\|([^|]+)\|([^|]*)\|", parts[3])
            if m:
                seen[(m.group(1), m.group(2))].add(parts[1])
    return seen


def load_dns(path):
    """name -> the set of source addresses its queries came from."""
    seen = collections.defaultdict(set)
    for line in open(path):
        m = re.search(r"query\[\w+\] (\S+) from (\S+)", line)
        if m:
            seen[m.group(1)].add(m.group(2))
    return seen


def path(srcs):
    if not srcs:
        return "nothing arrived"
    if srcs & CLIENT:
        return "DIRECT"
    return "proxied" if srcs <= PROXY else "from " + ",".join(sorted(srcs))


def sections(path_):
    out, cur = {}, None
    try:
        lines = open(path_).read().splitlines()
    except FileNotFoundError:
        return out
    for line in lines:
        if line.startswith("## "):
            cur = line[3:].strip()
            out[cur] = []
        elif cur:
            out[cur].append(line)
    return out


def matrix(tool, sec, lines, echo):
    """Counts of 'verdict/path' over the cells of one matrix section."""
    res = collections.Counter()
    for line in lines:
        m = re.match(r"CELL (\S+) (\S+)(.*)", line)
        if not m:
            continue
        cell, verdict, rest = m.groups()
        detail = rest.split()
        if verdict in ("SENDERR", "NOREPLY") and detail:
            verdict += "(" + detail[0] + ")"
        res[verdict + "/" + path(echo.get((f"{tool}-{sec}", cell), set()))] += 1
    return res


def first_line(lines):
    return next((l for l in lines if l.strip()), "(no output)")[:40]


def main():
    out, tools = sys.argv[1], sys.argv[2:]
    echo = load_echo(f"{out}/echo.log")
    dns = load_dns(f"{out}/dns.log")
    control_ok = True

    for t in tools:
        up = sections(f"{out}/{t}.up")
        down = sections(f"{out}/{t}.down")
        warm = sections(f"{out}/{t}.warm")
        print(f"=== {t}")
        for sec, label, src in (("m4", "IPv4", up), ("m6", "IPv6", up),
                                ("f4", "IPv4, fortified", up),
                                ("w4", "IPv4, warm socket", warm)):
            if sec not in src:
                continue
            res = matrix(t, sec, src[sec], echo)
            good, total = res["OK/proxied"], sum(res.values())
            rest = ", ".join(f"{k} x{v}" for k, v in sorted(res.items())
                             if k != "OK/proxied")
            print(f"  matrix {label:18s} {good:2d}/{total} through the proxy   {rest}")
            if t == "none" and sec == "m4" and res["OK/DIRECT"] != total:
                control_ok = False

        for line in up.get("x4", []):
            m = re.match(r"CELL (\S+) (\S+)", line)
            if m:
                print(f"  {m.group(1):12s} {m.group(2)}")
        print(f"  dig          {first_line(up.get('dig', [])):40s} "
              f"query {path(dns.get(f'dig-{t}.example.test', set()))}")
        gai = dns.get(f"gai-{t}.example.test", set())
        print(f"  getaddrinfo  {first_line(up.get('gai', [])):40s} "
              f"query {path(gai) if gai else 'none sent'}")
        print(f"  Go static    {first_line(up.get('go', [])):40s} "
              f"{path(echo.get((f'{t}-go', 'go'), set()))}")

        direct = sorted(f"{k[0].rsplit('-', 1)[-1]}:{k[1]}" for k, v in echo.items()
                        if k[0] in (f"{t}-down", f"{t}-down6") and v & CLIENT)
        results = collections.Counter(l.split()[2] for s in ("leak", "leak6")
                                      for l in down.get(s, []) if l.startswith("LEAK"))
        print(f"  PROXY DOWN   send results {dict(results)}")
        print(f"               reached the server directly: {', '.join(direct) or 'nothing'}")
        print(f"               lookup sent directly: "
              f"{'yes' if dns.get(f'down-{t}.example.test', set()) & CLIENT else 'no'}; "
              f"dig sent directly: "
              f"{'yes' if dns.get(f'downdig-{t}.example.test', set()) & CLIENT else 'no'}; "
              f"Go: {path(echo.get((f'{t}-down-go', 'go'), set()))}")
        if t == "none" and len(direct) != 18:
            control_ok = False
        print()

    if not control_ok:
        print("CONTROL FAILED: with no tool, traffic was not all seen as direct, so this "
              "lab could not have detected a leak.  Ignore the results above.")
        return 1
    print("The control saw every datagram arrive directly, so a leak would have been detected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

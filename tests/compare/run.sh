#!/bin/bash
# run.sh -- compare udpchains with other tools that proxy a program's UDP.
#
# The README's "Comparison with similar tools" section is this script's
# output.  It runs the same tests under each tool in a Docker lab of three
# hosts on one network:
#
#   10.77.0.10  fd77::10  server: an echo server and a resolver, each logging
#                         the source of everything it receives
#   10.77.0.20  fd77::20  proxy:  gost, a SOCKS5 proxy with UDP ASSOCIATE
#   10.77.0.30  fd77::30  client: the tool under test, and the test client
#
# A datagram or query from 10.77.0.20 went through the proxy; one from
# 10.77.0.30 was sent directly.  The verdicts come from those logs, never
# from what a tool reports.  The first tool, "none", runs with no tool at all,
# and is the control: if it is not seen as direct, the lab cannot detect a
# leak, and the run stops.
#
# Fairness, and its limits, are discussed in the README section.  In short:
# the tests measure what udpchains was designed for, and udpchains' authors
# configured every tool.  Corrections to conf/ are welcome.
#
# The other tools are black boxes.  Two are built from GPL source inside the
# client image; that source is never to be opened (CONTRIBUTING.md, D-01).
#
# Opt-in, never part of `make test`: it needs Docker and Python 3, downloads
# images and source, and takes about 15 minutes for every tool.
#
# usage: make compare [COMPARE_ARGS="tool ..."]
#        tests/compare/run.sh [tool ...]
#
#   tool  any of: udpchains socksify pc570 proxando graftcp-auto
#         graftcp-strict (default: all).  The control always runs.
#
# Logs and the summary go to build/compare/.

set -u

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
HERE="$ROOT/tests/compare"
OUT="$ROOT/build/compare"
LABEL=udpchains-compare
NET=udpchains-compare
CLIENT_IMG=udpchains-compare/client
SERVER_IMG=udpchains-compare/server
GOST=gogost/gost@sha256:2344854f44e79ad2f19568fe4dc5f2ace88eebf259575347e08a887cee188ec5

ALL="udpchains socksify pc570 proxando graftcp-auto graftcp-strict"
TOOLS=""
for a in "$@"; do
	case " $ALL " in
	*" $a "*) TOOLS="$TOOLS $a" ;;
	*) echo "run.sh: unknown tool $a (have: $ALL)" >&2; exit 2 ;;
	esac
done
TOOLS="none ${TOOLS:-$ALL}"

for cmd in docker python3; do
	if ! command -v $cmd > /dev/null 2>&1; then
		echo "run.sh: needs $cmd; skipping the comparison" >&2
		exit 2
	fi
done
if ! docker info > /dev/null 2>&1; then
	echo "run.sh: needs a working Docker; skipping the comparison" >&2
	exit 2
fi

cleanup() {
	docker ps -aq --filter "label=$LABEL" | xargs -r docker rm -f > /dev/null 2>&1
	docker network rm "$NET" > /dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 130' INT TERM

rm -rf "$OUT"
mkdir -p "$OUT"

# The build context is only what the images need: udpchains' sources and the
# Makefile, so the client runs the working tree's udpchains, and this
# directory.
echo "Building the lab images (the first build fetches and compiles the other tools)..."
for img in server client; do
	name=$SERVER_IMG
	[ $img = client ] && name=$CLIENT_IMG
	if ! tar -C "$ROOT" -c src Makefile tests/compare |
		docker build -q -t "$name" -f "tests/compare/Dockerfile.$img" - \
			> "$OUT/build-$img.log" 2>&1; then
		echo "FATAL: the $img image did not build; see $OUT/build-$img.log" >&2
		exit 1
	fi
done

cleanup
docker network create --subnet 10.77.0.0/24 --ipv6 --subnet fd77::/64 "$NET" > /dev/null ||
	{ echo "FATAL: could not create the lab network" >&2; exit 1; }
docker run -d --name udpc-compare-server --label "$LABEL" --network "$NET" \
	--ip 10.77.0.10 --ip6 fd77::10 -v "$HERE/conf/dnsmasq.conf:/etc/dnsmasq.conf:ro" \
	"$SERVER_IMG" sh -c 'dnsmasq -k -C /etc/dnsmasq.conf 2> /tmp/dns.log & server 7000' > /dev/null
docker run -d --name udpc-compare-proxy --label "$LABEL" --network "$NET" \
	--ip 10.77.0.20 --ip6 fd77::20 \
	"$GOST" -L 'socks5://:1080?udp=true&udpBufferSize=65535' > /dev/null
sleep 2

client() {	# <tool> <phase>
	local opts=()
	# graftcp traces with ptrace.  Under Docker's default seccomp filter
	# it failed intermittently ("ptrace: No such process"), which looks
	# environmental, so it runs without the filter.
	case $1 in graftcp*) opts=(--security-opt seccomp=unconfined) ;; esac
	docker run --rm --label "$LABEL" --network "$NET" --ip 10.77.0.30 --ip6 fd77::30 \
		--cap-add SYS_PTRACE "${opts[@]}" \
		-v "$HERE/conf:/cfg:ro" -v "$HERE/conf/resolv.conf:/etc/resolv.conf:ro" \
		"$CLIENT_IMG" tools.sh "$@"
}

for T in $TOOLS; do
	echo "== $T"
	client "$T" up > "$OUT/$T.up" 2>&1
	docker stop -t 1 udpc-compare-proxy > /dev/null
	client "$T" down > "$OUT/$T.down" 2>&1
	docker start udpc-compare-proxy > /dev/null
	sleep 2
	[ "$T" = none ] || client "$T" warm > "$OUT/$T.warm" 2>&1
done

docker logs udpc-compare-server > "$OUT/echo.log" 2>&1
docker exec udpc-compare-server cat /tmp/dns.log > "$OUT/dns.log"
echo
python3 -I "$HERE/analyze.py" "$OUT" $TOOLS | tee "$OUT/summary"

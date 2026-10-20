#!/bin/bash
# run.sh -- interop against real third-party SOCKS5 proxies.
#
# The fixture proxy (D-06) shares an author with the code under test, so a
# green `make test` is not evidence of interop: D-14 survived 108 green matrix
# cells.  This runs the same integration tests against seven independently
# written proxies, each in Docker on this host, plus the checks only a real
# proxy can answer -- what it does to an oversized or empty datagram, and what
# reaches a destination while it is dead.  Results and their meaning are in
# docs/INTEROP-CHECKLIST.md section 12.
#
# Each proxy's known behaviour is an EXPECTATION here, not a failure: Xray
# truncating above 8182 bytes is reported "expected".  A proxy that changes --
# a new version that stops truncating, or starts -- is reported FAIL, because
# the README's compatible-proxies table is then wrong.
#
# The proxies are black boxes (D-01): this file holds only their
# configuration.  Do not read their source; several are GPL.
#
# Opt-in, never part of `make test`: it needs Docker and downloads images.
# Every image is pinned by digest, and the one downloaded binary by checksum.
#
# usage: make interop [INTEROP_ARGS="..."]
#        tests/interop/run.sh [--long] [--internet] [proxy ...]
#
#   --long      also idle each association for 75 s against the proxy's
#               default timeout (FR-P-08); adds about 80 s
#   --internet  also resolve real names through each proxy, via 9.9.9.9
#   proxy       any of: dante 3proxy gost xray singbox hev ssrust
#
# INTEROP_PORT_BASE (default 21080) sets the first of the ~50 local ports used.
# Logs are kept in build/interop/.

set -u

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
B="$ROOT/build"
W="$ROOT/udpchains"
PROBE="$B/interop_probe"
LOGS="$B/interop"
BASE=${INTEROP_PORT_BASE:-21080}

ALL="dante 3proxy gost xray singbox hev ssrust"
LONG=0
INTERNET=0
SELECTED=""
for a in "$@"; do
	case "$a" in
	--long) LONG=1 ;;
	--internet) INTERNET=1 ;;
	-h|--help) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	-*) echo "run.sh: unknown option $a" >&2; exit 2 ;;
	*)
		case " $ALL " in
		*" $a "*) SELECTED="$SELECTED $a" ;;
		*) echo "run.sh: unknown proxy $a (have: $ALL)" >&2; exit 2 ;;
		esac ;;
	esac
done
SELECTED=${SELECTED:-$ALL}

# --- pinned images -------------------------------------------------------------
#
# Pinned on 2026-10-19, the versions INTEROP-CHECKLIST.md 12 records.  To move
# to a newer proxy, change the digest, rerun, and update the README table and
# 12 with whatever the run reports as changed.

IMG_UBUNTU=ubuntu@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac
IMG_ALPINE=alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
IMG_3PROXY=3proxy/3proxy@sha256:03d16fb5ff91d4c7ae908179dfc716635765c81f1dd7d160c074e1f8d12bce97
IMG_GOST=gogost/gost@sha256:2344854f44e79ad2f19568fe4dc5f2ace88eebf259575347e08a887cee188ec5
IMG_XRAY=ghcr.io/xtls/xray-core@sha256:592ec4d11f656db95598d01e76dbcc6e002d67360b96a5436500a938230f52c7
IMG_SINGBOX=ghcr.io/sagernet/sing-box@sha256:80c639ba467885b28511fb7c980565c2d30a8752f778e7bc8abdbc91fbfd95ec
IMG_SSLOCAL=ghcr.io/shadowsocks/sslocal-rust@sha256:56786760f6a1bc447c3bcdcac94d5e2e2ffdbdaacce14c38e819003d8bb125dc
IMG_SSSERVER=ghcr.io/shadowsocks/ssserver-rust@sha256:22240c07d8ce3a36421ede770bd775dcc5fc56d5d829943196957b05452dc36f
# hev-socks5-server publishes binaries, not images.  The checksum is the one
# GitHub lists for the release asset.
HEV_VERSION=2.13.1
HEV_SHA256=9707a6d9e6419f6474173affa9d00b25a9ec61c9f320f2d19bb14a0a5a584bc5

# Test-only credentials, for the authenticated instances.
AUSER=interop
APASS=interop-pw
SSKEY=interop-ss-key

# --- what each proxy is known to do (INTEROP-CHECKLIST.md 12) ------------------
#
# WHOLE  largest IPv4 payload the proxy carries whole
# CUT    a size it truncates, or - if none was found below 65 507
# ZERO   deliver | drop, for a zero-length datagram (FR-F-06)
# PORTSW pass | fail, for a reply from a switched port (the TFTP pattern)
# AUTHE  errno when credentials are refused, or - if not tested
# IDLE   a setting that shortens the UDP timeout to 4 s, or - if none known

declare -A IDX WHOLE CUT ZERO PORTSW AUTHE IDLE
IDX=([dante]=0 [3proxy]=1 [gost]=2 [xray]=3 [singbox]=4 [hev]=5 [ssrust]=6)
WHOLE=([dante]=65497 [3proxy]=16326 [gost]=65497 [xray]=8182 [singbox]=16122 [hev]=1490 [ssrust]=65000)
CUT=([dante]=- [3proxy]=16327 [gost]=- [xray]=8183 [singbox]=16123 [hev]=1491 [ssrust]=-)
ZERO=([dante]=deliver [3proxy]=drop [gost]=deliver [xray]=drop [singbox]=deliver [hev]=drop [ssrust]=drop)
PORTSW=([dante]=fail [3proxy]=pass [gost]=pass [xray]=pass [singbox]=pass [hev]=pass [ssrust]=pass)
AUTHE=([dante]=EACCES [3proxy]=ECONNRESET [gost]=EACCES [xray]=EACCES [singbox]=EACCES [hev]=EACCES [ssrust]=-)
IDLE=([dante]=yes [3proxy]=- [gost]=- [xray]=yes [singbox]=yes [hev]=yes [ssrust]=yes)

# Ports, per proxy index i: the plain instance, the authenticated one, a
# variant (Dante with udp.connectdst off, gost at its default buffer), and a
# short-idle one.  shadowsocks-rust's servers sit at BASE+40 and BASE+41.
port_plain()   { echo $((BASE + IDX[$1])); }
port_auth()    { echo $((BASE + 10 + IDX[$1])); }
port_variant() { echo $((BASE + 20 + IDX[$1])); }
port_idle()    { echo $((BASE + 30 + IDX[$1])); }

# --- preconditions -------------------------------------------------------------

if ! command -v docker > /dev/null 2>&1 || ! docker info > /dev/null 2>&1; then
	echo "run.sh: needs a working Docker; skipping interop" >&2
	exit 2
fi
for f in "$W" "$B/test_matrix" "$B/udpecho" "$B/dnsd" "$PROBE"; do
	if [ ! -x "$f" ]; then
		echo "run.sh: $f is missing; run it as \`make interop\`" >&2
		exit 2
	fi
done

rm -rf "$LOGS"
mkdir -p "$LOGS"
TMP=$(mktemp -d)
PIDS=()
LABEL=udpchains-interop

cleanup() {
	local p
	for p in "${PIDS[@]:-}"; do
		[ -n "$p" ] && kill "$p" 2> /dev/null
	done
	docker ps -aq --filter "label=$LABEL" | xargs -r docker rm -f > /dev/null 2>&1
	rm -rf "$TMP"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

now_ms() { date +%s%3N; }

# Starts a fixture or sink and stores the port it reports in the variable
# named by $1.  Not in a subshell: the PID must reach PIDS, or cleanup misses
# it and the fixture outlives the run.
start_bg() {
	local var=$1 name=$2 i port=""
	shift 2
	"$@" > "$TMP/$name.out" 2> "$TMP/$name.err" &
	PIDS+=($!)
	for ((i = 0; i < 100; i++)); do
		port=$(awk '/^PORT/{print $2; exit}' "$TMP/$name.out" 2> /dev/null)
		[ -n "$port" ] && break
		sleep 0.05
	done
	if [ -z "$port" ]; then
		echo "FATAL: $name did not report a port" >&2
		exit 1
	fi
	printf -v "$var" '%s' "$port"
}

wait_listen() {
	local i
	for ((i = 0; i < 150; i++)); do
		[ -n "$(ss -Hlnt "sport = :$1" 2> /dev/null)" ] && return 0
		sleep 0.1
	done
	return 1
}

# ctr <name> <docker run args...>: starts a container on the host network.
ctr() {
	local name=udpc-interop-$1
	shift
	docker rm -f "$name" > /dev/null 2>&1
	docker run -d --name "$name" --label "$LABEL" --network host "$@" > /dev/null
}

# --- results -------------------------------------------------------------------

FAILS=0
CUR=""
result() {	# <status> <check> [detail]
	printf '  %-9s %-18s %s\n' "$1" "$2" "${3:-}" | tee -a "$LOGS/summary"
	[ "$1" = FAIL ] && FAILS=$((FAILS + 1))
	return 0
}

# --- images and configuration --------------------------------------------------

build_images() {
	case " $SELECTED " in *" dante "*)
		docker build -q -t udpchains-interop/dante - > /dev/null <<-EOF || return 1
		FROM $IMG_UBUNTU
		RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
		    --no-install-recommends dante-server && rm -rf /var/lib/apt/lists/*
		RUN useradd -M $AUSER && echo '$AUSER:$APASS' | chpasswd
		ENTRYPOINT ["/usr/sbin/danted", "-f", "/etc/sockd.conf"]
		EOF
	esac
	case " $SELECTED " in *" hev "*)
		if [ "$(uname -m)" != x86_64 ]; then
			echo "run.sh: hev is pinned to its x86_64 binary; skipping it" >&2
			SELECTED=${SELECTED/hev/}
		else
			docker build -q -t udpchains-interop/hev - > /dev/null <<-EOF || return 1
			FROM $IMG_ALPINE
			ADD --checksum=sha256:$HEV_SHA256 --chmod=755 \
			    https://github.com/heiher/hev-socks5-server/releases/download/$HEV_VERSION/hev-socks5-server-linux-x86_64 \
			    /usr/local/bin/hev-socks5-server
			ENTRYPOINT ["/usr/local/bin/hev-socks5-server", "/etc/hev.yml"]
			EOF
		fi
	esac
}

dante_conf() {	# <port> <socksmethod> [extra server settings]
	local ext
	ext=$(ip route show default 2> /dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") {print $(i+1); exit}}')
	cat <<-EOF
	${3:-}
	logoutput: stderr
	internal: 127.0.0.1 port = $1
	external: lo
	${ext:+external: $ext}
	external.rotation: route
	clientmethod: none
	socksmethod: $2
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
	EOF
}

# start_proxy <proxy> <kind>: kind is plain, auth, variant or idle.  Echoes the
# port, or nothing if the proxy has no such instance.
start_proxy() {
	local p=$1 kind=$2 port c="$TMP/conf-$1-$2"
	case $kind in
	plain) port=$(port_plain "$p") ;;
	auth) port=$(port_auth "$p") ;;
	variant) port=$(port_variant "$p") ;;
	idle) port=$(port_idle "$p") ;;
	esac
	local name="$p-$kind"

	case $p in
	dante)
		case $kind in
		plain) dante_conf "$port" none ;;
		auth) dante_conf "$port" username ;;
		variant) dante_conf "$port" none "udp.connectdst: no" ;;
		idle) dante_conf "$port" none "timeout.io.udp: 4" ;;
		esac > "$c"
		ctr "$name" -v "$c:/etc/sockd.conf:ro" udpchains-interop/dante ;;
	3proxy)
		case $kind in
		plain) printf 'log\nauth none\nallow *\nsocks -p%s -i127.0.0.1\n' "$port" ;;
		auth) printf 'log\nusers %s:CL:%s\nauth strong\nallow %s\nsocks -p%s -i127.0.0.1\n' \
			"$AUSER" "$APASS" "$AUSER" "$port" ;;
		*) return 0 ;;
		esac > "$c"
		ctr "$name" -v "$c:/etc/3proxy/3proxy.cfg:ro" "$IMG_3PROXY" ;;
	gost)
		# UDP is off unless udp=true.  udpBufferSize defaults to 4096,
		# which truncates; the variant keeps that default.
		case $kind in
		plain) ctr "$name" "$IMG_GOST" -L "socks5://127.0.0.1:$port?udp=true&udpBufferSize=65535" ;;
		auth) ctr "$name" "$IMG_GOST" -L "socks5://$AUSER:$APASS@127.0.0.1:$port?udp=true&udpBufferSize=65535" ;;
		variant) ctr "$name" "$IMG_GOST" -L "socks5://127.0.0.1:$port?udp=true" ;;
		*) return 0 ;;
		esac ;;
	xray)
		local auth='"auth": "noauth"' policy=""
		[ $kind = auth ] && auth="\"auth\": \"password\", \"accounts\": [{\"user\": \"$AUSER\", \"pass\": \"$APASS\"}]"
		[ $kind = idle ] && policy='"policy": {"levels": {"0": {"connIdle": 4, "uplinkOnly": 1, "downlinkOnly": 1}}},'
		[ $kind = variant ] && return 0
		cat > "$c" <<-EOF
		{"log": {"loglevel": "warning"}, $policy
		 "inbounds": [{"listen": "127.0.0.1", "port": $port, "protocol": "socks",
		   "settings": {$auth, "udp": true, "ip": "127.0.0.1"}}],
		 "outbounds": [{"protocol": "freedom"}]}
		EOF
		ctr "$name" -v "$c:/etc/xray.json:ro" "$IMG_XRAY" run -c /etc/xray.json ;;
	singbox)
		local extra=""
		[ $kind = auth ] && extra=", \"users\": [{\"username\": \"$AUSER\", \"password\": \"$APASS\"}]"
		[ $kind = idle ] && extra=', "udp_timeout": "4s"'
		[ $kind = variant ] && return 0
		cat > "$c" <<-EOF
		{"log": {"level": "warn"},
		 "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": $port$extra}],
		 "outbounds": [{"type": "direct"}]}
		EOF
		ctr "$name" -v "$c:/etc/sing-box.json:ro" "$IMG_SINGBOX" run -c /etc/sing-box.json ;;
	hev)
		[ $kind = variant ] && return 0
		{
			printf "main:\n  workers: 4\n  port: %s\n  listen-address: '127.0.0.1'\n" "$port"
			[ $kind = auth ] && printf "auth:\n  username: %s\n  password: %s\n" "$AUSER" "$APASS"
			printf "misc:\n  log-level: warn\n"
			[ $kind = idle ] && printf "  udp-read-write-timeout: 4000\n"
		} > "$c"
		ctr "$name" -v "$c:/etc/hev.yml:ro" udpchains-interop/hev ;;
	ssrust)
		# sslocal is the SOCKS5 server; it relays through an ssserver,
		# also on this host.  -U turns UDP on at both ends.  sslocal's
		# own username/password support was not tested.
		local srv=$((BASE + 40)) to=()
		case $kind in
		plain) ;;
		idle) srv=$((BASE + 41)); to=(--udp-timeout 4) ;;
		*) return 0 ;;
		esac
		ctr "$name-server" --entrypoint ssserver "$IMG_SSSERVER" \
			-s "127.0.0.1:$srv" -m aes-256-gcm -k "$SSKEY" -U
		ctr "$name" --entrypoint sslocal "$IMG_SSLOCAL" -b "127.0.0.1:$port" \
			-s "127.0.0.1:$srv" -m aes-256-gcm -k "$SSKEY" -U "${to[@]}" ;;
	esac || return 1
	wait_listen "$port" || { echo "FATAL: $name never listened on $port" >&2; docker logs "udpc-interop-$name" 2>&1 | tail -5 >&2; return 1; }
	echo "$port"
}

proxy_version() {
	case $1 in
	dante) docker run --rm --entrypoint /usr/sbin/danted udpchains-interop/dante -v 2>&1 | head -1 ;;
	3proxy) echo "3proxy 1.0.1 (it has no version flag; this is the pinned image's)" ;;
	gost) docker run --rm "$IMG_GOST" -V 2>&1 | head -1 ;;
	xray) docker run --rm "$IMG_XRAY" version 2>&1 | head -1 ;;
	singbox) docker run --rm "$IMG_SINGBOX" version 2>&1 | head -1 ;;
	hev) echo "hev-socks5-server $HEV_VERSION" ;;
	ssrust) docker run --rm --entrypoint sslocal "$IMG_SSLOCAL" --version 2>&1 | head -1 ;;
	esac
}

# --- checks --------------------------------------------------------------------

shim() { UDPCHAINS_QUIET=1 timeout "$1" "$W" -p "$2" "${@:3}"; }

# A test program under the shim: ok if it passes.
check_prog() {	# <check> <timeout> <proxy> <cmd...>
	local name=$1
	if shim "$2" "$3" "${@:4}" > "$LOGS/$CUR.$name.log" 2>&1; then
		result ok "$name"
	else
		result FAIL "$name" "see $LOGS/$CUR.$name.log"
	fi
}

check_fidelity() {
	local f="$LOGS/$CUR.fidelity.log" bad
	shim 180 "$1" "$B/test_fidelity" "$E1" "$E2" "$E6" > "$f" 2>&1
	bad=$(grep '^not ok' "$f")
	if [ -z "$bad" ]; then
		[ "${ZERO[$P]}" = deliver ] && result ok fidelity ||
			result FAIL fidelity "passed, but this proxy was known to drop zero-length datagrams"
	elif [ "${ZERO[$P]}" = drop ] && ! grep -v 'zero-length' <<< "$bad" | grep -q .; then
		result expected fidelity "only the zero-length check fails: the proxy drops them"
	else
		result FAIL fidelity "see $f"
	fi
}

check_portswitch() {	# <proxy addr> <expected pass|fail> [why it fails]
	local f="$LOGS/$CUR.portswitch.log"
	if shim 90 "$1" "$B/test_portswitch" "$ESW" > "$f" 2>&1; then
		[ "$2" = pass ] && result ok portswitch ||
			result FAIL portswitch "passed, but this proxy was known to drop it"
	else
		[ "$2" = fail ] && result expected portswitch "${3:-}" ||
			result FAIL portswitch "see $f"
	fi
}

# Sizes, through the echo server.  Expects WHOLE and below whole, CUT cut, a
# zero-length datagram per ZERO, and EMSGSIZE above the default max_datagram.
check_sizes() {	# <proxy addr> <whole> <cut>
	local f="$LOGS/$CUR.sizes.log" want got bad="" s
	local sizes="1 1400 $2"
	[ "$3" != - ] && sizes="$sizes $3"
	UDPCHAINS_MAX_DATAGRAM=65507 shim 120 "$1" "$PROBE" sweep 127.0.0.1 "$E1" 0 $sizes > "$f" 2>&1
	shim 30 "$1" "$PROBE" sweep 127.0.0.1 "$E1" 8193 >> "$f" 2>&1

	for s in 1 1400 $2; do
		grep -qx "$s whole" "$f" || bad="$bad $s:$(awk -v s=$s '$1 == s {print $2 $3; exit}' "$f")"
	done
	if [ "$3" != - ] && ! grep -q "^$3 cut " "$f"; then
		bad="$bad $3:not-cut"
	fi
	[ "${ZERO[$P]}" = deliver ] && want="0 whole" || want="0 lost"
	grep -qx "$want" "$f" || bad="$bad 0:$(awk '$1 == 0 {print $2; exit}' "$f")"
	grep -qx '8193 refused EMSGSIZE' "$f" || bad="$bad 8193:not-EMSGSIZE"

	if [ -n "$bad" ]; then
		result FAIL sizes "unexpected:$bad (see $f)"
	elif [ "$3" != - ]; then
		result expected sizes "whole to $2 bytes, truncated at $3; zero-length: ${ZERO[$P]}"
	else
		got="whole to $2 bytes; zero-length: ${ZERO[$P]}"
		[ "${ZERO[$P]}" = drop ] && result expected sizes "$got" || result ok sizes "$got"
	fi
}

check_ipv6() {
	local f="$LOGS/$CUR.ipv6.log"
	UDPCHAINS_QUIET=0 timeout 30 "$W" -v -p "$1" "$PROBE" sweep ::1 "$E6" 100 > "$f" 2>&1
	if grep -qx '100 whole' "$f" && grep -q 'ATYP 0x04).*122 bytes on the wire' "$f"; then
		result ok ipv6 "ATYP 0x04, 22-byte header, to ::1"
	else
		result FAIL ipv6 "see $f"
	fi
}

dnsd_count() { grep -c "^QUERY $1" "$TMP/dnsd.err" || true; }

check_resolve() {
	local f="$LOGS/$CUR.resolve.log" u0 t0 u t
	u0=$(dnsd_count udp)
	t0=$(dnsd_count tcp)
	UDPCHAINS_DNS="127.0.0.1:$DNS" UDPCHAINS_HOSTS_FILE="$TMP/hosts" \
		UDPCHAINS_DNS_SEARCH=search.test UDPCHAINS_DNS_TIMEOUT=2000 \
		shim 180 "$1" "$B/test_resolve" main > "$f" 2>&1
	local rc=$?
	u=$(($(dnsd_count udp) - u0))
	t=$(($(dnsd_count tcp) - t0))
	if [ $rc -eq 0 ] && [ $u -gt 0 ] && [ $t -gt 0 ]; then
		result ok resolve "$u UDP queries via the relay, $t TCP via CONNECT"
	else
		result FAIL resolve "rc=$rc, $u UDP, $t TCP (see $f)"
	fi
}

check_auth() {	# <auth proxy addr>
	local f="$LOGS/$CUR.auth.log" r1 r2
	echo "$APASS" > "$TMP/pw"
	echo "not-$APASS" > "$TMP/badpw"
	chmod 600 "$TMP/pw" "$TMP/badpw"

	if ! UDPCHAINS_USERNAME=$AUSER UDPCHAINS_PASSWORD_FILE="$TMP/pw" \
		shim 300 "$1" "$B/test_matrix" "$E1" "$E6" > "$f" 2>&1; then
		result FAIL auth "the matrix failed with the right password (see $f)"
		return
	fi
	r1=$(UDPCHAINS_USERNAME=$AUSER UDPCHAINS_PASSWORD_FILE="$TMP/badpw" \
		shim 30 "$1" "$PROBE" sweep 127.0.0.1 "$E1" 10 2>> "$f")
	r2=$(shim 30 "$1" "$PROBE" sweep 127.0.0.1 "$E1" 10 2>> "$f")
	if [ "$r1" = "10 refused ${AUTHE[$P]}" ] && [ "$r2" = "10 refused ${AUTHE[$P]}" ]; then
		[ "${AUTHE[$P]}" = EACCES ] && result ok auth "accepted; refused with EACCES" ||
			result expected auth "accepted; refused with ${AUTHE[$P]}: the proxy closes instead of replying"
	else
		result FAIL auth "refusal gave '$r1' / '$r2', expected ${AUTHE[$P]}"
	fi
}

# The proxy is killed under a steady sender, then started again.  Nothing may
# reach the destination while it is dead (SEC-01), and the same socket must
# carry traffic again once it is back (FR-P-08).
check_failclosed() {	# <proxy addr> <container>
	local f="$LOGS/$CUR.failclosed.log" sink spid t_kill t_start leaked after fails errs
	start_bg sink "sink-$CUR" "$PROBE" sink
	shim 30 "$1" "$PROBE" steady 127.0.0.1 "$sink" 9 > "$f" 2>&1 &
	spid=$!
	sleep 2
	docker kill "$2" > /dev/null
	t_kill=$(now_ms)
	sleep 3
	t_start=$(now_ms)
	docker start "$2" > /dev/null
	wait "$spid"
	sleep 0.3

	# 200 ms of grace for a datagram the proxy relayed just before dying.
	leaked=$(awk -v a=$((t_kill + 200)) -v b="$t_start" '$1 == "got" && $2 > a && $2 < b' "$TMP/sink-$CUR.out" | wc -l)
	after=$(awk -v b="$t_start" '$1 == "got" && $2 > b' "$TMP/sink-$CUR.out" | wc -l)
	fails=$(grep -c '^fail' "$f")
	errs=$(awk '/^fail/{print $3}' "$f" | sort | uniq -c | awk '{printf "%s%s x%s", s, $2, $1; s=", "}')
	if [ "$leaked" -eq 0 ] && [ "$fails" -gt 0 ] && [ "$after" -gt 0 ]; then
		result ok failclosed "0 arrived while dead, sends failed ($errs), recovered ($after arrived)"
	else
		result FAIL failclosed "leaked $leaked, failed $fails, recovered $after (see $f)"
	fi
}

check_internet() {
	local f="$LOGS/$CUR.internet.log" d g
	d=$(shim 20 "$1" dig +short +tries=1 +time=5 @9.9.9.9 example.com A 2>> "$f" | head -1)
	g=$(UDPCHAINS_DNS=9.9.9.9 shim 20 "$1" getent ahosts example.org 2>> "$f" | head -1)
	if [[ "$d" =~ ^[0-9.]+$ ]] && [ -n "$g" ]; then
		result ok internet "dig @9.9.9.9 and getent through 9.9.9.9"
	else
		result FAIL internet "dig '$d', getent '$g'"
	fi
}

# Idle checks run together at the end, in the background: each one is mostly
# waiting.
IDLE_JOBS=()
queue_idle() {	# <label> <proxy addr> <secs>
	# -v, so the log shows whether the proxy dropped the association.
	timeout $(($3 + 30)) "$W" -v -p "$2" "$PROBE" idle 127.0.0.1 "$E1" "$3" \
		> "$LOGS/idle.$1.log" 2>&1 &
	PIDS+=($!)
	IDLE_JOBS+=("$!:$1")
}

# --- run ------------------------------------------------------------------------

echo "Building the proxy images that are not published as images..."
build_images || { echo "FATAL: image build failed" >&2; exit 1; }

start_bg E1 echo1 "$B/udpecho" --port 0 --quiet
start_bg E2 echo2 "$B/udpecho" --port 0 --quiet
start_bg E6 echo6 "$B/udpecho" --port 0 -6 --quiet
start_bg ESW echosw "$B/udpecho" --port 0 --switch-port --quiet
start_bg DNS dnsd "$B/dnsd" --port 0
printf '127.0.0.1\tlocalhost\n203.0.113.5\thostsonly.test\n' > "$TMP/hosts"

for P in $SELECTED; do
	CUR=$P
	echo | tee -a "$LOGS/summary"
	echo "== $P: $(proxy_version "$P")" | tee -a "$LOGS/summary"
	port=$(start_proxy "$P" plain) || { result FAIL start "the proxy did not start"; continue; }
	A=127.0.0.1:$port

	check_prog matrix 300 "$A" "$B/test_matrix" "$E1" "$E6"
	check_fidelity "$A"
	check_portswitch "$A" "${PORTSW[$P]}" "port-restricted by default; passes with udp.connectdst: no"
	check_prog lifecycle 180 "$A" "$B/test_lifecycle" "$E1" "$E2"
	check_prog thread 300 "$A" "$B/test_thread" "$E1"
	if "$ROOT/tests/test_realtools.sh" "$port" "$E1" > "$LOGS/$P.realtools.log" 2>&1; then
		result ok realtools "$(grep -c '^ok' "$LOGS/$P.realtools.log") tools (dig, nc -u where installed)"
	else
		result FAIL realtools "see $LOGS/$P.realtools.log"
	fi
	check_sizes "$A" "${WHOLE[$P]}" "${CUT[$P]}"
	check_ipv6 "$A"
	check_resolve "$A"

	if [ "${AUTHE[$P]}" != - ]; then
		aport=$(start_proxy "$P" auth) && check_auth "127.0.0.1:$aport" ||
			result FAIL auth "the authenticated instance did not start"
	fi

	case $P in
	dante)
		echo "  -- with udp.connectdst: no" | tee -a "$LOGS/summary"
		vport=$(start_proxy dante variant) && CUR=dante-connectdst-no &&
			check_portswitch "127.0.0.1:$vport" pass
		CUR=$P ;;
	gost)
		# The default udpBufferSize: the limit most gost users will meet.
		echo "  -- at the default udpBufferSize" | tee -a "$LOGS/summary"
		vport=$(start_proxy gost variant) && CUR=gost-default-buffer &&
			check_sizes "127.0.0.1:$vport" 4086 4087
		CUR=$P ;;
	esac

	[ $INTERNET -eq 1 ] && check_internet "$A"

	check_failclosed "$A" "udpc-interop-$P-plain"

	if [ "${IDLE[$P]}" != - ]; then
		iport=$(start_proxy "$P" idle) && queue_idle "$P-4s-timeout" "127.0.0.1:$iport" 10
	fi
	[ $LONG -eq 1 ] && queue_idle "$P-75s" "$A" 75
done

if [ ${#IDLE_JOBS[@]} -gt 0 ]; then
	echo | tee -a "$LOGS/summary"
	echo "== idle expiry (FR-P-08), waiting for ${#IDLE_JOBS[@]} runs" | tee -a "$LOGS/summary"
	for j in "${IDLE_JOBS[@]}"; do
		pid=${j%%:*}
		label=${j#*:}
		if wait "$pid"; then
			if grep -q 're-associating' "$LOGS/idle.$label.log"; then
				result ok "$label" "the proxy dropped the association; the shim re-associated"
			else
				result ok "$label" "the proxy kept the association"
			fi
		else
			result FAIL "$label" "see $LOGS/idle.$label.log"
		fi
	done
fi

echo
if [ $FAILS -eq 0 ]; then
	echo "INTEROP: every result matched INTEROP-CHECKLIST.md 12 (logs: $LOGS)"
else
	echo "INTEROP: $FAILS result(s) differ from INTEROP-CHECKLIST.md 12 (logs: $LOGS)" >&2
fi
exit $((FAILS > 0))

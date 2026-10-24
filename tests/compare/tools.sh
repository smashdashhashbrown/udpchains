#!/bin/sh
# tools.sh -- runs the comparison client under one tool, inside the client
# container (tests/compare/run.sh starts it).
#
# usage: tools.sh <tool> up|down|warm
#
#   up    the proxy is running: the call matrix over IPv4, IPv6 and a
#         _FORTIFY_SOURCE build; dup, fork, getpeername and zero-length;
#         dig; getaddrinfo; a static Go binary
#   down  the proxy is stopped: one send per sender over IPv4 and IPv6, a
#         lookup, dig and the Go binary.  Anything reaching the server now
#         was sent directly.
#   warm  the IPv4 matrix again, each cell after a warm-up exchange
#
# Each tool is configured from its own documentation.  See conf/.

T=$1
SERVER4=10.77.0.10
SERVER6=fd77::10
PORT=7000

case $T in
none)
	W="" ;;
udpchains)
	export UDPCHAINS_LIB=/udpchains/libudpchains.so UDPCHAINS_DNS=$SERVER4
	W="/udpchains/udpchains -q -p 10.77.0.20:1080" ;;
udpchains-sv)
	# Supervisor mode (D-48): the static Go binary is what it is for.
	export UDPCHAINS_DNS=$SERVER4
	W="/udpchains/udpchains -q --supervise -p 10.77.0.20:1080" ;;
socksify)
	# Without SOCKS_AUTOADD_LANROUTES=no, Dante sends the lab's own
	# network directly by design.
	export SOCKS_CONF=/cfg/socks.conf SOCKS_AUTOADD_LANROUTES=no
	W="socksify" ;;
pc570)
	W="/opt/pc570/bin/proxychains4 -q -f /cfg/proxychains.conf" ;;
proxando)
	W="/opt/proxando/bin/proxando -q -f /cfg/proxychains.conf --udp" ;;
graftcp-auto)
	W="graftcp --socks5 10.77.0.20:1080 --enable-udp --enable-dns --dns-server $SERVER4:53" ;;
graftcp-strict)
	W="graftcp --socks5 10.77.0.20:1080 --enable-udp --enable-dns --dns-server $SERVER4:53 --select_proxy_mode only_socks5" ;;
*)
	echo "tools.sh: unknown tool $T" >&2
	exit 2 ;;
esac

run() { timeout 120 $W "$@" 2>&1; }

# One process per cell: a crash inside a tool costs only that cell.
matrix() {	# <section> <client binary> <server address> [warm]
	echo "## $1"
	for s in sendto_u sendmsg_u sendmmsg_u sendto_c send_c write_c writev_c sendmsg_c sendmmsg_c; do
		for r in recvfrom recv read readv recvmsg recvmmsg; do
			# env, because an assignment that comes from an
			# expansion is not treated as one by the shell.
			out=$(env CMP_SENDER=$s CMP_RECVER=$r ${4:+CMP_WARM=1} \
				timeout 30 $W "$2" cell "$T-$1" "$3" $PORT 2>&1)
			rc=$?
			if echo "$out" | grep -q '^CELL'; then
				echo "$out" | grep '^CELL'
			else
				echo "CELL $s/$r CRASH rc=$rc"
			fi
		done
	done
}

case $2 in
up)
	matrix m4 client $SERVER4
	matrix m6 client $SERVER6
	matrix f4 client-fortified $SERVER4
	echo "## x4";  run client extra "$T-x4" $SERVER4 $PORT
	echo "## dig"; run dig +short +tries=1 +time=3 @$SERVER4 "dig-$T.example.test" A
	echo "## gai"; run getent ahostsv4 "gai-$T.example.test"
	echo "## go";  run gocmp "$T-go" $SERVER4:$PORT ;;
down)
	echo "## leak";  run client leak "$T-down" $SERVER4 $PORT
	echo "## leak6"; run client leak "$T-down6" $SERVER6 $PORT
	echo "## gai";   run getent ahostsv4 "down-$T.example.test"
	echo "## dig";   run dig +short +tries=1 +time=3 @$SERVER4 "downdig-$T.example.test" A
	echo "## go";    run gocmp "$T-down-go" $SERVER4:$PORT ;;
warm)
	matrix w4 client $SERVER4 warm ;;
esac
exit 0

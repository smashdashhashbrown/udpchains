// gocmp -- a statically linked Go UDP client for tests/compare/run.sh.
//
// Go issues its system calls directly rather than through libc, so no
// LD_PRELOAD tool can see it: only a ptrace or network-namespace tool can.
// It is here to show that limit, udpchains' included (README).
//
// usage: gocmp <tag> <host:port>
package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	tag, addr := os.Args[1], os.Args[2]
	c, err := net.Dial("udp", addr)
	if err != nil {
		fmt.Println("GO DIALERR", err)
		return
	}
	msg := []byte("T|" + tag + "|go|")
	if _, err := c.Write(msg); err != nil {
		fmt.Println("GO SENDERR", err)
		return
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, err := c.Read(buf)
	if err != nil || string(buf[:n]) != string(msg) {
		fmt.Println("GO NOREPLY", err)
		return
	}
	fmt.Println("GO OK")
}

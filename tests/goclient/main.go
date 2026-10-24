// goclient -- a static Go program under the supervisor (FR-SV-T5).
//
// Go makes its system calls itself, never through libc, so the shim cannot
// see any of them; supervisor mode exists for programs like this.  Its
// runtime also signals its threads constantly (SIGURG, for preemption), uses
// non-blocking sockets with epoll, and runs its own resolver, which reads
// /etc/resolv.conf: all of which the supervisor must carry (D-52, D-54).
//
// Built by tests/test_supervise.sh when a Go toolchain is present, with
// CGO_ENABLED=0, so it is static and needs no module download.
//
// usage: goclient <echo port>
//
// Prints TAP.  With UDPCHAINS_DNS set to dnsd, the lookups check D-52.
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

var n, failed int

func check(ok bool, format string, args ...any) {
	n++
	if ok {
		fmt.Printf("ok %d - %s\n", n, fmt.Sprintf(format, args...))
		return
	}
	failed++
	fmt.Printf("not ok %d - %s\n", n, fmt.Sprintf(format, args...))
}

// roundTrips sends count numbered datagrams on a connected socket, each
// waited for, and returns how many came back intact.
func roundTrips(addr string, tag string, count int) int {
	c, err := net.Dial("udp", addr)
	if err != nil {
		return 0
	}
	defer c.Close()
	got := 0
	buf := make([]byte, 256)
	for i := 0; i < count; i++ {
		msg := tag + "-" + strconv.Itoa(i)
		if _, err := c.Write([]byte(msg)); err != nil {
			continue
		}
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		k, err := c.Read(buf)
		if err == nil && string(buf[:k]) == msg {
			got++
		}
	}
	return got
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: goclient <echo port>")
		os.Exit(2)
	}
	echo := net.JoinHostPort("127.0.0.1", os.Args[1])

	fmt.Println("# a static Go program's UDP, carried (FR-SV-T5)")
	check(roundTrips(echo, "go", 100) == 100, "100 round trips on a connected socket")

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	ok := err == nil
	if ok {
		dst, _ := net.ResolveUDPAddr("udp", echo)
		buf := make([]byte, 256)
		_, err = pc.WriteTo([]byte("unconnected"), dst)
		pc.SetReadDeadline(time.Now().Add(3 * time.Second))
		k, from, rerr := pc.ReadFrom(buf)
		ok = err == nil && rerr == nil && string(buf[:k]) == "unconnected" &&
			from.String() == dst.String()
		pc.Close()
	}
	check(ok, "WriteTo and ReadFrom unconnected, the reply from the echo server")

	var wg sync.WaitGroup
	var mu sync.Mutex
	total := 0
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			k := roundTrips(echo, "g"+strconv.Itoa(g), 50)
			mu.Lock()
			total += k
			mu.Unlock()
		}(g)
	}
	wg.Wait()
	check(total == 800, "16 goroutines, 50 round trips each, all carried (%d)", total)

	if os.Getenv("UDPCHAINS_DNS") != "" {
		fmt.Println("# Go's own resolver, through the system resolver's redirect (D-52)")
		r := &net.Resolver{PreferGo: true}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		addrs, err := r.LookupHost(ctx, "a.test")
		cancel()
		found := false
		for _, a := range addrs {
			found = found || a == "192.0.2.1"
		}
		check(err == nil && found, "LookupHost(a.test) finds 192.0.2.1 (%v, %v)", addrs, err)

		// Truncated over UDP, so asked again over TCP: connected to dns
		// through the proxy by CONNECT.
		ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		addrs, err = r.LookupHost(ctx, "big.test")
		cancel()
		check(err == nil && len(addrs) == 100, "LookupHost(big.test) finds 100 addresses, "+
			"over TCP (%d, %v)", len(addrs), err)
	}

	fmt.Printf("1..%d\n", n)
	if failed > 0 {
		fmt.Printf("# FAILED %d of %d\n", failed, n)
		os.Exit(1)
	}
}

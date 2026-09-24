package httpproxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Regression test for the CONNECT handler dropping the first byte the client sends
// right after "200 Connection established" (net/http background read vs Hijack race).
func Test_handleHTTPS_firstByteNotDropped(t *testing.T) {
	const n = 4000
	var lost, destErr, clientErr int64

	dl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	defer dl.Close()

	// destWG.Add(n) happens once, up front, before any client or destination goroutine starts
	// — so it can't race with a Wait() that hasn't seen all the Adds it's counting on. Every
	// probe accounts for exactly one Done(): either the destination handler that reads its
	// byte (or fails to), or the client goroutine itself on a connect/write error that means no
	// destination connection will ever arrive for that probe.
	destWG := &sync.WaitGroup{}
	destWG.Add(n)
	go func() {
		for {
			c, err := dl.Accept(); if err != nil { return }
			go func(c net.Conn) {
				defer destWG.Done()
				b := make([]byte, 1)
				if _, err := io.ReadFull(c, b); err != nil {
					atomic.AddInt64(&destErr, 1)
				} else if b[0] != 0x16 {
					atomic.AddInt64(&lost, 1)
				}
				io.Copy(io.Discard, c); c.Close()
			}(c)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wg := &sync.WaitGroup{}
	h := newHandler(ctx, wg, &nopLogger{}, false, false, "", "")
	pl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	defer pl.Close()
	go http.Serve(pl, h) //nolint:errcheck

	hello := make([]byte, 395); hello[0] = 0x16; hello[1] = 3; hello[2] = 1
	for i := 0; i < n; i++ {
		c, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			atomic.AddInt64(&clientErr, 1)
			destWG.Done() // no destination connection will ever arrive for this probe
			continue
		}
		fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", dl.Addr(), dl.Addr()) //nolint:errcheck
		br := bufio.NewReader(c)
		headerErr := false
		for {
			line, err := br.ReadString('\n')
			if err != nil { headerErr = true; break }
			if line == "\r\n" { break }
		}
		if headerErr {
			atomic.AddInt64(&clientErr, 1)
			destWG.Done()
			c.Close()
			continue
		}
		if _, err := c.Write(hello); err != nil {
			atomic.AddInt64(&clientErr, 1)
			destWG.Done()
		}
		c.Close()
	}

	// Bounded wait instead of a busy-spin: a failed probe used to leave the loop spinning
	// forever with no actionable failure (Qodo finding: "Failed probes stall image builds").
	// Waiting on destWG rather than polling a counter also fixes the second finding — every
	// destination handler's atomic.AddInt64(&lost, ...) happens-before its deferred Done(),
	// and Done() happens-before Wait() returns, so this can no longer observe lost==0 before
	// the last probe's increment has landed.
	done := make(chan struct{})
	go func() { destWG.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatalf("timed out after 30s waiting for destination-side reads (possible hang in CONNECT forwarding)")
	}

	t.Logf("connections=%d client_errors=%d dest_errors=%d first_byte_lost=%d", n, clientErr, destErr, lost)
	if clientErr > 0 || destErr > 0 {
		t.Fatalf("%d client-side and %d destination-side errors — cannot verify first-byte integrity for those probes", clientErr, destErr)
	}
	if lost > 0 { t.Fatalf("%d/%d connections lost the first client byte after CONNECT", lost, n) }
}

type nopLogger struct{}
func (nopLogger) Info(string)  {}
func (nopLogger) Debug(string) {}
func (nopLogger) Warn(string)  {}
func (nopLogger) Error(string) {}

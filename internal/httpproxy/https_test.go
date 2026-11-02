package httpproxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// raceListener accepts connections which force the race between
// the CONNECT response flush and the end of the server background read.
type raceListener struct {
	net.Listener
}

func (l *raceListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &raceConn{Conn: conn, readAfterWrite: make(chan struct{})}, nil
}

// raceConn holds back the return of its first write until a read
// following that write has returned data. Since the http server flushes
// the CONNECT response before stopping its background read, this makes
// the background read reliably take the client's first byte.
type raceConn struct {
	net.Conn
	written        atomic.Bool
	readOnce       sync.Once
	writeOnce      sync.Once
	readAfterWrite chan struct{}
}

func (c *raceConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if n > 0 && c.written.Load() {
		c.readOnce.Do(func() { close(c.readAfterWrite) })
	}
	return n, err
}

func (c *raceConn) Write(b []byte) (n int, err error) {
	c.written.Store(true)
	n, err = c.Conn.Write(b)
	c.writeOnce.Do(func() {
		const timeout = time.Second // only reached if net/http changes its call order
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case <-c.readAfterWrite:
		case <-timer.C:
		}
	})
	return n, err
}

func Test_handler_handleHTTPS_clientBytesBufferedByHijack(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	listenConfig := net.ListenConfig{}

	destinationListener, err := listenConfig.Listen(ctx, "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = destinationListener.Close() })
	received := make(chan []byte, 1)
	go func() {
		conn, err := destinationListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		data, _ := io.ReadAll(conn)
		received <- data
	}()

	proxyListener, err := listenConfig.Listen(ctx, "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &http.Server{
		Handler:           newHandler(ctx, &sync.WaitGroup{}, nil, false, false, "", ""),
		ReadHeaderTimeout: time.Second,
	}
	go func() { _ = server.Serve(&raceListener{Listener: proxyListener}) }()
	t.Cleanup(func() { _ = server.Close() })

	dialer := net.Dialer{}
	clientConn, err := dialer.DialContext(ctx, "tcp", proxyListener.Addr().String())
	require.NoError(t, err)
	defer clientConn.Close()
	deadline, _ := ctx.Deadline()
	err = clientConn.SetDeadline(deadline)
	require.NoError(t, err)

	destination := destinationListener.Addr().String()
	_, err = clientConn.Write([]byte("CONNECT " + destination + " HTTP/1.1\r\nHost: " + destination + "\r\n\r\n"))
	require.NoError(t, err)
	clientReader := bufio.NewReader(clientConn)
	statusLine, err := clientReader.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "HTTP/1.1 200 OK\r\n", statusLine)
	for line := ""; line != "\r\n"; {
		line, err = clientReader.ReadString('\n')
		require.NoError(t, err)
	}

	clientHello := []byte{0x16, 0x03, 0x01, 0x00, 0x20, 0xab, 0xab, 0xab}
	_, err = clientConn.Write(clientHello)
	require.NoError(t, err)
	err = clientConn.Close()
	require.NoError(t, err)

	select {
	case data := <-received:
		assert.Equal(t, clientHello, data)
	case <-ctx.Done():
		t.Fatal("timed out waiting for destination to receive client data")
	}
}

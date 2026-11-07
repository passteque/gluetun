package httpproxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type noopLogger struct{}

func (noopLogger) Debug(string) {}
func (noopLogger) Info(string)  {}
func (noopLogger) Warn(string)  {}
func (noopLogger) Error(string) {}

// Test_handleHTTPS_bufferedClientData checks that client bytes already
// read by the HTTP server before the connection is hijacked, such as the
// start of a TLS ClientHello sent right after the CONNECT request,
// are forwarded to the destination and not dropped.
func Test_handleHTTPS_bufferedClientData(t *testing.T) {
	t.Parallel()

	listenConfig := net.ListenConfig{}
	echoListener, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = echoListener.Close() })
	go func() {
		conn, err := echoListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	wg := &sync.WaitGroup{}
	handler := newHandler(ctx, wg, noopLogger{}, false, false, "", "")
	proxyServer := httptest.NewServer(handler)
	t.Cleanup(func() {
		cancel()
		proxyServer.Close()
	})

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(t.Context(), "tcp", proxyServer.Listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	err = conn.SetDeadline(time.Now().Add(5 * time.Second))
	require.NoError(t, err)

	destination := echoListener.Addr().String()
	const payload = "hello"
	// Send the CONNECT request and the tunneled payload in a single write,
	// so the payload ends up in the HTTP server read buffer.
	_, err = conn.Write([]byte("CONNECT " + destination + " HTTP/1.1\r\n" +
		"Host: " + destination + "\r\n\r\n" + payload))
	require.NoError(t, err)

	reader := bufio.NewReader(conn)
	request := &http.Request{Method: http.MethodConnect}
	response, err := http.ReadResponse(reader, request)
	require.NoError(t, err)
	t.Cleanup(func() { _ = response.Body.Close() })
	assert.Equal(t, http.StatusOK, response.StatusCode)

	echoed := make([]byte, len(payload))
	_, err = io.ReadFull(reader, echoed)
	require.NoError(t, err)
	assert.Equal(t, payload, string(echoed))
}

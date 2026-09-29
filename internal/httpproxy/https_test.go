package httpproxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_handleHTTPS(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		verbose bool
	}{
		"success": {},
		"verbose": {
			verbose: true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// Backend TCP server: accepts one connection for the proxy to forward to.
			backendListener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
			require.NoError(t, err)

			backendConnCh := make(chan net.Conn, 1)
			go func() {
				conn, err := backendListener.Accept()
				if err != nil {
					return
				}
				backendConnCh <- conn
			}()

			var wg sync.WaitGroup
			h := newHandler(t.Context(), &wg, &testLogger{},
				false, testCase.verbose, "", "")

			// HTTP proxy server.
			proxyListener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
			require.NoError(t, err)

			server := &http.Server{Handler: h}
			go server.Serve(proxyListener) //nolint:errcheck
			t.Cleanup(func() {
				_ = server.Close()
				_ = backendListener.Close()
			})

			// Raw TCP client sends a CONNECT request.
			clientConn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", proxyListener.Addr().String())
			require.NoError(t, err)
			defer clientConn.Close()

			destAddr := backendListener.Addr().String()
			_, err = clientConn.Write([]byte("CONNECT " + destAddr + " HTTP/1.1\r\nHost: " + destAddr + "\r\n\r\n"))
			require.NoError(t, err)

			// Parse the CONNECT response.
			resp, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
			require.NoError(t, err)

			assert.Equal(t, http.StatusOK, resp.StatusCode)
			// RFC 7231 Section 4.3.6: a successful CONNECT response must not
			// include Transfer-Encoding.
			assert.Empty(t, resp.TransferEncoding)

			// Verify bidirectional proxy: client -> backend.
			backendConn := <-backendConnCh
			defer backendConn.Close()

			clientMessage := []byte("hello from client")
			_, err = clientConn.Write(clientMessage)
			require.NoError(t, err)

			received := make([]byte, len(clientMessage))
			_, err = io.ReadFull(backendConn, received)
			require.NoError(t, err)
			assert.Equal(t, clientMessage, received)

			// Verify bidirectional proxy: backend -> client.
			backendMessage := []byte("hello from backend")
			_, err = backendConn.Write(backendMessage)
			require.NoError(t, err)

			receivedByClient := make([]byte, len(backendMessage))
			_, err = io.ReadFull(clientConn, receivedByClient)
			require.NoError(t, err)
			assert.Equal(t, backendMessage, receivedByClient)
		})
	}
}

package natpmp

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// enough for slow machines for local UDP server.
const initialConnectionDuration = 3 * time.Second

type udpExchange struct {
	request  []byte
	response []byte
	close    bool // to trigger a client error
}

// launchUDPServer launches an UDP server which will expect
// the requests precised in each of the given exchanges,
// and respond the given corresponding response.
// The server shuts down gracefully at the end of the test.
// The remote address (127.0.0.1:port) is returned, where
// port is dynamically assigned by the OS so calling tests
// can run in parallel.
func launchUDPServer(t *testing.T, exchanges []udpExchange) (
	remoteAddress *net.UDPAddr,
) {
	t.Helper()

	conn, err := net.ListenUDP("udp", nil)
	require.NoError(t, err)

	listeningAddress, ok := conn.LocalAddr().(*net.UDPAddr)
	require.True(t, ok, "listening address is not UDP")
	remoteAddress = &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: listeningAddress.Port,
	}

	done := make(chan struct{})
	t.Cleanup(func() {
		err := conn.Close()
		if !errors.Is(err, net.ErrClosed) {
			assert.NoError(t, err)
		}
		<-done
	})

	var maxBufferSize int
	for _, exchange := range exchanges {
		if len(exchange.request) > maxBufferSize {
			maxBufferSize = len(exchange.request)
		}
	}

	buffer := make([]byte, maxBufferSize)

	ready := make(chan struct{})
	go func() {
		defer close(done)
		close(ready)
		for _, exchange := range exchanges {
			n, clientAddress, err := conn.ReadFromUDP(buffer)
			if errors.Is(err, net.ErrClosed) {
				t.Error("at least one exchange is missing")
				return
			}
			require.NoError(t, err)

			assert.Equal(t, len(exchange.request), n,
				"request message size is unexpected")
			if n > 0 {
				assert.Equal(t, exchange.request, buffer[:n],
					"request message is unexpected")
			}

			if exchange.close {
				err = conn.Close()
				if !errors.Is(err, net.ErrClosed) {
					// connection might be already closed by client production code
					assert.NoError(t, err)
				}
				return
			}

			_, err = conn.WriteToUDP(exchange.response, clientAddress)
			require.NoError(t, err)
		}

		err := conn.Close()
		if !errors.Is(err, net.ErrClosed) {
			// The connection closing can be raced by the test
			// cleanup function defined above.
			assert.NoError(t, err)
		}
	}()
	<-ready

	return remoteAddress
}

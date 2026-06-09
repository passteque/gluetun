package restrictednet

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"sync"
	"syscall"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ptrTo[T any](value T) *T {
	return &value
}

func newInterceptTransport(handler func(host string, requestBody io.Reader) (*http.Response, error)) *http.Transport {
	return &http.Transport{
		DialTLSContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			clientConn, serverConn := net.Pipe()
			go func() {
				defer serverConn.Close()

				reader := bufio.NewReader(serverConn)
				request, err := http.ReadRequest(reader)
				if err != nil {
					return
				}

				response, err := handler(request.Host, request.Body)
				if err != nil {
					return
				}

				// Read the response body and re-create it to avoid linting
				// complaining that the response body must be closed.
				responseData, err := io.ReadAll(response.Body)
				if err != nil {
					return
				}
				_ = response.Body.Close()
				response.Body = io.NopCloser(bytes.NewReader(responseData))

				_ = response.Write(serverConn)
			}()
			return clientConn, nil
		},
	}
}

func expectFirewallCallPair(
	firewall *MockFirewall,
	addContext context.Context, //nolint:revive
	destinationIP netip.Addr,
	destinationPort uint16,
	addErr error,
	removeErr error,
) {
	destination := netip.AddrPortFrom(destinationIP, destinationPort)
	sourceMatcher := listenAddrPortMatcher{}

	firewall.EXPECT().AcceptOutputFromIPPortToIPPort(
		addContext, "tcp", "eth0", sourceMatcher, destination, false,
	).DoAndReturn(func(
		_ context.Context, _, _ string, source, _ netip.AddrPort, _ bool,
	) error {
		sourceMatcher.expected = source
		return addErr
	})

	firewall.EXPECT().AcceptOutputFromIPPortToIPPort(
		context.Background(), "tcp", "eth0", sourceMatcher, destination, true,
	).Return(removeErr)
}

func urlToHostnamePort(rawURL string, port uint16) string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		panic(err) // programming error in test
	}
	parsedURL.Host = net.JoinHostPort(parsedURL.Hostname(), strconv.FormatUint(uint64(port), 10))
	return parsedURL.String()
}

func responseWireForQuery(t *testing.T, queryReader io.Reader, answers ...dns.RR) []byte {
	t.Helper()

	queryData, err := io.ReadAll(queryReader)
	require.NoError(t, err)

	query := new(dns.Msg)
	err = query.Unpack(queryData)
	require.NoError(t, err)

	response := new(dns.Msg)
	response.SetReply(query)
	response.Answer = append(response.Answer, answers...)

	wire, err := response.Pack()
	require.NoError(t, err)
	return wire
}

func startTCPAccepter(t *testing.T) (port uint16) {
	t.Helper()

	// Find a port available for both TCP IPv4 and TCP IPv6
	listeners := make([]net.Listener, 2) // IPv4 + IPv6
	netConfig := net.ListenConfig{}
	var listenersToClose []net.Listener
	for t.Context().Err() == nil {
		// Find an available port for IPv4
		listeningAddress := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 0)
		listener, err := netConfig.Listen(t.Context(), "tcp", listeningAddress.String())
		require.NoError(t, err)
		listeners[0] = listener
		port = uint16(listener.Addr().(*net.TCPAddr).Port) //nolint:gosec,forcetypeassert

		// Check if that port is also available for IPv6
		listeningAddress = netip.AddrPortFrom(
			netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
			port,
		)
		listener, err = netConfig.Listen(t.Context(), "tcp", listeningAddress.String())
		if err == nil {
			listeners[1] = listener
			break // success, we found a port available for both IPv4 and IPv6
		}
		var opErr *net.OpError
		if errors.As(err, &opErr) {
			var sysErr *os.SyscallError
			if errors.As(opErr.Err, &sysErr) && errors.Is(sysErr.Err, syscall.EADDRINUSE) {
				// Port found for IPv4 is already in use for IPv6, try another port
				// We don't close the IPv4 listener yet to make sure we don't get the same port again from the OS.
				listenersToClose = append(listenersToClose, listeners[0])
				continue
			}
		}
	}

	for _, listener := range listenersToClose {
		err := listener.Close()
		assert.NoError(t, err)
	}

	var ready sync.WaitGroup
	ready.Add(len(listeners))
	for _, listener := range listeners {
		t.Cleanup(func() {
			err := listener.Close()
			assert.NoError(t, err)
		})

		go func() {
			ready.Done()
			for {
				connection, err := listener.Accept()
				if err != nil {
					if errors.Is(err, net.ErrClosed) && t.Context().Err() != nil {
						return
					}
					assert.NoError(t, err)
					return
				}
				err = connection.Close()
				assert.NoError(t, err)
			}
		}()
	}

	ready.Wait()

	return port
}

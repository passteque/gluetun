package httpproxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// Test_handleHTTPS_tunnelPayloadForwarded checks that the bytes the client sends for the tunnel
// are all forwarded to the destination, including the ones the HTTP server has already read when
// the handler hijacks the connection. net/http hands these bytes back in the *bufio.ReadWriter
// returned by Hijack, and they are silently dropped when the bare connection is forwarded instead.
func Test_handleHTTPS_tunnelPayloadForwarded(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		// bulkPayload repeats the payload well above the HTTP server read buffer, so only its
		// beginning is buffered when the handler hijacks.
		bulkPayload bool
		// payloadWithRequest writes the CONNECT request and the first tunnel bytes in a single
		// write, so the HTTP server holds them in its read buffer when the handler hijacks.
		payloadWithRequest bool
		// holdConnectResponseWrite makes the server read the first tunnel byte before Hijack
		// returns, by holding the CONNECT response write back (see hijackRaceConn).
		holdConnectResponseWrite bool
	}{
		"payload_buffered_with_connect_request":      {payloadWithRequest: true},
		"payload_stolen_by_background_read":          {holdConnectResponseWrite: true},
		"payload_after_connect_response":             {},
		"bulk_payload_buffered_with_connect_request": {bulkPayload: true, payloadWithRequest: true},
		"bulk_payload_after_connect_response":        {bulkPayload: true},
	}

	for testName, testCase := range testCases {
		t.Run(testName, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
			defer cancel()

			destinationAddress := startEchoServer(t)
			logger := NewMockLogger(gomock.NewController(t))
			proxyAddress := startProxyServer(t, logger, testCase.holdConnectResponseWrite)
			payload := []byte(tunnelPayload)
			if testCase.bulkPayload {
				payload = bytes.Repeat(payload, bulkPayloadRepeatCount)
			}

			outcome, err := runTunnelProbe(ctx, proxyAddress, destinationAddress,
				payload, testCase.payloadWithRequest)
			require.Equal(t, probeOutcomeVerified, outcome, "%s", err)
			require.NoError(t, err)
		})
	}
}

// Test_handleHTTPS_tunnelPayloadForwardedRepeatedConnections supplements the deterministic checks
// of Test_handleHTTPS_tunnelPayloadForwarded with real timing: each probe writes its first tunnel
// bytes as soon as it has read the CONNECT response, which is the timing losing them. The volume
// is kept low on purpose, since a single probe only has a small chance of hitting the window.
func Test_handleHTTPS_tunnelPayloadForwardedRepeatedConnections(t *testing.T) {
	t.Parallel()

	const (
		connectionCount      = 500
		minimumVerifiedCount = connectionCount * 90 / 100
	)

	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	defer cancel()

	destinationAddress := startEchoServer(t)
	logger := NewMockLogger(gomock.NewController(t))
	proxyAddress := startProxyServer(t, logger, false)
	payload := []byte(tunnelPayload)

	var verifiedCount, alteredPayloadCount, erroredCount int
	for probeNumber := range connectionCount {
		outcome, err := runTunnelProbe(ctx, proxyAddress, destinationAddress, payload, false)
		switch outcome {
		case probeOutcomeVerified:
			verifiedCount++
		case probeOutcomeLeadingBytesLost:
			alteredPayloadCount++
			t.Errorf("probe %d: %s", probeNumber, err)
		case probeOutcomeCorruptedPayload:
			alteredPayloadCount++
			t.Errorf("probe %d: %s", probeNumber, err)
		case probeOutcomeErrored:
			erroredCount++
			t.Logf("probe %d: %s", probeNumber, err)
		}
	}

	t.Logf("connections=%d verified=%d alteredPayloads=%d errored=%d",
		connectionCount, verifiedCount, alteredPayloadCount, erroredCount)
	require.Zero(t, alteredPayloadCount, "tunnel payload altered by the proxy")
	// A few probes can fail to connect on a heavily loaded machine, which says nothing about
	// the tunnel. The check would be vacuous without a minimum number of verified probes though.
	require.GreaterOrEqual(t, verifiedCount, minimumVerifiedCount,
		"too few probes went through the tunnel to conclude anything, %d errored", erroredCount)
}

// Test_handleHTTPS_hijackingUnsupported checks the destination connection is closed when the
// response writer cannot be hijacked, since nothing can forward it to the client then.
func Test_handleHTTPS_hijackingUnsupported(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	listenConfig := net.ListenConfig{}
	destinationListener, err := listenConfig.Listen(ctx, "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = destinationListener.Close() })
	acceptedConnection := make(chan net.Conn, 1)
	go func() {
		destinationConnection, err := destinationListener.Accept()
		if err != nil {
			return
		}
		acceptedConnection <- destinationConnection
	}()

	logger := NewMockLogger(gomock.NewController(t))
	proxyHandler, ok := newHandler(ctx, &sync.WaitGroup{}, logger, false, false, "", "").(*handler)
	require.Truef(t, ok, "the proxy handler should be a *handler")

	request := &http.Request{
		Method:     http.MethodConnect,
		Host:       destinationListener.Addr().String(),
		RemoteAddr: "127.0.0.1:1234",
	}
	// Unlike the response writer of a listening server, a recorder cannot be hijacked.
	proxyHandler.handleHTTPS(httptest.NewRecorder(), request)

	select {
	case destinationConnection := <-acceptedConnection:
		defer func() { _ = destinationConnection.Close() }()
		err := destinationConnection.SetReadDeadline(time.Now().Add(probeDeadline))
		require.NoError(t, err)
		_, err = destinationConnection.Read(make([]byte, 1))
		require.ErrorIs(t, err, io.EOF, "the proxy left the destination connection open")
	case <-ctx.Done():
		t.Fatal("the proxy never connected to the destination")
	}
}

// probeOutcome tells what happened to the tunnel payload of a single CONNECT request.
type probeOutcome uint8

const (
	// probeOutcomeErrored covers the failures unrelated to the tunnel: the CONNECT request
	// could not be sent or answered, or the tunnel connection broke.
	probeOutcomeErrored probeOutcome = iota
	probeOutcomeVerified
	// probeOutcomeLeadingBytesLost and probeOutcomeCorruptedPayload both mean the destination
	// received the payload altered, which no load on the machine can explain.
	probeOutcomeLeadingBytesLost
	probeOutcomeCorruptedPayload
)

const (
	// testTimeout bounds the whole duration of a test, from the connection to the proxy to the
	// data coming back from the destination.
	testTimeout = 30 * time.Second
	// probeDeadline bounds a single probe, so that a proxy losing bytes is reported as a
	// failure rather than as a test running forever.
	probeDeadline = 10 * time.Second
	// readHeaderTimeout bounds the CONNECT request read by the proxy HTTP server.
	readHeaderTimeout = 5 * time.Second
	// holdConnectResponseTimeout bounds the artificial delay applied to the CONNECT response
	// write. It is only reached if net/http stops reading from the client connection in the
	// background before Hijack returns, in which case the test degrades to a plain one.
	holdConnectResponseTimeout = time.Second
	// tunnelPayload is the data a probe sends through the tunnel. A CONNECT tunnel generally
	// carries TLS traffic, and the first byte of a ClientHello record is the one at risk, so
	// anything but a single byte payload would do.
	tunnelPayload = "the tunnel payload, sent to the destination and echoed back"
	// bulkPayloadRepeatCount repeats tunnelPayload well above the 4 KiB read buffer of the
	// HTTP server, so the payload cannot fit in it.
	bulkPayloadRepeatCount = 200
)

// runTunnelProbe sends a single CONNECT request to the proxy, then the tunnel payload, and checks
// the destination echoes that payload back intact. The payload is sent within the same write as
// the CONNECT request when payloadWithRequest is true, and as soon as the CONNECT response has
// been read otherwise.
func runTunnelProbe(ctx context.Context, proxyAddress, destinationAddress string,
	payload []byte, payloadWithRequest bool,
) (outcome probeOutcome, err error) {
	dialer := net.Dialer{}
	clientConnection, err := dialer.DialContext(ctx, "tcp", proxyAddress)
	if err != nil {
		return probeOutcomeErrored, fmt.Errorf("dialing the proxy server: %w", err)
	}
	defer func() { _ = clientConnection.Close() }()

	err = clientConnection.SetDeadline(time.Now().Add(probeDeadline))
	if err != nil {
		return probeOutcomeErrored, fmt.Errorf("setting the client connection deadline: %w", err)
	}

	connectRequest := []byte("CONNECT " + destinationAddress + " HTTP/1.1\r\n" +
		"Host: " + destinationAddress + "\r\n\r\n")
	if payloadWithRequest {
		connectRequest = append(connectRequest, payload...)
	}
	if _, err := clientConnection.Write(connectRequest); err != nil {
		return probeOutcomeErrored, fmt.Errorf("writing the CONNECT request: %w", err)
	}

	clientReader := bufio.NewReader(clientConnection)
	if err := readConnectResponse(clientReader); err != nil {
		return probeOutcomeErrored, err
	}

	if !payloadWithRequest {
		if _, err := clientConnection.Write(payload); err != nil {
			return probeOutcomeErrored, fmt.Errorf("writing the tunnel payload: %w", err)
		}
	}

	echoed := make([]byte, len(payload))
	echoedLength, err := io.ReadFull(clientReader, echoed)
	if echoedLength > 0 && echoedLength < len(payload) &&
		bytes.Equal(echoed[:echoedLength], payload[len(payload)-echoedLength:]) {
		// The destination echoed back what it received, which is the payload without its
		// leading bytes: the proxy lost them between the client and the destination.
		return probeOutcomeLeadingBytesLost, fmt.Errorf(
			"%d leading tunnel payload byte(s) dropped by the proxy: got %s, want %s",
			len(payload)-echoedLength, payloadExcerpt(echoed[:echoedLength]), payloadExcerpt(payload))
	}
	if echoedLength != len(payload) {
		return probeOutcomeErrored, fmt.Errorf(
			"only %d of the %d tunnel payload bytes came back: got %s, want %s: %w",
			echoedLength, len(payload), payloadExcerpt(echoed[:echoedLength]), payloadExcerpt(payload), err)
	}
	if !bytes.Equal(echoed, payload) {
		return probeOutcomeCorruptedPayload, fmt.Errorf(
			"the destination echoed a corrupted payload: got %s, want %s",
			payloadExcerpt(echoed), payloadExcerpt(payload))
	}

	return probeOutcomeVerified, nil
}

// payloadExcerpt describes a payload for a failure message, since a bulk payload is too large
// to be worth dumping.
func payloadExcerpt(payload []byte) string {
	const maximumExcerptLength = 32

	if len(payload) <= maximumExcerptLength {
		return fmt.Sprintf("%q", payload)
	}

	return fmt.Sprintf("%q… of %d bytes", payload[:maximumExcerptLength], len(payload))
}

// readConnectResponse reads the CONNECT response status line and headers, and fails when the
// status is not a success. The tunneled data starts right after the header block, so the response
// body is deliberately left unread.
func readConnectResponse(clientReader *bufio.Reader) error {
	const statusLinePrefix = "HTTP/1.1 200 "
	statusLine, err := clientReader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("reading the CONNECT response status line: %w", err)
	}
	if !strings.HasPrefix(statusLine, statusLinePrefix) {
		return fmt.Errorf("unexpected CONNECT response status line %q", statusLine)
	}
	for {
		headerLine, err := clientReader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("reading the CONNECT response headers: %w", err)
		}
		if headerLine == "\r\n" {
			return nil
		}
	}
}

// startEchoServer listens on a local address and echoes back to each accepted connection the data
// it receives, until that connection is closed. It returns the listening address, which the
// probes use as the CONNECT tunnel destination.
func startEchoServer(t *testing.T) string {
	t.Helper()

	ctx := t.Context()
	listenConfig := net.ListenConfig{}
	listener, err := listenConfig.Listen(ctx, "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			echoConnection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(echoConnection, echoConnection)
				_ = echoConnection.Close()
			}()
		}
	}()

	return listener.Addr().String()
}

// startProxyServer runs the proxy handler on a local address and returns it. When
// holdConnectResponseWrite is true, every connection accepted by the proxy is wrapped by
// hijackRaceConn, which makes the byte stealing race deterministic.
func startProxyServer(t *testing.T, logger Logger, holdConnectResponseWrite bool) string {
	t.Helper()

	ctx := t.Context()
	listenConfig := net.ListenConfig{}
	listener, err := listenConfig.Listen(ctx, "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := &http.Server{
		Handler:           newHandler(ctx, &sync.WaitGroup{}, logger, false, false, "", ""),
		ReadHeaderTimeout: readHeaderTimeout,
	}
	if holdConnectResponseWrite {
		listener = &hijackRaceListener{Listener: listener}
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	return listener.Addr().String()
}

// hijackRaceListener wraps every accepted connection into a hijackRaceConn.
type hijackRaceListener struct {
	net.Listener
}

func (l *hijackRaceListener) Accept() (net.Conn, error) {
	serverConnection, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &hijackRaceConn{
		Conn:           serverConnection,
		clientDataRead: make(chan struct{}),
	}, nil
}

// hijackRaceConn holds the return of its first Write until a following Read has returned data.
// The HTTP server flushes the CONNECT response when Hijack is called, just before it stops the
// background read it keeps on the client connection. Holding that write back until the background
// read has taken a byte makes the race deterministic, since a client only sends its first tunnel
// bytes once it has read the response.
type hijackRaceConn struct {
	net.Conn
	clientDataRead chan struct{}
	dataReadOnce   sync.Once
	writeOnce      sync.Once
	responseSent   atomic.Bool
}

func (c *hijackRaceConn) Read(buffer []byte) (readLength int, err error) {
	readLength, err = c.Conn.Read(buffer)
	if readLength > 0 && c.responseSent.Load() {
		c.dataReadOnce.Do(func() { close(c.clientDataRead) })
	}
	return readLength, err
}

func (c *hijackRaceConn) Write(buffer []byte) (writtenLength int, err error) {
	c.responseSent.Store(true)
	writtenLength, err = c.Conn.Write(buffer)
	c.writeOnce.Do(func() {
		timer := time.NewTimer(holdConnectResponseTimeout)
		defer timer.Stop()
		select {
		case <-c.clientDataRead:
		case <-timer.C:
		}
	})
	return writtenLength, err
}

package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type noopLogger struct{}

func (noopLogger) Infof(string, ...any) {}
func (noopLogger) Warnf(string, ...any) {}

func TestServerProxy(t *testing.T) {
	t.Parallel()
	testCases := map[string]struct {
		username string
		password string
	}{
		"no_auth": {},
		"with_auth": {
			username: "user",
			password: "pass",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// Backend TCP server: accepts one connection for the proxy to forward to.
			backendListener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
			require.NoError(t, err)

			backendConnCh := make(chan net.Conn)
			go func() {
				conn, err := backendListener.Accept()
				if err != nil {
					return
				}
				backendConnCh <- conn
			}()

			server := newServer(Settings{
				Username: testCase.username,
				Password: testCase.password,
				Address:  "127.0.0.1:0",
				Logger:   noopLogger{},
			})
			_, err = server.Start(t.Context())
			require.NoError(t, err)
			t.Cleanup(func() {
				_ = server.Stop()
				_ = backendListener.Close()
			})

			// Dial through the SOCKS5 proxy to the backend.
			// By the time dialSOCKS5 returns, the SOCKS5 server has already
			// established the TCP connection to the backend, so backendConnCh
			// is guaranteed to be populated.
			clientConn := dialSOCKS5(t, server.listeningAddress().String(),
				backendListener.Addr().String(), testCase.username, testCase.password)
			defer clientConn.Close()

			backendConn := <-backendConnCh
			defer backendConn.Close()

			// Verify client → backend direction.
			clientMessage := []byte("hello from client")
			_, err = clientConn.Write(clientMessage)
			require.NoError(t, err)

			received := make([]byte, len(clientMessage))
			_, err = io.ReadFull(backendConn, received)
			require.NoError(t, err)
			assert.Equal(t, clientMessage, received)

			// Verify backend → client direction.
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

func TestServerProxyTCPAndUDPParallel(t *testing.T) {
	t.Parallel()
	testCases := map[string]struct {
		username string
		password string
	}{
		"no_auth": {},
		"with_auth": {
			username: "user",
			password: "pass",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			backendTCPListener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
			require.NoError(t, err)

			backendTCPConnChannel := make(chan net.Conn, 1)
			go func() {
				connection, err := backendTCPListener.Accept()
				if err != nil {
					return
				}
				backendTCPConnChannel <- connection
			}()

			backendUDPPacketConn, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp", "127.0.0.1:0")
			require.NoError(t, err)

			server := newServer(Settings{
				Username: testCase.username,
				Password: testCase.password,
				Address:  "127.0.0.1:0",
				Logger:   noopLogger{},
			})
			_, err = server.Start(t.Context())
			require.NoError(t, err)
			t.Cleanup(func() {
				_ = server.Stop()
				_ = backendTCPListener.Close()
				_ = backendUDPPacketConn.Close()
			})

			clientTCPConn := dialSOCKS5(t, server.listeningAddress().String(),
				backendTCPListener.Addr().String(), testCase.username, testCase.password)
			defer clientTCPConn.Close()

			backendTCPConn := <-backendTCPConnChannel
			defer backendTCPConn.Close()

			udpControlConn, clientUDPConn := dialSOCKS5UDPAssociate(t,
				server.listeningAddress().String(), testCase.username, testCase.password)
			defer udpControlConn.Close()
			defer clientUDPConn.Close()

			tcpErrCh := make(chan error, 1)
			go func() {
				tcpErrCh <- runTCPProxyRoundTrip(clientTCPConn, backendTCPConn)
			}()

			udpErrCh := make(chan error, 1)
			go func() {
				udpErrCh <- runUDPProxyRoundTrip(t.Context(), clientUDPConn, backendUDPPacketConn)
			}()

			err = <-tcpErrCh
			require.NoError(t, err)
			err = <-udpErrCh
			require.NoError(t, err)
		})
	}
}

func runTCPProxyRoundTrip(clientTCPConn net.Conn, backendTCPConn net.Conn) error {
	clientMessage := []byte("hello from client")
	_, err := clientTCPConn.Write(clientMessage)
	if err != nil {
		return err
	}

	received := make([]byte, len(clientMessage))
	_, err = io.ReadFull(backendTCPConn, received)
	if err != nil {
		return err
	}
	if !bytes.Equal(clientMessage, received) {
		return errors.New("backend did not receive expected TCP payload")
	}

	backendMessage := []byte("hello from backend")
	_, err = backendTCPConn.Write(backendMessage)
	if err != nil {
		return err
	}

	receivedByClient := make([]byte, len(backendMessage))
	_, err = io.ReadFull(clientTCPConn, receivedByClient)
	if err != nil {
		return err
	}
	if !bytes.Equal(backendMessage, receivedByClient) {
		return errors.New("client did not receive expected TCP payload")
	}

	return nil
}

func runUDPProxyRoundTrip(ctx context.Context, clientUDPConn *net.UDPConn, backendUDPPacketConn net.PacketConn) error {
	udpPayload := []byte("hello from udp client")
	udpRequest, err := makeSOCKS5UDPDatagram(backendUDPPacketConn.LocalAddr().String(), udpPayload)
	if err != nil {
		return err
	}

	_, err = clientUDPConn.Write(udpRequest)
	if err != nil {
		return err
	}

	deadline, hasDeadline := ctx.Deadline()
	if hasDeadline {
		err = backendUDPPacketConn.SetReadDeadline(deadline)
		if err != nil {
			return fmt.Errorf("setting read deadline on backend connection: %w", err)
		}
	}
	const bufferSize = 512
	backendReadBuffer := make([]byte, bufferSize)
	packetLength, proxyAddress, err := backendUDPPacketConn.ReadFrom(backendReadBuffer)
	if err != nil {
		return err
	}
	if !bytes.Equal(udpPayload, backendReadBuffer[:packetLength]) {
		return errors.New("backend did not receive expected UDP payload")
	}

	backendUDPReply := []byte("hello from udp backend")
	_, err = backendUDPPacketConn.WriteTo(backendUDPReply, proxyAddress)
	if err != nil {
		return err
	}

	if hasDeadline {
		err = clientUDPConn.SetReadDeadline(deadline)
		if err != nil {
			return fmt.Errorf("setting read deadline on client connection: %w", err)
		}
	}
	udpResponseBuffer := make([]byte, 1024)
	responseLength, err := clientUDPConn.Read(udpResponseBuffer)
	if err != nil {
		return err
	}

	destinationAddress, udpResponsePayload, err := parseSOCKS5UDPDatagram(udpResponseBuffer[:responseLength])
	if err != nil {
		return err
	}

	if !bytes.Equal(backendUDPReply, udpResponsePayload) {
		return errors.New("client did not receive expected UDP payload")
	}
	if destinationAddress != backendUDPPacketConn.LocalAddr().String() {
		return errors.New("udp response destination address mismatch")
	}

	return nil
}

// dialSOCKS5 performs the full SOCKS5 handshake (with optional username/password
// subnegotiation) and returns a connected net.Conn ready for data exchange.
func dialSOCKS5(t *testing.T, proxyAddr, targetAddr, username, password string) net.Conn {
	t.Helper()

	host, portStr, err := net.SplitHostPort(targetAddr)
	require.NoError(t, err)
	targetPort, err := strconv.Atoi(portStr)
	require.NoError(t, err)

	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", proxyAddr)
	require.NoError(t, err)

	negotiateSOCKS5(t, conn, username, password)

	var connectRequest []byte
	if ip := net.ParseIP(host).To4(); ip != nil {
		connectRequest = []byte{socks5Version, byte(connect), 0, byte(ipv4)}
		connectRequest = append(connectRequest, ip...)
	} else {
		connectRequest = []byte{socks5Version, byte(connect), 0, byte(domainName), byte(len(host))}
		connectRequest = append(connectRequest, []byte(host)...)
	}
	connectRequest = binary.BigEndian.AppendUint16(connectRequest, uint16(targetPort)) //nolint:gosec
	_, err = conn.Write(connectRequest)
	require.NoError(t, err)

	_, err = readSOCKS5ResponseAddress(t, conn)
	require.NoError(t, err)

	return conn
}

func dialSOCKS5UDPAssociate(t *testing.T, proxyAddr, username, password string) (net.Conn, *net.UDPConn) {
	t.Helper()

	controlConn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", proxyAddr)
	require.NoError(t, err)

	negotiateSOCKS5(t, controlConn, username, password)

	udpAssociateRequest := []byte{socks5Version, byte(udpAssociate), 0, byte(ipv4), 0, 0, 0, 0, 0, 0}
	_, err = controlConn.Write(udpAssociateRequest)
	require.NoError(t, err)

	udpProxyAddress, err := readSOCKS5ResponseAddress(t, controlConn)
	require.NoError(t, err)

	udpProxyResolvedAddress, err := net.ResolveUDPAddr("udp", udpProxyAddress)
	require.NoError(t, err)

	udpConn, err := net.DialUDP("udp", nil, udpProxyResolvedAddress)
	require.NoError(t, err)

	return controlConn, udpConn
}

func negotiateSOCKS5(t *testing.T, conn net.Conn, username, password string) {
	t.Helper()

	var err error

	var method authMethod
	if username != "" || password != "" {
		method = authUsernamePassword
	} else {
		method = authNotRequired
	}
	_, err = conn.Write([]byte{socks5Version, 1, byte(method)})
	require.NoError(t, err)

	var methodResp [2]byte
	_, err = io.ReadFull(conn, methodResp[:])
	require.NoError(t, err)
	require.Equal(t, socks5Version, methodResp[0])
	require.Equal(t, byte(method), methodResp[1])

	if method == authUsernamePassword {
		packet := []byte{authUsernamePasswordSubNegotiation1, byte(len(username))}
		packet = append(packet, []byte(username)...)
		packet = append(packet, byte(len(password)))
		packet = append(packet, []byte(password)...)
		_, err = conn.Write(packet)
		require.NoError(t, err)

		var subnegResp [2]byte
		_, err = io.ReadFull(conn, subnegResp[:])
		require.NoError(t, err)
		require.Equal(t, authUsernamePasswordSubNegotiation1, subnegResp[0])
		require.Equal(t, byte(0), subnegResp[1])
	}
}

func readSOCKS5ResponseAddress(t *testing.T, conn net.Conn) (address string, err error) {
	t.Helper()

	var responseHeader [4]byte
	_, err = io.ReadFull(conn, responseHeader[:])
	if err != nil {
		return "", err
	}
	if responseHeader[0] != socks5Version {
		return "", errors.New("version mismatch")
	}
	if responseHeader[1] != byte(succeeded) {
		return "", errors.New("request was not successful")
	}

	var host string
	switch addrType(responseHeader[3]) {
	case ipv4:
		addressAndPort := make([]byte, net.IPv4len+2)
		_, err = io.ReadFull(conn, addressAndPort)
		if err != nil {
			return "", err
		}
		host = net.IP(addressAndPort[:net.IPv4len]).String()
		port := binary.BigEndian.Uint16(addressAndPort[net.IPv4len:])
		return net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10)), nil
	case ipv6:
		addressAndPort := make([]byte, net.IPv6len+2)
		_, err = io.ReadFull(conn, addressAndPort)
		if err != nil {
			return "", err
		}
		host = net.IP(addressAndPort[:net.IPv6len]).String()
		port := binary.BigEndian.Uint16(addressAndPort[net.IPv6len:])
		return net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10)), nil
	case domainName:
		var lengthBuffer [1]byte
		_, err = io.ReadFull(conn, lengthBuffer[:])
		if err != nil {
			return "", err
		}
		domainAndPort := make([]byte, int(lengthBuffer[0])+2)
		_, err = io.ReadFull(conn, domainAndPort)
		if err != nil {
			return "", err
		}
		host = string(domainAndPort[:len(domainAndPort)-2])
		port := binary.BigEndian.Uint16(domainAndPort[len(domainAndPort)-2:])
		return net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10)), nil
	default:
		return "", errors.New("unknown address type")
	}
}

func makeSOCKS5UDPDatagram(targetAddress string, payload []byte) ([]byte, error) {
	host, portString, err := net.SplitHostPort(targetAddress)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		return nil, err
	}

	datagram := []byte{0, 0, 0}
	ipAddress := net.ParseIP(host)
	if ipAddress != nil {
		if ipAddress.To4() != nil {
			datagram = append(datagram, byte(ipv4))
			datagram = append(datagram, ipAddress.To4()...)
		} else {
			datagram = append(datagram, byte(ipv6))
			datagram = append(datagram, ipAddress.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("domain name too long")
		}
		datagram = append(datagram, byte(domainName), byte(len(host)))
		datagram = append(datagram, []byte(host)...)
	}
	datagram = binary.BigEndian.AppendUint16(datagram, uint16(port))
	datagram = append(datagram, payload...)

	return datagram, nil
}

func parseSOCKS5UDPDatagram(datagram []byte) (destinationAddress string, payload []byte, err error) {
	if len(datagram) < 4 {
		return "", nil, errors.New("datagram too short")
	}
	if datagram[0] != 0 || datagram[1] != 0 {
		return "", nil, errors.New("invalid reserved header")
	}
	if datagram[2] != 0 {
		return "", nil, errors.New("fragments are not supported")
	}

	offset := 3
	var host string
	switch addrType(datagram[offset]) {
	case ipv4:
		offset++
		if len(datagram) < offset+net.IPv4len+2 {
			return "", nil, errors.New("datagram too short for IPv4")
		}
		host = net.IP(datagram[offset : offset+net.IPv4len]).String()
		offset += net.IPv4len
	case ipv6:
		offset++
		if len(datagram) < offset+net.IPv6len+2 {
			return "", nil, errors.New("datagram too short for IPv6")
		}
		host = net.IP(datagram[offset : offset+net.IPv6len]).String()
		offset += net.IPv6len
	case domainName:
		offset++
		if len(datagram) < offset+1 {
			return "", nil, errors.New("datagram too short for domain length")
		}
		domainLength := int(datagram[offset])
		offset++
		if len(datagram) < offset+domainLength+2 {
			return "", nil, errors.New("datagram too short for domain")
		}
		host = string(datagram[offset : offset+domainLength])
		offset += domainLength
	default:
		return "", nil, errors.New("unknown address type")
	}

	if len(datagram) < offset+2 {
		return "", nil, errors.New("datagram too short for port")
	}
	port := binary.BigEndian.Uint16(datagram[offset : offset+2])
	offset += 2

	return net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10)), datagram[offset:], nil
}

func Test_newServer(t *testing.T) {
	t.Parallel()
	testCases := map[string]struct {
		settings Settings
		expected *server
	}{
		"with_auth": {
			settings: Settings{
				Username: "user",
				Password: "pass",
				Address:  "127.0.0.1:1080",
			},
			expected: &server{
				username: "user",
				password: "pass",
				address:  "127.0.0.1:1080",
			},
		},
		"without_auth": {
			settings: Settings{
				Address: "127.0.0.1:1080",
			},
			expected: &server{
				address: "127.0.0.1:1080",
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := newServer(testCase.settings)
			assert.Equal(t, testCase.expected.username, result.username)
			assert.Equal(t, testCase.expected.password, result.password)
			assert.Equal(t, testCase.expected.address, result.address)
			assert.Equal(t, testCase.expected.logger, result.logger)
		})
	}
}

func Test_Server_StartStop(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	logger := NewMockLogger(ctrl)
	logger.EXPECT().Infof("SOCKS5 TCP server listening on %s", gomock.Any())
	logger.EXPECT().Infof("SOCKS5 UDP server listening on %s", gomock.Any())

	server := newServer(Settings{
		Address: "127.0.0.1:0",
		Logger:  logger,
	})

	runErr, startErr := server.Start(t.Context())
	require.NoError(t, startErr)

	select {
	case err := <-runErr:
		t.Fatalf("unexpected error on start: %v", err)
	default:
	}

	address := server.listeningAddress()
	assert.NotNil(t, address)

	err := server.Stop()
	require.NoError(t, err)
}

func Test_encodeBindData(t *testing.T) {
	t.Parallel()
	testCases := map[string]struct {
		addrType    addrType
		address     string
		port        uint16
		expectedErr string
	}{
		"ipv4_valid": {
			addrType: ipv4,
			address:  "127.0.0.1",
			port:     8080,
		},
		"ipv6_valid": {
			addrType: ipv6,
			address:  "::1",
			port:     8080,
		},
		"domain_name_valid": {
			addrType: domainName,
			address:  "example.com",
			port:     8080,
		},
		"ipv4_invalid": {
			addrType:    ipv4,
			address:     "invalid",
			expectedErr: "parsing IP address",
		},
		"ipv4_actual_ipv6": {
			addrType:    ipv4,
			address:     "::1",
			expectedErr: "ip version is unexpected",
		},
		"ipv6_actual_ipv4": {
			addrType:    ipv6,
			address:     "127.0.0.1",
			expectedErr: "ip version is unexpected",
		},
		"domain_too_long": {
			addrType:    domainName,
			address:     strings.Repeat("a", 256),
			expectedErr: "domain name is too long",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			data, err := encodeBindData(testCase.addrType, testCase.address, testCase.port)

			if testCase.expectedErr != "" {
				assert.ErrorContains(t, err, testCase.expectedErr)
				assert.Nil(t, data)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, data)

				assert.Equal(t, byte(testCase.addrType), data[0])

				portOffset := len(data) - 2
				decodedPort := binary.BigEndian.Uint16(data[portOffset:])
				assert.Equal(t, testCase.port, decodedPort)
			}
		})
	}
}

func Test_decodeRequest(t *testing.T) {
	t.Parallel()
	testCases := map[string]struct {
		packet      []byte
		expectedErr string
		validate    func(*testing.T, request)
	}{
		"ipv4_valid": {
			packet: []byte{socks5Version, byte(connect), 0, byte(ipv4), 127, 0, 0, 1, byte(0x1f), byte(0x90)},
			validate: func(t *testing.T, request request) {
				t.Helper()
				assert.Equal(t, connect, request.command)
				assert.Equal(t, "127.0.0.1", request.destination)
				assert.Equal(t, uint16(8080), request.port)
				assert.Equal(t, ipv4, request.addressType)
			},
		},
		"domain_name_valid": {
			packet: concatBytes(
				[]byte{socks5Version, byte(connect), 0, byte(domainName)},
				[]byte{byte(len("example.com"))},
				[]byte("example.com"),
				[]byte{0x00, 0x50},
			),
			validate: func(t *testing.T, request request) {
				t.Helper()
				assert.Equal(t, "example.com", request.destination)
				assert.Equal(t, uint16(80), request.port)
				assert.Equal(t, domainName, request.addressType)
			},
		},
		"version_mismatch": {
			packet:      []byte{4, byte(connect), 0, byte(ipv4), 127, 0, 0, 1, 0, 0},
			expectedErr: "version is not supported",
		},
		"truncated_header": {
			packet:      []byte{socks5Version, byte(connect)},
			expectedErr: "reading header",
		},
		"unsupported_address_type": {
			packet:      []byte{socks5Version, byte(connect), 0, byte(255)},
			expectedErr: "address type is not supported",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			reader := bytes.NewReader(testCase.packet)

			request, err := decodeRequest(reader, socks5Version)

			if testCase.expectedErr != "" {
				assert.ErrorContains(t, err, testCase.expectedErr)
			} else {
				assert.NoError(t, err)
				testCase.validate(t, request)
			}
		})
	}
}

func Test_udpAssociateExpectedClientEndpoint(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		request     request
		expected    netip.AddrPort
		expectedErr string
	}{
		"ipv4_endpoint": {
			request: request{
				addressType: ipv4,
				destination: "192.0.2.10",
				port:        5555,
			},
			expected: netip.MustParseAddrPort("192.0.2.10:5555"),
		},
		"ipv4_unspecified_address": {
			request: request{
				addressType: ipv4,
				destination: "0.0.0.0",
				port:        6000,
			},
			expected: netip.AddrPortFrom(netip.Addr{}, 6000),
		},
		"domain_name_with_port": {
			request: request{
				addressType: domainName,
				destination: "client.example",
				port:        7000,
			},
			expected: netip.AddrPortFrom(netip.Addr{}, 7000),
		},
		"domain_name_without_port": {
			request: request{
				addressType: domainName,
				destination: "client.example",
			},
			expected: netip.AddrPort{},
		},
		"unsupported_address_type": {
			request: request{
				addressType: 255,
			},
			expectedErr: "address type 255 is not supported",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			result, err := udpAssociateExpectedClientEndpoint(testCase.request)

			if testCase.expectedErr != "" {
				assert.ErrorContains(t, err, testCase.expectedErr)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, testCase.expected, result)
		})
	}
}

func Test_verifyFirstNegotiation(t *testing.T) {
	t.Parallel()
	testCases := map[string]struct {
		packet       []byte
		requiredAuth authMethod
		expectedErr  string
	}{
		"version_mismatch": {
			packet:       []byte{4, 2, byte(authNotRequired), byte(authUsernamePassword)},
			requiredAuth: authNotRequired,
			expectedErr:  "version is not supported",
		},
		"no_methods": {
			packet:       []byte{socks5Version, 0},
			requiredAuth: authNotRequired,
			expectedErr:  "no method identifiers",
		},
		"required_method_not_present": {
			packet:       []byte{socks5Version, 2, byte(authNotRequired), byte(authGssapi)},
			requiredAuth: authUsernamePassword,
			expectedErr:  "no valid method identifier",
		},
		"required_method_present": {
			packet:       []byte{socks5Version, 3, byte(authNotRequired), byte(authUsernamePassword), byte(authGssapi)},
			requiredAuth: authUsernamePassword,
		},
		"no_auth_required": {
			packet:       []byte{socks5Version, 1, byte(authNotRequired)},
			requiredAuth: authNotRequired,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			reader := bytes.NewReader(testCase.packet)

			err := verifyFirstNegotiation(reader, testCase.requiredAuth)

			if testCase.expectedErr != "" {
				assert.ErrorContains(t, err, testCase.expectedErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_usernamePasswordSubnegotiate(t *testing.T) {
	t.Parallel()
	testCases := map[string]struct {
		packet      []byte
		username    string
		password    string
		expectedErr string
	}{
		"valid_credentials": {
			packet: concatBytes(
				[]byte{authUsernamePasswordSubNegotiation1, 4},
				[]byte("user"),
				[]byte{4},
				[]byte("pass"),
			),
			username: "user",
			password: "pass",
		},
		"version_mismatch": {
			packet:      []byte{2, 4, 'u', 's', 'e', 'r'},
			username:    "user",
			password:    "pass",
			expectedErr: "subnegotiation version not supported",
		},
		"wrong_username": {
			packet: concatBytes(
				[]byte{authUsernamePasswordSubNegotiation1, 4},
				[]byte("fake"),
				[]byte{4},
				[]byte("pass"),
			),
			username:    "user",
			password:    "pass",
			expectedErr: "username received is not valid",
		},
		"wrong_password": {
			packet: concatBytes(
				[]byte{authUsernamePasswordSubNegotiation1, 4},
				[]byte("user"),
				[]byte{4},
				[]byte("fake"),
			),
			username:    "user",
			password:    "pass",
			expectedErr: "password not valid",
		},
		"truncated_header": {
			packet:      []byte{authUsernamePasswordSubNegotiation1},
			username:    "user",
			password:    "pass",
			expectedErr: "reading header",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			buffer := bytes.NewBuffer(testCase.packet)

			readWriter := struct {
				io.Reader
				io.Writer
			}{
				Reader: buffer,
				Writer: io.Discard,
			}

			err := usernamePasswordSubnegotiate(readWriter, testCase.username, testCase.password)

			if testCase.expectedErr != "" {
				assert.ErrorContains(t, err, testCase.expectedErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func concatBytes(slices ...[]byte) []byte {
	var result []byte
	for _, slice := range slices {
		result = append(result, slice...)
	}
	return result
}

func Test_bindDataLength(t *testing.T) {
	t.Parallel()
	testCases := map[string]struct {
		addrType      addrType
		address       string
		wantMaxLength uint
	}{
		"ipv4": {
			addrType:      ipv4,
			address:       "127.0.0.1",
			wantMaxLength: 1 + 4 + 2,
		},
		"ipv6": {
			addrType:      ipv6,
			address:       "::1",
			wantMaxLength: 1 + 16 + 2,
		},
		"domain_short": {
			addrType:      domainName,
			address:       "example.com",
			wantMaxLength: 1 + 1 + uint(len("example.com")) + 2,
		},
		"domain_long": {
			addrType:      domainName,
			address:       strings.Repeat("a", 100),
			wantMaxLength: 1 + 1 + 100 + 2,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			length := bindDataLength(testCase.addrType, testCase.address)
			assert.Equal(t, testCase.wantMaxLength, length)
		})
	}
}

func Test_authMethod_String(t *testing.T) {
	t.Parallel()
	testCases := map[string]struct {
		method       authMethod
		expectedName string
	}{
		"no_auth": {
			method:       authNotRequired,
			expectedName: "no authentication required",
		},
		"gssapi": {
			method:       authGssapi,
			expectedName: "GSSAPI",
		},
		"username_password": {
			method:       authUsernamePassword,
			expectedName: "username/password",
		},
		"not_acceptable": {
			method:       authNotAcceptable,
			expectedName: "no acceptable methods",
		},
		"unknown": {
			method:       authMethod(99),
			expectedName: "unknown method (99)",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := testCase.method.String()
			assert.Equal(t, testCase.expectedName, result)
		})
	}
}

func Test_cmdType_String(t *testing.T) {
	t.Parallel()
	testCases := map[string]struct {
		cmd          cmdType
		expectedName string
	}{
		"connect": {
			cmd:          connect,
			expectedName: "connect",
		},
		"udp_associate": {
			cmd:          udpAssociate,
			expectedName: "UDP associate",
		},
		"unknown": {
			cmd:          cmdType(99),
			expectedName: "unknown command (99)",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := testCase.cmd.String()
			assert.Equal(t, testCase.expectedName, result)
		})
	}
}

func Test_socksConn_udpAssociationAddresses(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		routerAddress         string
		expectAddressFromConn bool
		expectedAddress       string
	}{
		"wildcard_router_address_uses_control_connection_local_ip": {
			routerAddress:         ":0",
			expectAddressFromConn: true,
		},
		"concrete_router_address_is_kept": {
			routerAddress:   "127.0.0.1:0",
			expectedAddress: "127.0.0.1",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			router, err := newUDPRouter(t.Context(), testCase.routerAddress, noopLogger{})
			require.NoError(t, err)
			t.Cleanup(func() {
				err := router.close()
				assert.NoError(t, err)
			})

			controlListener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
			require.NoError(t, err)
			t.Cleanup(func() {
				err := controlListener.Close()
				assert.NoError(t, err)
			})

			acceptedConnCh := make(chan net.Conn, 1)
			go func() {
				acceptedConn, acceptErr := controlListener.Accept()
				if acceptErr != nil {
					return
				}
				acceptedConnCh <- acceptedConn
			}()

			clientControlConn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", controlListener.Addr().String())
			require.NoError(t, err)
			defer clientControlConn.Close()

			serverControlConn := <-acceptedConnCh
			defer serverControlConn.Close()

			socksConnection := &socksConn{
				clientConn: clientControlConn,
				udpRouter:  router,
			}
			bindAddress, bindPort, bindAddrType, err := socksConnection.udpAssociationAddresses()
			require.NoError(t, err)

			if testCase.expectAddressFromConn {
				clientLocalHost, _, err := net.SplitHostPort(clientControlConn.LocalAddr().String())
				require.NoError(t, err)
				assert.Equal(t, clientLocalHost, bindAddress)
			} else {
				assert.Equal(t, testCase.expectedAddress, bindAddress)
			}

			_, routerPortString, err := net.SplitHostPort(router.localAddress().String())
			require.NoError(t, err)
			routerPort, err := strconv.ParseUint(routerPortString, 10, 16)
			require.NoError(t, err)
			assert.Equal(t, uint16(routerPort), bindPort)
			assert.Equal(t, ipv4, bindAddrType)
		})
	}
}

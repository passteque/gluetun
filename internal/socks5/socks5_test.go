package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type noopLogger struct{}

func (noopLogger) Infof(string, ...interface{}) {}
func (noopLogger) Warnf(string, ...interface{}) {}

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
			backendListener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
			require.NoError(t, err)

			backendConnCh := make(chan net.Conn, 1)
			go func() {
				conn, err := backendListener.Accept()
				if err != nil {
					return
				}
				backendConnCh <- conn
			}()

			server := New(Settings{
				Username: testCase.username,
				Password: testCase.password,
				Address:  "127.0.0.1:0",
				Logger:   noopLogger{},
			})
			_, err = server.Start(context.Background())
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

// dialSOCKS5 performs the full SOCKS5 handshake (with optional username/password
// subnegotiation) and returns a connected net.Conn ready for data exchange.
func dialSOCKS5(t *testing.T, proxyAddr, targetAddr, username, password string) net.Conn {
	t.Helper()

	host, portStr, err := net.SplitHostPort(targetAddr)
	require.NoError(t, err)
	targetPort, err := strconv.Atoi(portStr)
	require.NoError(t, err)

	conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", proxyAddr)
	require.NoError(t, err)

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

	var responseHeader [4]byte
	_, err = io.ReadFull(conn, responseHeader[:])
	require.NoError(t, err)
	require.Equal(t, socks5Version, responseHeader[0])
	require.Equal(t, byte(succeeded), responseHeader[1])

	// Consume BND.ADDR and BND.PORT (their values are irrelevant to the caller).
	switch addrType(responseHeader[3]) {
	case ipv4:
		var addrPort [net.IPv4len + 2]byte
		_, err = io.ReadFull(conn, addrPort[:])
		require.NoError(t, err)
	case ipv6:
		var addrPort [net.IPv6len + 2]byte
		_, err = io.ReadFull(conn, addrPort[:])
		require.NoError(t, err)
	case domainName:
		var lenBuf [1]byte
		_, err = io.ReadFull(conn, lenBuf[:])
		require.NoError(t, err)
		addrPort := make([]byte, int(lenBuf[0])+2)
		_, err = io.ReadFull(conn, addrPort)
		require.NoError(t, err)
	}

	return conn
}

func TestNew(t *testing.T) {
	t.Parallel()
	testCases := map[string]struct {
		settings Settings
		expected *Server
	}{
		"with_auth": {
			settings: Settings{
				Username: "user",
				Password: "pass",
				Address:  "127.0.0.1:1080",
				Logger:   nil,
			},
			expected: &Server{
				username: "user",
				password: "pass",
				address:  "127.0.0.1:1080",
				logger:   nil,
			},
		},
		"without_auth": {
			settings: Settings{
				Address: "127.0.0.1:1080",
				Logger:  nil,
			},
			expected: &Server{
				address: "127.0.0.1:1080",
				logger:  nil,
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := New(testCase.settings)
			assert.Equal(t, testCase.expected.username, result.username)
			assert.Equal(t, testCase.expected.password, result.password)
			assert.Equal(t, testCase.expected.address, result.address)
			assert.Equal(t, testCase.expected.logger, result.logger)
		})
	}
}

func TestStartStop(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	logger := NewMockLogger(ctrl)
	logger.EXPECT().Infof(gomock.Any(), gomock.Any()).Times(0)
	logger.EXPECT().Warnf(gomock.Any(), gomock.Any()).Times(0)

	server := New(Settings{
		Address: "127.0.0.1:0",
		Logger:  logger,
	})

	runErr, startErr := server.Start(context.Background())
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

func TestEncodeBindData(t *testing.T) {
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

func TestDecodeRequest(t *testing.T) {
	t.Parallel()
	testCases := map[string]struct {
		buildPacket func() []byte
		expectedErr string
		validate    func(*testing.T, request)
	}{
		"ipv4_valid": {
			buildPacket: func() []byte {
				packet := []byte{socks5Version, byte(connect), 0, byte(ipv4)}
				packet = append(packet, 127, 0, 0, 1)
				packet = append(packet, byte(0x1f), byte(0x90))
				return packet
			},
			validate: func(t *testing.T, req request) {
				t.Helper()
				assert.Equal(t, connect, req.command)
				assert.Equal(t, "127.0.0.1", req.destination)
				assert.Equal(t, uint16(8080), req.port)
				assert.Equal(t, ipv4, req.addressType)
			},
		},
		"domain_name_valid": {
			buildPacket: func() []byte {
				packet := []byte{socks5Version, byte(connect), 0, byte(domainName)}
				domain := "example.com"
				packet = append(packet, byte(len(domain)))
				packet = append(packet, []byte(domain)...)
				packet = append(packet, byte(0x00), byte(0x50))
				return packet
			},
			validate: func(t *testing.T, req request) {
				t.Helper()
				assert.Equal(t, "example.com", req.destination)
				assert.Equal(t, uint16(80), req.port)
				assert.Equal(t, domainName, req.addressType)
			},
		},
		"version_mismatch": {
			buildPacket: func() []byte {
				return []byte{4, byte(connect), 0, byte(ipv4), 127, 0, 0, 1, 0, 0}
			},
			expectedErr: "version is not supported",
		},
		"truncated_header": {
			buildPacket: func() []byte {
				return []byte{socks5Version, byte(connect)}
			},
			expectedErr: "reading header",
		},
		"unsupported_address_type": {
			buildPacket: func() []byte {
				packet := []byte{socks5Version, byte(connect), 0, byte(255)}
				return packet
			},
			expectedErr: "address type is not supported",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			packet := testCase.buildPacket()
			reader := bytes.NewReader(packet)

			req, err := decodeRequest(reader, socks5Version)

			if testCase.expectedErr != "" {
				assert.ErrorContains(t, err, testCase.expectedErr)
			} else {
				assert.NoError(t, err)
				testCase.validate(t, req)
			}
		})
	}
}

func TestVerifyFirstNegotiation(t *testing.T) {
	t.Parallel()
	testCases := map[string]struct {
		buildPacket  func() []byte
		requiredAuth authMethod
		expectedErr  string
	}{
		"version_mismatch": {
			buildPacket: func() []byte {
				return []byte{4, 2, byte(authNotRequired), byte(authUsernamePassword)}
			},
			requiredAuth: authNotRequired,
			expectedErr:  "version is not supported",
		},
		"no_methods": {
			buildPacket: func() []byte {
				return []byte{socks5Version, 0}
			},
			requiredAuth: authNotRequired,
			expectedErr:  "no method identifiers",
		},
		"required_method_not_present": {
			buildPacket: func() []byte {
				return []byte{socks5Version, 2, byte(authNotRequired), byte(authGssapi)}
			},
			requiredAuth: authUsernamePassword,
			expectedErr:  "no valid method identifier",
		},
		"required_method_present": {
			buildPacket: func() []byte {
				return []byte{socks5Version, 3, byte(authNotRequired), byte(authUsernamePassword), byte(authGssapi)}
			},
			requiredAuth: authUsernamePassword,
		},
		"no_auth_required": {
			buildPacket: func() []byte {
				return []byte{socks5Version, 1, byte(authNotRequired)}
			},
			requiredAuth: authNotRequired,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			packet := testCase.buildPacket()
			reader := bytes.NewReader(packet)

			err := verifyFirstNegotiation(reader, testCase.requiredAuth)

			if testCase.expectedErr != "" {
				assert.ErrorContains(t, err, testCase.expectedErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestUsernamePasswordSubnegotiate(t *testing.T) {
	t.Parallel()
	testCases := map[string]struct {
		buildPacket func() []byte
		username    string
		password    string
		expectedErr string
	}{
		"valid_credentials": {
			buildPacket: func() []byte {
				packet := []byte{authUsernamePasswordSubNegotiation1, 4}
				packet = append(packet, []byte("user")...)
				packet = append(packet, 4)
				packet = append(packet, []byte("pass")...)
				return packet
			},
			username: "user",
			password: "pass",
		},
		"version_mismatch": {
			buildPacket: func() []byte {
				return []byte{2, 4, 'u', 's', 'e', 'r'}
			},
			username:    "user",
			password:    "pass",
			expectedErr: "subnegotiation version not supported",
		},
		"wrong_username": {
			buildPacket: func() []byte {
				packet := []byte{authUsernamePasswordSubNegotiation1, 4}
				packet = append(packet, []byte("fake")...)
				packet = append(packet, 4)
				packet = append(packet, []byte("pass")...)
				return packet
			},
			username:    "user",
			password:    "pass",
			expectedErr: "username not valid",
		},
		"wrong_password": {
			buildPacket: func() []byte {
				packet := []byte{authUsernamePasswordSubNegotiation1, 4}
				packet = append(packet, []byte("user")...)
				packet = append(packet, 4)
				packet = append(packet, []byte("fake")...)
				return packet
			},
			username:    "user",
			password:    "pass",
			expectedErr: "password not valid",
		},
		"truncated_header": {
			buildPacket: func() []byte {
				return []byte{authUsernamePasswordSubNegotiation1}
			},
			username:    "user",
			password:    "pass",
			expectedErr: "reading header",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			packet := testCase.buildPacket()
			buffer := &bytes.Buffer{}
			buffer.Write(packet)

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

func TestBindDataLength(t *testing.T) {
	t.Parallel()
	testCases := map[string]struct {
		addrType      addrType
		address       string
		expectedBytes int
	}{
		"ipv4": {
			addrType:      ipv4,
			address:       "127.0.0.1",
			expectedBytes: 1 + 4 + 2,
		},
		"ipv6": {
			addrType:      ipv6,
			address:       "::1",
			expectedBytes: 1 + 16 + 2,
		},
		"domain_short": {
			addrType:      domainName,
			address:       "example.com",
			expectedBytes: 1 + 1 + len("example.com") + 2,
		},
		"domain_long": {
			addrType:      domainName,
			address:       strings.Repeat("a", 100),
			expectedBytes: 1 + 1 + 100 + 2,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			length := bindDataLength(testCase.addrType, testCase.address)
			assert.Equal(t, testCase.expectedBytes, length)
		})
	}
}

func TestAuthMethodString(t *testing.T) {
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

func TestCmdTypeString(t *testing.T) {
	t.Parallel()
	testCases := map[string]struct {
		cmd          cmdType
		expectedName string
	}{
		"connect": {
			cmd:          connect,
			expectedName: "connect",
		},
		"bind": {
			cmd:          bind,
			expectedName: "bind",
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

func TestParseAddress(t *testing.T) {
	t.Parallel()
	testCases := map[string]struct {
		address     string
		expectedIP  string
		expectedErr string
	}{
		"ipv4": {
			address:    "127.0.0.1",
			expectedIP: "127.0.0.1",
		},
		"ipv6": {
			address:    "::1",
			expectedIP: "::1",
		},
		"domain": {
			address:     "example.com",
			expectedErr: "parsing IP address",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if testCase.expectedErr == "" {
				assert.True(t, strings.Contains(testCase.address, testCase.expectedIP) || testCase.address == testCase.expectedIP)
			}
		})
	}
}

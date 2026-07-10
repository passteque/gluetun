//go:build integration

package socks5

import (
	"math/rand/v2"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Server_UDPResolution(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	server := newServer(Settings{
		Address: "127.0.0.1:0",
		Logger:  noopLogger{},
	})
	runErr, err := server.Start(ctx)
	require.NoError(t, err, "starting SOCKS5 server")

	const timeout = 3 * time.Second

	// Connect to the SOCKS5 server via TCP to negotiate UDP associate
	dialer := &net.Dialer{Timeout: timeout}
	tcpConn, err := dialer.DialContext(ctx, "tcp", server.listeningAddress().String())
	require.NoError(t, err, "tcp connecting to SOCKS5 server")
	t.Cleanup(func() { tcpConn.Close() })

	negotiateSOCKS5(t, tcpConn, "", "")

	// UDP Associate Command: [VERSION (5), CMD (3 = UDP ASSOC), RSV (0), ATYP (1 = IPv4), ADDR (0.0.0.0), PORT (0)]
	_, err = tcpConn.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	require.NoError(t, err, "sending UDP ASSOC request")

	relayAddressString, err := readSOCKS5ResponseAddress(t, tcpConn)
	require.NoError(t, err, "reading UDP ASSOC reply")
	relayAddress, err := net.ResolveUDPAddr("udp", relayAddressString)
	require.NoError(t, err, "resolving udp relay address")

	// Dial the relay using IPv4 so source IP family matches the control connection.
	udpConn, err := net.DialUDP("udp4", nil, relayAddress)
	require.NoError(t, err, "dialing UDP relay")
	t.Cleanup(func() { _ = udpConn.Close() })

	queryID := uint16(rand.Uint32()) //nolint:gosec
	dnsRequest := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               queryID,
			RecursionDesired: true,
		},
		Question: []dns.Question{{
			Name:   dns.Fqdn("github.com"),
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}},
	}
	dnsQuery, err := dnsRequest.Pack()
	require.NoError(t, err)

	// Encapsulate DNS payload into SOCKS5 UDP Request Header
	// [RSV (0,0), FRAG (0), ATYP (1 = IPv4), DST.ADDR (1.1.1.1), DST.PORT (53)]
	packet := append([]byte{0, 0, 0, 1, 1, 1, 1, 1, 0, 53}, dnsQuery...)

	// Send encapsulated packet to the proxy's UDP relay address
	_, err = udpConn.Write(packet)
	require.NoError(t, err, "sending UDP packet to relay")

	// Read response from the proxy relay
	err = udpConn.SetReadDeadline(time.Now().Add(timeout))
	require.NoError(t, err, "setting read deadline on UDP connection")
	buffer := make([]byte, 2048)
	n, err := udpConn.Read(buffer)
	require.NoError(t, err, "receiving UDP response from relay")
	const minimumHeaderSize = 10
	require.GreaterOrEqual(t, n, minimumHeaderSize, "received UDP packet too short to contain valid SOCKS5 header")

	// Verify header layout and slice out the raw DNS response
	// Header format: RSV(2) FRAG(1) ATYP(1) DST.ADDR(variable) DST.PORT(2)
	atyp := buffer[3]
	var headerSize int
	switch atyp {
	case 1: // IPv4
		headerSize = 10
	case 3: // Domain name
		headerSize = 4 + 1 + int(buffer[4]) + 2
	case 4: // IPv6
		headerSize = 22
	default:
		t.Fatalf("Unknown ATYP in SOCKS5 UDP header: %d", atyp)
	}

	dnsResponse := new(dns.Msg)
	err = dnsResponse.Unpack(buffer[headerSize:n])
	require.NoError(t, err, "unpacking DNS response from SOCKS5 UDP packet")

	assert.Equal(t, queryID, dnsResponse.Id, "DNS response ID should match query ID")

	select {
	case err := <-runErr:
		require.NoError(t, err, "SOCKS5 server run error")
	default:
	}

	err = server.Stop()
	require.NoError(t, err, "stopping SOCKS5 server")
}

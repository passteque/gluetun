//go:build integration

package socks5

import (
	"bytes"
	"context"
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_udpRouter_ResolveGithubFromCloudflareDNS(t *testing.T) {
	ctx := t.Context()
	var cancel context.CancelFunc
	deadline, hasDeadline := ctx.Deadline()
	if hasDeadline {
		const deadlineBuffer = 500 * time.Millisecond
		deadline = deadline.Add(-deadlineBuffer)
	} else {
		const defaultTimeout = 10 * time.Second
		deadline = time.Now().Add(defaultTimeout)
	}
	ctx, cancel = context.WithDeadline(ctx, deadline)

	ctrl := gomock.NewController(t)
	logger := NewMockLogger(ctrl)

	router, err := newUDPRouter(ctx, "127.0.0.1:0", logger)
	require.NoError(t, err)

	routerRunErrCh := make(chan error)
	go func() {
		routerRunErrCh <- router.run(ctx)
	}()

	t.Cleanup(func() {
		cancel()
		err := router.close()
		assert.NoError(t, err, "closing router")
		runErr := <-routerRunErrCh
		assert.NoError(t, runErr)
	})

	controlListener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		err := controlListener.Close()
		assert.NoError(t, err, "closing control listener")
	})

	acceptedConnCh := make(chan net.Conn)
	go func() {
		acceptedConn, acceptErr := controlListener.Accept()
		assert.NoError(t, acceptErr, "accepting control connection")
		if acceptErr != nil {
			return
		}
		acceptedConnCh <- acceptedConn
	}()

	clientControlConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", controlListener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() {
		err = clientControlConn.Close()
		assert.NoError(t, err, "closing client control connection")
	})

	serverControlConn := <-acceptedConnCh
	t.Cleanup(func() {
		err := serverControlConn.Close()
		assert.NoError(t, err, "closing server control connection")
	})

	association, err := router.registerAssociation(serverControlConn, netip.AddrPort{})
	require.NoError(t, err)
	t.Cleanup(func() {
		router.unregisterAssociation(association)
	})

	associationCtx, associationCancel := context.WithCancel(ctx)
	handlerDoneCh := make(chan struct{})
	go func() {
		router.runAssociationHandler(associationCtx, association)
		close(handlerDoneCh)
	}()
	t.Cleanup(func() {
		associationCancel()
		<-handlerDoneCh
	})

	udpRouterAddress, err := net.ResolveUDPAddr("udp", router.localAddress().String())
	require.NoError(t, err)

	clientUDPConn, err := net.DialUDP("udp", nil, udpRouterAddress)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := clientUDPConn.Close()
		assert.NoError(t, err, "closing client UDP connection")
	})

	queryID := uint16(rand.Uint())
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

	targetAddrPort := netip.MustParseAddrPort("1.1.1.1:53")
	socksDatagramBuffer := bytes.NewBuffer(nil)
	err = encodeUDPDatagramToBuffer(socksDatagramBuffer, targetAddrPort, dnsQuery)
	require.NoError(t, err)
	socksDatagram := socksDatagramBuffer.Bytes()

	err = clientUDPConn.SetDeadline(deadline)
	require.NoError(t, err)

	_, err = clientUDPConn.Write(socksDatagram)
	require.NoError(t, err)

	responseBuffer := make([]byte, maxUDPPacketLength)
	responseLength, err := clientUDPConn.Read(responseBuffer)
	require.NoError(t, err)

	responseDestination, responsePayload, err := decodeUDPDatagram(responseBuffer[:responseLength])
	require.NoError(t, err)

	responseHost, responsePortString, err := net.SplitHostPort(responseDestination)
	require.NoError(t, err)
	responsePort, err := strconv.ParseUint(responsePortString, 10, 16)
	require.NoError(t, err)
	assert.Equal(t, uint64(53), responsePort)
	assert.NotEmpty(t, responseHost)

	dnsResponse := new(dns.Msg)
	err = dnsResponse.Unpack(responsePayload)
	require.NoError(t, err)
	assert.Equal(t, queryID, dnsResponse.Id)
	assert.True(t, dnsResponse.Response)
	assert.Equal(t, dns.RcodeSuccess, dnsResponse.Rcode)
	require.NotEmpty(t, dnsResponse.Question)
	assert.Equal(t, dns.Fqdn("github.com"), dnsResponse.Question[0].Name)
	assert.Equal(t, uint16(dns.TypeA), dnsResponse.Question[0].Qtype)
	assert.NotEmpty(t, dnsResponse.Answer)
	require.NoError(t, err)
}

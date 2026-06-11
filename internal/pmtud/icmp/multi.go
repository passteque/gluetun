package icmp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/qdm12/gluetun/internal/pmtud/test"
	"golang.org/x/net/icmp"
)

type icmpTestUnit struct {
	mtu       uint32
	echoID    uint16
	sentBytes int
	ok        bool
}

func pmtudMultiSizes(ctx context.Context, ip netip.Addr,
	minMTU, maxPossibleMTU uint32, pingTimeout time.Duration,
	logger Logger,
) (maxMTU uint32, err error) {
	var ipVersion string
	var conn net.PacketConn
	if ip.Is4() {
		ipVersion = "v4"
		conn, err = listenICMPv4(ctx)
	} else {
		ipVersion = "v6"
		conn, err = listenICMPv6(ctx)
	}
	if err != nil {
		if strings.HasSuffix(err.Error(), "socket: operation not permitted") {
			err = fmt.Errorf("%w: you can try adding NET_RAW capability to resolve this", ErrNotPermitted)
		}
		return 0, fmt.Errorf("listening for ICMP packets: %w", err)
	}

	mtusToTest := test.MakeMTUsToTest(minMTU, maxPossibleMTU)
	if len(mtusToTest) == 1 { // only minMTU because minMTU == maxPossibleMTU
		return minMTU, nil
	}
	logger.Debugf("ICMP testing the following MTUs: %v", mtusToTest)

	tests := make([]icmpTestUnit, len(mtusToTest))
	for i := range mtusToTest {
		tests[i] = icmpTestUnit{mtu: mtusToTest[i]}
	}

	timedCtx, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()
	go func() {
		<-timedCtx.Done()
		conn.Close()
	}()

	for i := range tests {
		id, message := buildMessageToSend(ipVersion, tests[i].mtu)
		tests[i].echoID = id

		encodedMessage, err := message.Marshal(nil)
		if err != nil {
			return 0, fmt.Errorf("encoding ICMP message: %w", err)
		}
		tests[i].sentBytes = len(encodedMessage)

		_, err = conn.WriteTo(encodedMessage, &net.IPAddr{IP: ip.AsSlice()})
		if err != nil {
			if strings.HasSuffix(err.Error(), "sendto: operation not permitted") {
				err = ErrNotPermitted
			}
			return 0, fmt.Errorf("writing ICMP message: %w", err)
		}
	}

	err = collectReplies(conn, ipVersion, tests, logger)
	switch {
	case err == nil: // max possible MTU is working
		return tests[len(tests)-1].mtu, nil
	case err != nil && errors.Is(err, net.ErrClosed):
		// we have timeouts (IPv4 testing or IPv6 PMTUD blackholes)
		// so find the highest MTU which worked.
		// Note we start from index len(tests) - 2 since the max MTU
		// cannot be working if we had a timeout.
		for i := len(tests) - 2; i >= 0; i-- { //nolint:mnd
			if tests[i].ok {
				return pmtudMultiSizes(ctx, ip, tests[i].mtu, tests[i+1].mtu-1,
					pingTimeout, logger)
			}
		}

		// All MTUs failed.
		return 0, fmt.Errorf("%w: ICMP might be blocked", ErrMTUNotFound)
	case err != nil:
		return 0, fmt.Errorf("collecting ICMP echo replies: %w", err)
	default:
		panic("unreachable")
	}
}

// The theoretical limit is 4GiB for IPv6 MTU path discovery jumbograms, but that would
// create huge buffers which we don't really want to support anyway.
// The standard frame maximum MTU is 1500 bytes, and there are Jumbo frames with
// a conventional maximum of 9000 bytes. However, some manufacturers support up
// 9216-20 = 9196 bytes for the maximum MTU. We thus use buffers of size 9196 to
// match eventual Jumbo frames. More information at:
// https://en.wikipedia.org/wiki/Maximum_transmission_unit#MTUs_for_common_media
const maxPossibleMTU = 9196

func collectReplies(conn net.PacketConn, ipVersion string,
	tests []icmpTestUnit, logger Logger,
) (err error) {
	echoIDToTestIndex := make(map[uint16]int, len(tests))
	for i, test := range tests {
		echoIDToTestIndex[test.echoID] = i
	}

	buffer := make([]byte, maxPossibleMTU)

	idsFound := 0
	for idsFound < len(tests) {
		// Note we need to read the whole packet in one call to ReadFrom, so the buffer
		// must be large enough to read the entire reply packet. See:
		// https://groups.google.com/g/golang-nuts/c/5dy2Q4nPs08/m/KmuSQAGEtG4J
		bytesRead, _, err := conn.ReadFrom(buffer)
		if err != nil {
			return fmt.Errorf("reading from ICMP connection: %w", err)
		}
		packetBytes := buffer[:bytesRead]

		ipPacketLength := len(packetBytes)

		var icmpProtocol int
		switch ipVersion {
		case "v4":
			icmpProtocol = icmpv4Protocol
		case "v6":
			icmpProtocol = icmpv6Protocol
		default:
			panic(fmt.Sprintf("unknown IP version: %s", ipVersion))
		}

		// Parse the ICMP message
		// Note: this parsing works for a truncated 556 bytes ICMP reply packet.
		message, err := icmp.ParseMessage(icmpProtocol, packetBytes)
		if err != nil {
			return fmt.Errorf("parsing message: %w", err)
		}

		switch message.Body.(type) {
		case *icmp.Echo:
		case *icmp.DstUnreach, *icmp.TimeExceeded:
			logger.Debugf("ignoring ICMP message (type: %d, code: %d)", message.Type, message.Code)
			continue
		default:
			return fmt.Errorf("ICMP body type is not supported: %T", message.Body)
		}

		echoBody, _ := message.Body.(*icmp.Echo)

		id := uint16(echoBody.ID) //nolint:gosec
		testIndex, testing := echoIDToTestIndex[id]
		if !testing { // not an id we expected so ignore it
			logger.Warnf("ignoring ICMP reply with unexpected ID %d (type: %d, code: %d, length: %d)",
				echoBody.ID, message.Type, message.Code, ipPacketLength)
			continue
		}
		idsFound++
		sentBytes := tests[testIndex].sentBytes

		// echo reply should be at most the number of bytes sent,
		// and can be lower, more precisely 556 bytes, in case
		// the host we are reaching wants to stay out of trouble
		// and ensure its echo reply goes through without
		// fragmentation, see the following page:
		// https://datatracker.ietf.org/doc/html/rfc1122#page-59
		const conservativeReplyLength = 556
		truncated := ipPacketLength < sentBytes &&
			ipPacketLength == conservativeReplyLength
		// Check the packet size is the same if the reply is not truncated
		if !truncated && sentBytes != ipPacketLength {
			return fmt.Errorf("ICMP data mismatch: sent %dB and received %dB",
				sentBytes, ipPacketLength)
		}
		// Truncated reply or matching reply size
		tests[testIndex].ok = true
	}
	return nil
}

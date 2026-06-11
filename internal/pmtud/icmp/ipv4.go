package icmp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/qdm12/gluetun/internal/pmtud/constants"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	icmpv4Protocol = 1
)

func listenICMPv4(ctx context.Context) (conn net.PacketConn, err error) {
	var listenConfig net.ListenConfig
	listenConfig.Control = func(_, _ string, rawConn syscall.RawConn) error {
		var setDFErr error
		err := rawConn.Control(func(fd uintptr) {
			const ipv4 = true
			setDFErr = setDontFragment(fd, ipv4) // runs when calling ListenPacket
		})
		if err == nil {
			err = setDFErr
		}
		return err
	}

	const listenAddress = ""
	packetConn, err := listenConfig.ListenPacket(ctx, "ip4:icmp", listenAddress)
	if err != nil {
		if strings.HasSuffix(err.Error(), "socket: operation not permitted") {
			err = fmt.Errorf("%w: you can try adding NET_RAW capability to resolve this", ErrNotPermitted)
		}
		return nil, err
	}

	if runtime.GOOS == "darwin" || runtime.GOOS == "ios" {
		packetConn = ipv4ToNetPacketConn(ipv4.NewPacketConn(packetConn))
	}

	return packetConn, nil
}

func findIPv4NextHopMTU(ctx context.Context, ip netip.Addr,
	physicalLinkMTU uint32, pingTimeout time.Duration, logger Logger,
) (mtu uint32, err error) {
	if ip.Is6() {
		panic("IP address is not v4")
	}
	conn, err := listenICMPv4(ctx)
	if err != nil {
		return 0, fmt.Errorf("listening for ICMP packets: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	// First try to send a packet which is too big to get the maximum MTU
	// directly.
	outboundID, outboundMessage := buildMessageToSend("v4", physicalLinkMTU)
	encodedMessage, err := outboundMessage.Marshal(nil)
	if err != nil {
		return 0, fmt.Errorf("encoding ICMP message: %w", err)
	}

	_, err = conn.WriteTo(encodedMessage, &net.IPAddr{IP: ip.AsSlice()})
	if err != nil {
		err = wrapConnErr(err, ctx, pingTimeout)
		return 0, fmt.Errorf("writing ICMP message: %w", err)
	}

	buffer := make([]byte, physicalLinkMTU)

	// for loop in case we read an ICMP message from another ICMP request
	// or TCP/UDP traffic triggering an ICMP response.
	for {
		// Note we need to read the whole packet in one call to ReadFrom, so the buffer
		// must be large enough to read the entire reply packet. See:
		// https://groups.google.com/g/golang-nuts/c/5dy2Q4nPs08/m/KmuSQAGEtG4J
		bytesRead, _, err := conn.ReadFrom(buffer)
		if err != nil {
			err = wrapConnErr(err, ctx, pingTimeout)
			return 0, fmt.Errorf("reading from ICMP connection: %w", err)
		}
		packetBytes := buffer[:bytesRead]
		// Side note: echo reply should be at most the number of bytes
		// sent, and can be lower, more precisely 576-ipHeader bytes,
		// in case the next hop we are reaching replies with a destination
		// unreachable and wants to ensure the response makes it way back
		// by keeping a low packet size, see:
		// https://datatracker.ietf.org/doc/html/rfc1122#page-59

		inboundMessage, err := icmp.ParseMessage(icmpv4Protocol, packetBytes)
		if err != nil {
			return 0, fmt.Errorf("parsing message: %w", err)
		}

		switch typedBody := inboundMessage.Body.(type) {
		case *icmp.DstUnreach:
			const fragmentationRequiredAndDFFlagSetCode = 4
			const portUnreachable = 3
			const communicationAdministrativelyProhibitedCode = 13
			switch inboundMessage.Code {
			case fragmentationRequiredAndDFFlagSetCode:
			case portUnreachable: // triggered by TCP or UDP from applications
				continue // ignore and wait for the next message
			case communicationAdministrativelyProhibitedCode:
				return 0, fmt.Errorf("ICMP destination unreachable: %w (code %d)", errCommunicationAdministrativelyProhibited,
					inboundMessage.Code)
			default:
				return 0, fmt.Errorf("ICMP destination unreachable: code %d", inboundMessage.Code)
			}

			// See https://datatracker.ietf.org/doc/html/rfc1191#section-4
			// Note: the go library does not handle this NextHopMTU section.
			nextHopMTU := packetBytes[6:8]
			mtu = uint32(binary.BigEndian.Uint16(nextHopMTU))
			err = checkMTU(mtu, constants.MinIPv4MTU, physicalLinkMTU)
			if err != nil {
				return 0, fmt.Errorf("checking next-hop-mtu found: %w", err)
			}

			// The code below is really for sanity checks
			packetBytes = packetBytes[8:]
			header, err := ipv4.ParseHeader(packetBytes)
			if err != nil {
				return 0, fmt.Errorf("parsing IPv4 header: %w", err)
			}
			packetBytes = packetBytes[header.Len:] // truncated original datagram

			const truncated = true
			err = checkEchoReply(icmpv4Protocol, packetBytes, outboundMessage, truncated)
			if err != nil {
				return 0, fmt.Errorf("checking echo reply: %w", err)
			}
			return mtu, nil
		case *icmp.Echo:
			inboundID := uint16(typedBody.ID) //nolint:gosec
			if inboundID == outboundID {
				return physicalLinkMTU, nil
			}
			logger.Debugf("discarding received ICMP echo reply with id %d mismatching sent id %d",
				inboundID, outboundID)
			continue
		default:
			return 0, fmt.Errorf("ICMP body type is not supported: %T", typedBody)
		}
	}
}

package icmp

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type Echoer struct {
	buffer       []byte
	randomSource io.Reader
	logger       Logger
	seqStart     time.Time
	id           int
	seq          int
}

func NewEchoer(logger Logger) *Echoer {
	const maxICMPEchoSize = 1500
	buffer := make([]byte, maxICMPEchoSize)
	var seed [32]byte
	_, _ = cryptorand.Read(seed[:])
	randomSource := rand.NewChaCha8(seed)
	return &Echoer{
		buffer:       buffer,
		randomSource: randomSource,
		logger:       logger,
	}
}

// Reset resets the [Echoer] icmp echo parameters:
// - ID is assigned a new random value
// - sequence is reset to 1
// - sequence start time is set to now
// It is used when the sequence is complete or when the VPN reconnects.
func (e *Echoer) Reset() {
	const uint16Bytes = 2
	idBytes := make([]byte, uint16Bytes)
	_, _ = e.randomSource.Read(idBytes)
	e.id = int(binary.BigEndian.Uint16(idBytes))
	e.seq = 1
	e.seqStart = time.Now()
}

var ErrNotPermitted = errors.New("not permitted")

func (e *Echoer) Echo(ctx context.Context, ip netip.Addr) (err error) {
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
		return fmt.Errorf("listening for ICMP packets: %w", err)
	}

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	const maxSeq = 1<<16 - 1
	const refreshIDInterval = 5 * time.Minute
	if e.seq > maxSeq && time.Since(e.seqStart) >= refreshIDInterval {
		e.Reset()
	}

	message := buildMessageToSend(ipVersion, e.id, e.seq, e.randomSource)

	encodedMessage, err := message.Marshal(nil)
	if err != nil {
		return fmt.Errorf("encoding ICMP message: %w", err)
	}

	_, err = conn.WriteTo(encodedMessage, &net.IPAddr{IP: ip.AsSlice()})
	if err != nil {
		if strings.HasSuffix(err.Error(), "sendto: operation not permitted") {
			err = fmt.Errorf("%w", ErrNotPermitted)
		}
		return fmt.Errorf("writing ICMP message to %s: %w", ip, err)
	}
	defer func() {
		e.seq++
	}()

	receivedData, err := receiveEchoReply(conn, e.id, e.seq, e.buffer, ipVersion, e.logger)
	if err != nil {
		if errors.Is(err, net.ErrClosed) && ctx.Err() != nil {
			return fmt.Errorf("timed out waiting for ICMP echo reply from %s", ip)
		}
		return fmt.Errorf("receiving ICMP echo reply from %s: %w", ip, err)
	}

	sentData := message.Body.(*icmp.Echo).Data //nolint:forcetypeassert
	if !bytes.Equal(receivedData, sentData) {
		return fmt.Errorf("ICMP data mismatch: sent %x to %s and received %x", sentData, ip, receivedData)
	}

	return nil
}

func buildMessageToSend(ipVersion string, id, seq int, randomSource io.Reader) (message *icmp.Message) {
	var icmpType icmp.Type
	switch ipVersion {
	case "v4":
		icmpType = ipv4.ICMPTypeEcho
	case "v6":
		icmpType = ipv6.ICMPTypeEchoRequest
	default:
		panic(fmt.Sprintf("IP version %q not supported", ipVersion))
	}
	const size = 32
	messageBodyData := make([]byte, size)
	_, _ = randomSource.Read(messageBodyData)

	// See https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-types
	message = &icmp.Message{
		Type:     icmpType, // echo request
		Code:     0,        // no code
		Checksum: 0,        // calculated at encoding (ipv4) or sending (ipv6)
		Body: &icmp.Echo{
			ID:   id,
			Seq:  seq,
			Data: messageBodyData,
		},
	}
	return message
}

func receiveEchoReply(conn net.PacketConn, id, seq int, buffer []byte, ipVersion string, logger Logger,
) (data []byte, err error) {
	var icmpProtocol int
	const (
		icmpv4Protocol = 1
		icmpv6Protocol = 58
	)
	switch ipVersion {
	case "v4":
		icmpProtocol = icmpv4Protocol
	case "v6":
		icmpProtocol = icmpv6Protocol
	default:
		panic(fmt.Sprintf("unknown IP version: %s", ipVersion))
	}

	for {
		// Note we need to read the whole packet in one call to ReadFrom, so the buffer
		// must be large enough to read the entire reply packet. See:
		// https://groups.google.com/g/golang-nuts/c/5dy2Q4nPs08/m/KmuSQAGEtG4J
		bytesRead, returnAddr, err := conn.ReadFrom(buffer)
		if err != nil {
			return nil, fmt.Errorf("reading from ICMP connection: %w", err)
		}
		packetBytes := buffer[:bytesRead]

		// Parse the ICMP message
		message, err := icmp.ParseMessage(icmpProtocol, packetBytes)
		if err != nil {
			return nil, fmt.Errorf("parsing message: %w", err)
		}

		switch body := message.Body.(type) {
		case *icmp.Echo:
			switch {
			case id != body.ID:
				logger.Warnf("ignoring ICMP echo reply mismatching expected id %d "+
					"(id: %d, seq: %d, type: %d, code: %d, length: %d, return address %s)",
					id, body.Seq, body.ID, message.Type, message.Code, len(packetBytes), returnAddr)
				continue // not the ID we are looking for
			case seq != body.Seq:
				logger.Warnf("ignoring ICMP echo reply mismatching expected sequence number %d "+
					"(id: %d, seq: %d, type: %d, code: %d, length: %d, return address %s)",
					seq, body.ID, body.Seq, message.Type, message.Code, len(packetBytes), returnAddr)
				continue // not the seq we are looking for
			}
			return body.Data, nil
		case *icmp.DstUnreach:
			logger.Debugf("ignoring ICMP destination unreachable message "+
				"(type: 3, code: %d, return address %s, expected id %d and seq %d)",
				message.Code, returnAddr, id, seq)
			// See https://github.com/qdm12/gluetun/pull/2923#issuecomment-3377532249
			// on why we ignore this message. If it is actually unreachable, the timeout on waiting for
			// the echo reply will do instead of returning an error error.
			continue
		case *icmp.TimeExceeded:
			logger.Debugf("ignoring ICMP time exceeded message "+
				"(type: 11, code: %d, return address %s, expected id %d and seq %d)",
				message.Code, returnAddr, id, seq)
			continue
		default:
			return nil, fmt.Errorf("ICMP body type is not supported: "+
				"%T (type %d, code %d, return address %s, expected id %d and seq %d)",
				body, message.Type, message.Code, returnAddr, id, seq)
		}
	}
}

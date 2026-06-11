package tcp

import (
	"encoding/binary"
	"fmt"

	"github.com/qdm12/gluetun/internal/pmtud/constants"
)

// For SYN, ack is 0.
// For SYN-ACK, ack is the sequence number + 1 of the SYN.
func makeTCPHeader(srcPort, dstPort uint16, seq, ack uint32, flags byte) []byte {
	header := make([]byte, constants.BaseTCPHeaderLength)
	binary.BigEndian.PutUint16(header[0:], srcPort)
	binary.BigEndian.PutUint16(header[2:], dstPort)
	binary.BigEndian.PutUint32(header[4:], seq)
	binary.BigEndian.PutUint32(header[8:], ack)
	//nolint:mnd
	header[12] = byte(constants.BaseTCPHeaderLength) << 2 // data offset
	header[13] = flags
	// windowSize can be left to 5840 even for IPv6, it doesn't matter.
	const windowSize = 5840
	binary.BigEndian.PutUint16(header[14:], windowSize)
	// header[16:17] is the checksum, set later
	// header[18:19] is urgent pointer, not needed for our use case
	return header
}

//nolint:mnd
func tcpChecksum(ipHeader, tcpHeader, payload []byte) uint16 {
	var pseudoHeader []byte
	isIPv6 := len(ipHeader) >= 40 && (ipHeader[0]>>4) == 6
	if isIPv6 {
		pseudoHeader = make([]byte, 40)
		copy(pseudoHeader[0:16], ipHeader[8:24])             // Source Address
		copy(pseudoHeader[16:32], ipHeader[24:40])           // Destination Address
		totalLength := uint32(len(tcpHeader) + len(payload)) //nolint:gosec
		binary.BigEndian.PutUint32(pseudoHeader[32:], totalLength)
		pseudoHeader[39] = 6 // Next Header (TCP)
	} else {
		pseudoHeader = make([]byte, 12)
		copy(pseudoHeader[0:4], ipHeader[12:16])
		copy(pseudoHeader[4:8], ipHeader[16:20])
		pseudoHeader[9] = 6
		totalLength := uint16(len(tcpHeader) + len(payload)) //nolint:gosec
		binary.BigEndian.PutUint16(pseudoHeader[10:], totalLength)
	}

	sum := uint32(0)
	for _, slice := range [][]byte{pseudoHeader, tcpHeader, payload} {
		for i := 0; i < len(slice)-1; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(slice[i : i+2]))
		}
		if len(slice)%2 != 0 {
			sum += uint32(slice[len(slice)-1]) << 8
		}
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum) //nolint:gosec
}

const (
	finFlag byte = 0x01
	synFlag byte = 0x02
	rstFlag byte = 0x04
	pshFlag byte = 0x08
	ackFlag byte = 0x10
)

type packetType uint8

const (
	packetTypeSYN packetType = iota + 1
	packetTypeSYNACK
	packetTypeFIN
	packetTypeFINACK
	packetTypeRST
	packetTypeRSTACK
	packetTypePSHACK
	packetTypeACK
)

func (p packetType) String() string {
	switch p {
	case packetTypeSYN:
		return "SYN"
	case packetTypeSYNACK:
		return "SYN-ACK"
	case packetTypeFIN:
		return "FIN"
	case packetTypeFINACK:
		return "FIN-ACK"
	case packetTypeRST:
		return "RST"
	case packetTypeRSTACK:
		return "RST-ACK"
	case packetTypePSHACK:
		return "PSH-ACK"
	case packetTypeACK:
		return "ACK"
	default:
		panic("unknown packet type")
	}
}

type tcpHeader struct {
	typ        packetType
	srcPort    uint16
	dstPort    uint16
	seq        uint32
	ack        uint32
	dataOffset uint8
	flags      uint8
	windowSize uint16
	checksum   uint16
	urgentPtr  uint16
	options    options
}

// parseTCPHeader parses the TCP header from b.
// b should be the entire TCP packet bytes.
func parseTCPHeader(b []byte) (header tcpHeader, err error) {
	if len(b) < int(constants.BaseTCPHeaderLength) {
		return tcpHeader{}, fmt.Errorf("TCP header is too short: %d bytes", len(b))
	}

	header.srcPort = binary.BigEndian.Uint16(b[0:2])
	header.dstPort = binary.BigEndian.Uint16(b[2:4])
	header.seq = binary.BigEndian.Uint32(b[4:8])
	header.ack = binary.BigEndian.Uint32(b[8:12])
	// upper 4 bits of the 12th byte
	header.dataOffset = (b[12] >> 4) * 4 //nolint:mnd
	header.flags = b[13]
	header.windowSize = binary.BigEndian.Uint16(b[14:16])
	header.checksum = binary.BigEndian.Uint16(b[16:18])
	header.urgentPtr = binary.BigEndian.Uint16(b[18:20])

	switch {
	case uint32(header.dataOffset) < constants.BaseTCPHeaderLength:
		return tcpHeader{}, fmt.Errorf("TCP header data offset is invalid: "+
			"data offset is %d bytes, expected at least %d bytes", header.dataOffset, constants.BaseTCPHeaderLength)
	case int(header.dataOffset) > len(b):
		return tcpHeader{}, fmt.Errorf("TCP header data offset is invalid: "+
			"data offset is %d bytes, but packet is only %d bytes", header.dataOffset, len(b))
	}

	if uint32(header.dataOffset) > constants.BaseTCPHeaderLength {
		optionsBytes := b[constants.BaseTCPHeaderLength:header.dataOffset]
		header.options, err = parseTCPOptions(optionsBytes)
		if err != nil {
			return tcpHeader{}, fmt.Errorf("parsing TCP options: %w", err)
		}
	}

	flags := header.flags
	switch {
	case flags&synFlag != 0:
		if flags&ackFlag != 0 {
			header.typ = packetTypeSYNACK
		} else {
			header.typ = packetTypeSYN
		}
	case flags&rstFlag != 0:
		if flags&ackFlag != 0 {
			header.typ = packetTypeRSTACK
		} else {
			header.typ = packetTypeRST
		}
	case flags&finFlag != 0:
		if flags&ackFlag != 0 {
			header.typ = packetTypeFINACK
		} else {
			header.typ = packetTypeFIN
		}
	case flags&pshFlag != 0:
		header.typ = packetTypePSHACK
	case flags&ackFlag != 0:
		header.typ = packetTypeACK
	default:
		return tcpHeader{}, fmt.Errorf("TCP packet type is unknown: flags are 0x%02x", flags)
	}

	header.seq = binary.BigEndian.Uint32(b[4:8])
	header.ack = binary.BigEndian.Uint32(b[8:12])
	return header, nil
}

type options struct {
	mss           uint32
	windowScale   *uint8 // Pointer to differentiate between 0 and "not present"
	sackPermitted bool
	timestamps    *optionTimestamps
}

type optionTimestamps struct {
	value uint32
	echo  uint32
}

func parseTCPOptions(b []byte) (parsed options, err error) {
	i := 0
	for i < len(b) {
		optionType := b[i]

		// Handle single-byte options
		if optionType == 0 { // End of List
			break
		}
		if optionType == 1 { // No-Operation (Padding)
			i++
			continue
		}

		// Handle TLV (Type-Length-Value) options
		if i+1 >= len(b) {
			// This should not happen for DF packets.
			return options{}, fmt.Errorf("TCP option length is truncated: at offset %d", i)
		}

		length := int(b[i+1])
		const minLength = 2
		maxLength := len(b) - i
		switch {
		case length < minLength:
			return options{}, fmt.Errorf("TCP option length is invalid: "+
				"type %d at offset %d has length %d < %d", optionType, i, length, minLength)
		case length > maxLength:
			return options{}, fmt.Errorf("TCP option length is invalid: "+
				"type %d at offset %d has length %d > %d", optionType, i, length, maxLength)
		}

		data := b[i+2 : i+length]

		const (
			optionTypeMSS           = 2
			optionTypeWindowScale   = 3
			optionTypeSACKPermitted = 4
			optionTypeTimestamps    = 8
		)
		switch optionType {
		case optionTypeMSS:
			const expectedLength = 4
			if length != expectedLength {
				return options{}, fmt.Errorf("TCP option MSS value is invalid: "+
					"MSS option at offset %d has length %d, expected %d", i, length, expectedLength)
			}
			parsed.mss = uint32(binary.BigEndian.Uint16(data))
		case optionTypeWindowScale:
			const expectedLength = 3
			if length != expectedLength {
				return options{}, fmt.Errorf("TCP option Window Scale value is invalid: "+
					"window scale option at offset %d has length %d, expected %d", i, length, expectedLength)
			}
			windowScale := data[0]
			parsed.windowScale = &windowScale
		case optionTypeSACKPermitted:
			parsed.sackPermitted = true
		case optionTypeTimestamps:
			const expectedLength = 10
			if length != expectedLength {
				return options{}, fmt.Errorf("TCP option Timestamps value is invalid: "+
					"timestamps option at offset %d has length %d, expected %d", i, length, expectedLength)
			}
			parsed.timestamps = &optionTimestamps{
				value: binary.BigEndian.Uint32(data[:4]),
				echo:  binary.BigEndian.Uint32(data[4:]),
			}
		default:
			return options{}, fmt.Errorf("TCP option type is unknown: type %d", optionType)
		}

		i += length
	}

	return parsed, nil
}

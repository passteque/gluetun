package ip

import (
	"encoding/binary"
	"net/netip"

	"github.com/qdm12/gluetun/internal/pmtud/constants"
)

func HeaderLength(ipv4 bool) uint32 {
	if ipv4 {
		return constants.IPv4HeaderLength
	}
	return constants.IPv6HeaderLength
}

func HeaderV4(srcIP, dstIP netip.Addr, payloadLength uint32) []byte {
	ipHeader := make([]byte, constants.IPv4HeaderLength)
	const version byte = 4
	const headerLength byte = 20 / 4                                          // in 32-bit words
	ipHeader[0] = (version << 4) | headerLength                               //nolint:mnd
	ipHeader[1] = 0                                                           // type of Service
	putUint16(ipHeader[2:], uint16(constants.IPv4HeaderLength+payloadLength)) //nolint:gosec
	ipHeader[4], ipHeader[5] = 0, 0                                           // identification
	const flagsAndOffset uint16 = 0x4000                                      // DF bit set
	putUint16(ipHeader[6:], flagsAndOffset)
	ipHeader[8] = 64 // ttl
	ipHeader[9] = constants.IPPROTO_TCP
	srcIPBytes := srcIP.As4()
	copy(ipHeader[12:16], srcIPBytes[:])
	dstIPBytes := dstIP.As4()
	copy(ipHeader[16:20], dstIPBytes[:])

	checksum := ipChecksum(ipHeader)
	ipHeader[10] = byte(checksum >> 8)   //nolint:mnd
	ipHeader[11] = byte(checksum & 0xff) //nolint:mnd

	return ipHeader
}

// ipChecksum calculates the checksum for the IP header.
//
//nolint:mnd
func ipChecksum(header []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < len(header)-1; i += 2 {
		sum += uint32(header[i])<<8 + uint32(header[i+1])
	}
	if len(header)%2 != 0 {
		sum += uint32(header[len(header)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// HeaderV6 makes an IPv6 header.
// payloadLen is the length of the payload following the header.
// nextHeader can be byte([constants.IPPROTO_TCP]) for example.
func HeaderV6(srcIP, dstIP netip.Addr,
	payloadLen uint16, nextHeader byte,
) []byte {
	ipv6Header := make([]byte, constants.IPv6HeaderLength)
	ipv6Header[0] = 0x60 // version (4 bits) | traffic Class (4 bits)
	ipv6Header[1] = 0x00 // traffic Class (4 bits) | flow label (4 bits)

	// Flow Label (remaining 16 bits)
	ipv6Header[2] = 0x00
	ipv6Header[3] = 0x00

	binary.BigEndian.PutUint16(ipv6Header[4:], payloadLen)
	ipv6Header[6] = nextHeader
	const hopLimit = 64
	ipv6Header[7] = hopLimit
	copy(ipv6Header[8:24], srcIP.AsSlice())
	copy(ipv6Header[24:40], dstIP.AsSlice())
	return ipv6Header
}

//go:build linux

package nftables

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/google/nftables/expr"
)

const (
	protocolNumberIPv4 = 2
	protocolNumberIPv6 = 10
)

const (
	protocolTCP = 6
	protocolUDP = 17
)

// Offsets and length of the source and destination port fields within the
// TCP/UDP transport header, in bytes.
const (
	srcPortOffset = 0
	dstPortOffset = 2
	portLen       = 2
)

// parseProtocol converts a protocol name to its IANA protocol number.
func parseProtocol(protocol string) (uint8, error) {
	switch protocol {
	case "tcp", "tcp-client":
		return protocolTCP, nil
	case "udp":
		return protocolUDP, nil
	default:
		return 0, fmt.Errorf("unsupported protocol: %s", protocol)
	}
}

// nfprotoGuardExprs returns expressions matching the family of the packet, as
// the nft CLI does when matching ip or ipv6 fields in an inet family chain.
func nfprotoGuardExprs(isIPv4 bool) []expr.Any {
	protocolNumber := uint8(protocolNumberIPv6)
	if isIPv4 {
		protocolNumber = protocolNumberIPv4
	}
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protocolNumber}},
	}
}

// protocolExprs returns expressions matching the L4 protocol number, as the
// nft CLI does when matching a tcp or udp keyword in an inet family chain.
func protocolExprs(protocol uint8) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protocol}},
	}
}

// sourceIPExprs returns expressions matching the source IP address of a
// packet, guarded by the address family.
func sourceIPExprs(addr netip.Addr) []expr.Any {
	const ipv4Offset, ipv6Offset = 12, 8
	const ipv4Len, ipv6Len = 4, 16
	offset, length := uint32(ipv6Offset), uint32(ipv6Len)
	if addr.Is4() {
		offset, length = uint32(ipv4Offset), uint32(ipv4Len)
	}
	return append(nfprotoGuardExprs(addr.Is4()),
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: length},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addr.AsSlice()},
	)
}

// destinationIPExprs returns expressions matching the destination IP address
// of a packet, guarded by the address family.
func destinationIPExprs(addr netip.Addr) []expr.Any {
	const ipv4Offset, ipv6Offset = 16, 24
	const ipv4Len, ipv6Len = 4, 16
	offset, length := uint32(ipv6Offset), uint32(ipv6Len)
	if addr.Is4() {
		offset, length = uint32(ipv4Offset), uint32(ipv4Len)
	}
	return append(nfprotoGuardExprs(addr.Is4()),
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: length},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addr.AsSlice()},
	)
}

// destinationSubnetExprs returns expressions matching the destination IP
// address within the given subnet, guarded by the address family.
func destinationSubnetExprs(subnet netip.Prefix) []expr.Any {
	const ipv4Offset, ipv6Offset = 16, 24
	const ipv4Len, ipv6Len = 4, 16
	offset, length := ipv6Offset, ipv6Len
	if subnet.Addr().Is4() {
		offset, length = ipv4Offset, ipv4Len
	}
	mask := cidrMask(subnet.Bits(), length)
	networkAddr := subnet.Masked().Addr().AsSlice()
	return append(nfprotoGuardExprs(subnet.Addr().Is4()),
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: uint32(offset), Len: uint32(length)},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            uint32(length),
			Mask:           mask,
			Xor:            make([]byte, length),
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: networkAddr},
	)
}

// sourcePortExprs returns expressions matching the source port of a TCP or
// UDP packet.
func sourcePortExprs(port uint16) []expr.Any {
	portData := make([]byte, portLen)
	binary.BigEndian.PutUint16(portData, port)
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: srcPortOffset, Len: portLen},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: portData},
	}
}

// destinationPortExprs returns expressions matching the destination port of a
// TCP or UDP packet.
func destinationPortExprs(port uint16) []expr.Any {
	portData := make([]byte, portLen)
	binary.BigEndian.PutUint16(portData, port)
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: dstPortOffset, Len: portLen},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: portData},
	}
}

// cidrMask returns the binary mask for a CIDR prefix length.
func cidrMask(bits, addrLen int) []byte {
	const bitsPerByte = 8
	const fullByte = 0xff

	result := make([]byte, addrLen)
	fullBytes := bits / bitsPerByte
	remainingBits := bits % bitsPerByte
	for i := range fullBytes {
		result[i] = fullByte
	}
	if remainingBits > 0 {
		result[fullBytes] = byte((fullByte << (bitsPerByte - remainingBits)) & fullByte)
	}
	return result
}

// inputInterfaceExprs returns expressions matching packets entering the given
// interface, or nil if the interface is empty or "*", in which case all
// interfaces are matched.
func inputInterfaceExprs(intf string) []expr.Any {
	if intf == "" || intf == "*" {
		return nil
	}
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(intf + "\x00")},
	}
}

// outputInterfaceExprs returns expressions matching packets leaving the given
// interface, or nil if the interface is empty or "*", in which case all
// interfaces are matched.
func outputInterfaceExprs(intf string) []expr.Any {
	if intf == "" || intf == "*" {
		return nil
	}
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(intf + "\x00")},
	}
}

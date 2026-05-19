package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
)

// See https://datatracker.ietf.org/doc/html/rfc1928#section-6
func (c *socksConn) encodeFailedResponse(writer io.Writer, socksVersion byte, reply replyCode) { //nolint:unparam
	_, err := writer.Write([]byte{
		socksVersion,
		byte(reply),
		0, // RSV byte
		// The RFC requires a full response frame even for failures.
		// Use IPv4 address type with zeroed address and port.
		byte(ipv4), // ATYP
		0, 0, 0, 0, // BND.ADDR (zeroed)
		0, 0, // BND.PORT (zeroed)
	})
	if err != nil {
		c.logger.Warnf("failed writing failed response: %s", err)
	}
}

// See https://datatracker.ietf.org/doc/html/rfc1928#section-6
func (c *socksConn) encodeSuccessResponse(writer io.Writer, socksVersion byte,
	reply replyCode, bindAddrType addrType, bindAddress string,
	bindPort uint16,
) (err error) {
	bindData, err := encodeBindData(bindAddrType, bindAddress, bindPort)
	if err != nil {
		return fmt.Errorf("encoding bind data: %w", err)
	}

	const initialPacketLength = 3
	capacity := initialPacketLength + len(bindData)
	packet := make([]byte, initialPacketLength, capacity)
	packet[0] = socksVersion
	packet[1] = byte(reply)
	packet[2] = 0 // RSV byte
	packet = append(packet, bindData...)

	_, err = writer.Write(packet)
	if err != nil {
		return fmt.Errorf("writing packet: %w", err)
	}
	return nil
}

var (
	ErrIPVersionUnexpected = errors.New("ip version is unexpected")
	ErrDomainNameTooLong   = errors.New("domain name is too long")
)

func encodeBindData(addrType addrType, address string, port uint16) (
	data []byte, err error,
) {
	capacity := bindDataLength(addrType, address)
	data = make([]byte, 0, capacity)

	data = append(data, byte(addrType))
	switch addrType {
	case ipv4, ipv6:
		ip, err := netip.ParseAddr(address)
		if err != nil {
			return nil, fmt.Errorf("parsing IP address: %w", err)
		}

		switch {
		case addrType == ipv4 && !ip.Is4():
			return nil, fmt.Errorf("%w: expected IPv4 for %s", ErrIPVersionUnexpected, ip)
		case addrType == ipv6 && !ip.Is6():
			return nil, fmt.Errorf("%w: expected IPv6 for %s", ErrIPVersionUnexpected, ip)
		}
		data = append(data, ip.AsSlice()...)
	case domainName:
		const maxDomainNameLength = 255
		if len(address) > maxDomainNameLength {
			return nil, fmt.Errorf("%w: %s", ErrDomainNameTooLong, address)
		}
		data = append(data, byte(len(address)))
		data = append(data, []byte(address)...)
	default:
		panic(fmt.Sprintf("unsupported address type %d", addrType))
	}
	data = binary.BigEndian.AppendUint16(data, port)
	return data, nil
}

func bindDataLength(addrType addrType, address string) (maxLength uint) {
	maxLength++ // address type
	switch addrType {
	case ipv4:
		maxLength += net.IPv4len
	case domainName:
		maxLength++ // domain name length
		maxLength += uint(len([]byte(address)))
	case ipv6:
		maxLength += net.IPv6len
	default:
		panic("unsupported address type: " + fmt.Sprint(addrType))
	}
	maxLength += 2 // port
	return maxLength
}

//go:build unix

package restrictednet

import (
	"fmt"
	"net/netip"

	"golang.org/x/sys/unix"
)

func closeFD(fd int) {
	unix.Close(fd)
}

func newTCPSockStream(family int) (fd int, err error) {
	return unix.Socket(family, unix.SOCK_STREAM, unix.IPPROTO_TCP)
}

func bindFD(fd int, address netip.AddrPort) error {
	bindAddr := makeSockAddr(address)
	return unix.Bind(fd, bindAddr)
}

func connectFD(fd int, destination netip.AddrPort) error {
	return unix.Connect(fd, makeSockAddr(destination))
}

func fdToSourceAddr(fd int) (sourceAddrPort netip.AddrPort, err error) {
	sockAddr, err := unix.Getsockname(fd)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("getting sockname: %w", err)
	}

	sourceAddrPort, err = sockAddrToAddrPort(sockAddr)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return sourceAddrPort, nil
}

func makeSockAddr(addressPort netip.AddrPort) unix.Sockaddr {
	if addressPort.Addr().Is4() {
		return &unix.SockaddrInet4{
			Port: int(addressPort.Port()),
			Addr: addressPort.Addr().As4(),
		}
	}
	return &unix.SockaddrInet6{
		Port: int(addressPort.Port()),
		Addr: addressPort.Addr().As16(),
	}
}

func sockAddrToAddrPort(sockAddr unix.Sockaddr) (addrPort netip.AddrPort, err error) {
	switch typedSockAddr := sockAddr.(type) {
	case *unix.SockaddrInet4:
		return netip.AddrPortFrom(netip.AddrFrom4(typedSockAddr.Addr), uint16(typedSockAddr.Port)), nil //nolint:gosec
	case *unix.SockaddrInet6:
		return netip.AddrPortFrom(netip.AddrFrom16(typedSockAddr.Addr), uint16(typedSockAddr.Port)), nil //nolint:gosec
	default:
		return netip.AddrPort{}, fmt.Errorf("unexpected socket address type %T", typedSockAddr)
	}
}

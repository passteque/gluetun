//go:build windows

package restrictednet

import (
	"context"
	"net/netip"
)

func closeFD(fd int) {
	panic("not implemented")
}

func newTCPSockStream(family int) (fd int, err error) {
	panic("not implemented")
}

func bindFD(fd int, address netip.AddrPort) error {
	panic("not implemented")
}

func connectFD(ctx context.Context, fd int, destination netip.AddrPort) error {
	panic("not implemented")
}

func fdToSourceAddr(fd int) (sourceAddrPort netip.AddrPort, err error) {
	panic("not implemented")
}

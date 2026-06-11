//go:build !windows

package restrictednet

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"golang.org/x/sys/unix"
)

func closeFD(fd int) {
	unix.Close(fd)
}

func newTCPSockStream(family int) (fd int, err error) {
	fd, err = unix.Socket(family, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	if err != nil {
		return 0, err
	}
	err = unix.SetNonblock(fd, true)
	if err != nil {
		_ = unix.Close(fd)
		return 0, err
	}
	return fd, nil
}

func bindFD(fd int, address netip.AddrPort) error {
	bindAddr := makeSockAddr(address)
	return unix.Bind(fd, bindAddr)
}

func connectFD(ctx context.Context, fd int, destination netip.AddrPort) error {
	err := unix.Connect(fd, makeSockAddr(destination))
	switch {
	case err == nil:
		return nil
	case !errors.Is(err, unix.EINPROGRESS):
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			bitsIndex := fd / 64 //nolint:mnd
			if bitsIndex >= len(unix.FdSet{}.Bits) {
				return fmt.Errorf("fd %d exceeds unix.Select FdSet capacity", fd)
			}
			wset := &unix.FdSet{}
			wset.Bits[bitsIndex] |= 1 << (uint64(fd) % 64) //nolint:gosec,mnd
			eset := &unix.FdSet{}
			eset.Bits[bitsIndex] |= 1 << (uint64(fd) % 64) //nolint:gosec,mnd
			const selectTimeout = 50 * time.Millisecond
			timeval := unix.NsecToTimeval(int64(selectTimeout))

			// Wait for the FD to become writable or hit an error state
			n, err := unix.Select(fd+1, nil, wset, eset, &timeval)
			if err != nil {
				if errors.Is(err, unix.EINTR) {
					continue // Syscall interrupted, try again
				}
				return fmt.Errorf("select error: %w", err)
			} else if n == 0 {
				continue // no status change yet
			}

			// Check if the socket encountered an error
			n, err = unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
			if err != nil {
				return fmt.Errorf("getsockopt error: %w", err)
			} else if n != 0 {
				return fmt.Errorf("connect failed asynchronously: %w", unix.Errno(n))
			}

			return nil
		}
	}
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

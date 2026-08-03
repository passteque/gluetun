package wireguard

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

// createTUN creates a TUN device. When disableGSO is true, IFF_VNET_HDR is
// omitted so wireguard-go's initFromFlags sees no vnet header support and
// keeps tun.vnetHdr=false, falling back to simple single-packet writes instead
// of the GRO/GSO batch path that causes EINVAL on some vendor kernels.
func createTUN(name string, mtu int, disableGSO bool) (tun.Device, error) { //nolint:ireturn
	if !disableGSO {
		return tun.CreateTUN(name, mtu)
	}
	tunFile, err := OpenTUNFile(name)
	if err != nil {
		return nil, err
	}
	return tun.CreateTUNFromFile(tunFile, mtu)
}

// OpenTUNFile opens /dev/net/tun with IFF_TUN|IFF_NO_PI but without
// IFF_VNET_HDR. It is exported so that the amneziawg package can use the same
// file with amneziatun.CreateTUNFromFile.
func OpenTUNFile(name string) (*os.File, error) {
	tunFD, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("opening /dev/net/tun: %w", err)
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(tunFD)
		return nil, fmt.Errorf("creating ifreq: %w", err)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI) // intentionally omit IFF_VNET_HDR
	if err := unix.IoctlIfreq(tunFD, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(tunFD)
		return nil, fmt.Errorf("setting TUN flags: %w", err)
	}
	if err := unix.SetNonblock(tunFD, true); err != nil {
		unix.Close(tunFD)
		return nil, fmt.Errorf("setting nonblock: %w", err)
	}
	return os.NewFile(uintptr(tunFD), "/dev/net/tun"), nil
}

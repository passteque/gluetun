package amneziawg

import (
	"fmt"

	amneziatun "github.com/amnezia-vpn/amneziawg-go/tun"
	"github.com/qdm12/gluetun/internal/wireguard"
)

// createTUN creates a TUN device. When gso is false, IFF_VNET_HDR is
// omitted so amneziawg-go's initFromFlags sees no vnet header support and
// keeps tun.vnetHdr=false, falling back to simple single-packet writes instead
// of the GRO/GSO batch path that causes EINVAL on some vendor kernels.
func createTUN(name string, mtu int, gso bool) (amneziatun.Device, error) { //nolint:ireturn
	if gso {
		return amneziatun.CreateTUN(name, mtu)
	}
	tunFile, err := wireguard.OpenTUNFile(name)
	if err != nil {
		return nil, fmt.Errorf("creating tun fd file: %w", err)
	}
	tunDevice, err := amneziatun.CreateTUNFromFile(tunFile, mtu)
	if err != nil {
		return nil, fmt.Errorf("creating TUN device from file: %w", err)
	}
	return tunDevice, nil
}

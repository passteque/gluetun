package wireguard

import (
	"fmt"
	"net/netip"
)

func AddAddresses(linkIndex uint32,
	addresses []netip.Prefix, ipv6 bool,
	netlink NetLinker,
) (err error) {
	for _, address := range addresses {
		if !ipv6 && address.Addr().Is6() {
			continue
		}

		err = netlink.AddrReplace(linkIndex, address)
		if err != nil {
			return fmt.Errorf("%w: when adding address %s to link with index %d",
				err, address, linkIndex)
		}
	}

	return nil
}

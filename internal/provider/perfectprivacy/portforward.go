package perfectprivacy

import (
	"context"
	"net/netip"

	"github.com/qdm12/gluetun/internal/provider/utils"
)

// PortForward calculates and returns the VPN server side ports forwarded.
func (p *Provider) PortForward(_ context.Context,
	objects utils.PortForwardObjects,
) (internalToExternalPorts map[uint16]uint16, err error) {
	if !objects.InternalIP.IsValid() {
		panic("internal ip is not set")
	}

	ports := internalIPToPorts(objects.InternalIP)
	internalToExternalPorts = make(map[uint16]uint16, len(ports))
	for _, port := range ports {
		internalToExternalPorts[port] = port
	}
	return internalToExternalPorts, nil
}

func (p *Provider) KeepPortForward(ctx context.Context,
	_ utils.PortForwardObjects,
) (err error) {
	<-ctx.Done()
	return ctx.Err()
}

// See https://www.perfect-privacy.com/en/faq section
// How are the default forwarding ports being calculated?
func internalIPToPorts(internalIP netip.Addr) (ports []uint16) {
	internalIPBytes := internalIP.AsSlice()
	// Convert the internal IP address to a bit string
	// and keep only the last 12 bits
	last16Bits := internalIPBytes[len(internalIPBytes)-2:]
	last12Bits := []byte{
		last16Bits[0] & 0b00001111, // only keep 4 bits
		last16Bits[1],
	}
	basePort := uint16(last12Bits[0])<<8 + uint16(last12Bits[1]) //nolint:mnd
	return []uint16{
		10000 + basePort,
		20000 + basePort,
		30000 + basePort,
	}
}

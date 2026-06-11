package settings

import (
	"fmt"
	"net/netip"

	"github.com/qdm12/gosettings"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gotree"
)

// PMTUD contains settings to configure Path MTU Discovery.
type PMTUD struct {
	// ICMPAddresses is the redundancy list of addresses to use
	// for ICMP path MTU discovery. Each address MUST handle ICMP
	// packets for PMTUD to work.
	// It cannot be nil in the internal state.
	ICMPAddresses []netip.Addr `json:"icmp_addresses"`
	// TCPAddresses is the redundancy list of addresses to use
	// for TCP path MTU discovery. Each address MUST have a listening
	// TCP server on the port specified.
	// It cannot be nil in the internal state.
	TCPAddresses []netip.AddrPort `json:"tcp_addresses"`
}

// Validate validates PMTUD settings.
func (p PMTUD) validate() (err error) {
	for i, addr := range p.ICMPAddresses {
		if !addr.IsValid() {
			return fmt.Errorf("PMTUD ICMP address is not valid: at index %d", i)
		}
	}
	for i, addr := range p.TCPAddresses {
		if !addr.IsValid() {
			return fmt.Errorf("PMTUD TCP address is not valid: at index %d", i)
		}
	}
	return nil
}

func (p *PMTUD) copy() (copied PMTUD) {
	return PMTUD{
		ICMPAddresses: gosettings.CopySlice(p.ICMPAddresses),
		TCPAddresses:  gosettings.CopySlice(p.TCPAddresses),
	}
}

func (p *PMTUD) overrideWith(other PMTUD) {
	p.ICMPAddresses = gosettings.OverrideWithSlice(p.ICMPAddresses, other.ICMPAddresses)
	p.TCPAddresses = gosettings.OverrideWithSlice(p.TCPAddresses, other.TCPAddresses)
}

func (p *PMTUD) setDefaults() {
	defaultICMPAddresses := []netip.Addr{
		netip.AddrFrom4([4]byte{1, 1, 1, 1}),
		netip.AddrFrom4([4]byte{8, 8, 8, 8}),
	}
	p.ICMPAddresses = gosettings.DefaultSlice(p.ICMPAddresses, defaultICMPAddresses)

	const dnsPort, tlsPort = 53, 443
	defaultTCPAddresses := []netip.AddrPort{
		netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), dnsPort),
		netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, 8, 8}), dnsPort),
		netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), tlsPort),
		netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, 8, 8}), tlsPort),
		netip.AddrPortFrom(netip.MustParseAddr("2606:4700:4700::1111"), dnsPort),
		netip.AddrPortFrom(netip.MustParseAddr("2001:4860:4860::8888"), dnsPort),
		netip.AddrPortFrom(netip.MustParseAddr("2606:4700:4700::1111"), tlsPort),
		netip.AddrPortFrom(netip.MustParseAddr("2001:4860:4860::8888"), tlsPort),
	}
	p.TCPAddresses = gosettings.DefaultSlice(p.TCPAddresses, defaultTCPAddresses)
}

func (p PMTUD) String() string {
	return p.toLinesNode().String()
}

func (p PMTUD) toLinesNode() (node *gotree.Node) {
	node = gotree.New("Path MTU discovery:")

	icmpAddrNode := node.Append("ICMP addresses:")
	for _, addr := range p.ICMPAddresses {
		icmpAddrNode.Append(addr.String())
	}

	tcpAddrNode := node.Append("TCP addresses:")
	for _, addr := range p.TCPAddresses {
		tcpAddrNode.Append(addr.String())
	}
	return node
}

func (p *PMTUD) read(r *reader.Reader) (err error) {
	p.ICMPAddresses, err = r.CSVNetipAddresses("PMTUD_ICMP_ADDRESSES")
	if err != nil {
		return err
	}

	p.TCPAddresses, err = r.CSVNetipAddrPorts("PMTUD_TCP_ADDRESSES")
	if err != nil {
		return err
	}

	return nil
}

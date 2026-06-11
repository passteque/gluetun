package settings

import (
	"net/netip"

	"github.com/qdm12/gosettings"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gotree"
)

// IPv6 contains settings regarding IPv6 configuration.
type IPv6 struct {
	// CheckAddresses are the TCP ip:port addresses to dial to check if
	// IPv6 is supported, in case a default IPv6 route is found.
	// It defaults to google and cloudflare IPv6 anycast addresses
	// [2001:4860:4860::8888]:53,[2606:4700:4700::1111]:53
	CheckAddresses []netip.AddrPort
}

func (i IPv6) validate() (err error) {
	return nil
}

func (i *IPv6) copy() (copied IPv6) {
	return IPv6{
		CheckAddresses: gosettings.CopySlice(i.CheckAddresses),
	}
}

func (i *IPv6) overrideWith(other IPv6) {
	i.CheckAddresses = gosettings.OverrideWithSlice(i.CheckAddresses, other.CheckAddresses)
}

func (i *IPv6) setDefaults() {
	defaultCheckAddresses := []netip.AddrPort{
		netip.MustParseAddrPort("[2001:4860:4860::8888]:53"),
		netip.MustParseAddrPort("[2606:4700:4700::1111]:53"),
	}
	i.CheckAddresses = gosettings.DefaultSlice(i.CheckAddresses, defaultCheckAddresses)
}

func (i IPv6) String() string {
	return i.toLinesNode().String()
}

func (i IPv6) toLinesNode() (node *gotree.Node) {
	node = gotree.New("IPv6 settings:")
	addrsNode := node.Appendf("Check addresses:")
	for _, addr := range i.CheckAddresses {
		addrsNode.Append(addr.String())
	}
	return node
}

func (i *IPv6) read(r *reader.Reader) (err error) {
	i.CheckAddresses, err = r.CSVNetipAddrPorts("IPV6_CHECK_ADDRESSES")
	return err
}

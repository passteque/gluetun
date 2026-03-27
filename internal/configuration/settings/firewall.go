package settings

import (
	"fmt"
	"net/netip"

	"github.com/qdm12/gosettings"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gotree"
)

// Firewall contains settings to customize the firewall operation.
type Firewall struct {
	VPNInputPorts   []uint16
	InputPorts      []uint16
	OutboundSubnets []netip.Prefix
	Enabled         *bool
	Iptables        Iptables
}

func (f Firewall) validate() (err error) {
	if hasZeroPort(f.VPNInputPorts) {
		return fmt.Errorf("VPN input ports: %w", ErrFirewallZeroPort)
	}

	if hasZeroPort(f.InputPorts) {
		return fmt.Errorf("input ports: %w", ErrFirewallZeroPort)
	}

	for _, subnet := range f.OutboundSubnets {
		if subnet.Addr().IsUnspecified() {
			return fmt.Errorf("%w: %s", ErrFirewallPublicOutboundSubnet, subnet)
		}
	}

	err = f.Iptables.validate()
	if err != nil {
		return fmt.Errorf("iptables settings: %w", err)
	}

	return nil
}

func hasZeroPort(ports []uint16) (has bool) {
	for _, port := range ports {
		if port == 0 {
			return true
		}
	}
	return false
}

func (f *Firewall) copy() (copied Firewall) {
	return Firewall{
		VPNInputPorts:   gosettings.CopySlice(f.VPNInputPorts),
		InputPorts:      gosettings.CopySlice(f.InputPorts),
		OutboundSubnets: gosettings.CopySlice(f.OutboundSubnets),
		Enabled:         gosettings.CopyPointer(f.Enabled),
		Iptables:        f.Iptables.copy(),
	}
}

// overrideWith overrides fields of the receiver
// settings object with any field set in the other
// settings.
func (f *Firewall) overrideWith(other Firewall) {
	f.VPNInputPorts = gosettings.OverrideWithSlice(f.VPNInputPorts, other.VPNInputPorts)
	f.InputPorts = gosettings.OverrideWithSlice(f.InputPorts, other.InputPorts)
	f.OutboundSubnets = gosettings.OverrideWithSlice(f.OutboundSubnets, other.OutboundSubnets)
	f.Enabled = gosettings.OverrideWithPointer(f.Enabled, other.Enabled)
	f.Iptables.overrideWith(other.Iptables)
}

func (f *Firewall) setDefaults(globalLogLevel string) {
	f.Enabled = gosettings.DefaultPointer(f.Enabled, true)
	f.Iptables.setDefaults(globalLogLevel)
}

func (f Firewall) String() string {
	return f.toLinesNode().String()
}

func (f Firewall) toLinesNode() (node *gotree.Node) {
	node = gotree.New("Firewall settings:")

	node.Appendf("Enabled: %s", gosettings.BoolToYesNo(f.Enabled))
	if !*f.Enabled {
		return node
	}

	node.AppendNode(f.Iptables.toLinesNode())

	if len(f.VPNInputPorts) > 0 {
		vpnInputPortsNode := node.Appendf("VPN input ports:")
		for _, port := range f.VPNInputPorts {
			vpnInputPortsNode.Appendf("%d", port)
		}
	}

	if len(f.InputPorts) > 0 {
		inputPortsNode := node.Appendf("Input ports:")
		for _, port := range f.InputPorts {
			inputPortsNode.Appendf("%d", port)
		}
	}

	if len(f.OutboundSubnets) > 0 {
		outboundSubnets := node.Appendf("Outbound subnets:")
		for _, subnet := range f.OutboundSubnets {
			outboundSubnets.Appendf("%s", &subnet)
		}
	}

	return node
}

func (f *Firewall) read(r *reader.Reader) (err error) {
	f.VPNInputPorts, err = r.CSVUint16("FIREWALL_VPN_INPUT_PORTS")
	if err != nil {
		return err
	}

	f.InputPorts, err = r.CSVUint16("FIREWALL_INPUT_PORTS")
	if err != nil {
		return err
	}

	f.OutboundSubnets, err = r.CSVNetipPrefixes(
		"FIREWALL_OUTBOUND_SUBNETS", reader.RetroKeys("EXTRA_SUBNETS"))
	if err != nil {
		return err
	}

	f.Enabled, err = r.BoolPtr("FIREWALL_ENABLED_DISABLING_IT_SHOOTS_YOU_IN_YOUR_FOOT")
	if err != nil {
		return err
	}

	err = f.Iptables.read(r)
	if err != nil {
		return fmt.Errorf("reading iptables settings: %w", err)
	}

	return nil
}

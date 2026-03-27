package settings

import (
	"fmt"

	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gosettings"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gosettings/validate"
	"github.com/qdm12/gotree"
)

type VPN struct {
	// Type is the VPN type and can only be
	// 'openvpn' or 'wireguard'. It cannot be the
	// empty string in the internal state.
	Type      string    `json:"type"`
	Provider  Provider  `json:"provider"`
	AmneziaWg AmneziaWg `json:"amneziawg"`
	OpenVPN   OpenVPN   `json:"openvpn"`
	Wireguard Wireguard `json:"wireguard"`
	PMTUD     PMTUD     `json:"pmtud"`
	// UpCommand is the command to use when the VPN connection is up.
	// It can be the empty string to indicate not to run a command.
	// It cannot be nil in the internal state.
	UpCommand *string `json:"up_command"`
	// DownCommand is the command to use after the VPN connection goes down.
	// It can be the empty string to indicate to NOT run a command.
	// It cannot be nil in the internal state.
	DownCommand *string `json:"down_command"`
}

// Validate validates VPN settings, using the filter choices getter (aka servers data storage),
// and if IPv6 is supported or not.
// TODO v4 remove pointer for receiver (because of Surfshark).
func (v *VPN) Validate(filterChoicesGetter FilterChoicesGetter, ipv6Supported bool, warner Warner) (err error) {
	// Validate Type
	validVPNTypes := []string{vpn.AmneziaWg, vpn.OpenVPN, vpn.Wireguard}
	if err = validate.IsOneOf(v.Type, validVPNTypes...); err != nil {
		return fmt.Errorf("%w: %w", ErrVPNTypeNotValid, err)
	}

	err = v.Provider.validate(v.Type, filterChoicesGetter, warner)
	if err != nil {
		return fmt.Errorf("provider settings: %w", err)
	}

	switch v.Type {
	case vpn.AmneziaWg:
		err = v.AmneziaWg.validate(v.Provider.Name, ipv6Supported)
		if err != nil {
			return fmt.Errorf("AmneziaWG settings: %w", err)
		}
	case vpn.OpenVPN:
		err := v.OpenVPN.validate(v.Provider.Name)
		if err != nil {
			return fmt.Errorf("OpenVPN settings: %w", err)
		}
	case vpn.Wireguard:
		const amneziawg = false
		err := v.Wireguard.validate(v.Provider.Name, ipv6Supported, amneziawg)
		if err != nil {
			return fmt.Errorf("Wireguard settings: %w", err)
		}
	}

	err = v.PMTUD.validate()
	if err != nil {
		return fmt.Errorf("PMTUD settings: %w", err)
	}

	return nil
}

func (v *VPN) Copy() (copied VPN) {
	return VPN{
		Type:        v.Type,
		Provider:    v.Provider.copy(),
		AmneziaWg:   v.AmneziaWg.copy(),
		OpenVPN:     v.OpenVPN.copy(),
		Wireguard:   v.Wireguard.copy(),
		PMTUD:       v.PMTUD.copy(),
		UpCommand:   gosettings.CopyPointer(v.UpCommand),
		DownCommand: gosettings.CopyPointer(v.DownCommand),
	}
}

func (v *VPN) OverrideWith(other VPN) {
	v.Type = gosettings.OverrideWithComparable(v.Type, other.Type)
	v.Provider.overrideWith(other.Provider)
	v.AmneziaWg.overrideWith(other.AmneziaWg)
	v.OpenVPN.overrideWith(other.OpenVPN)
	v.Wireguard.overrideWith(other.Wireguard)
	v.PMTUD.overrideWith(other.PMTUD)
	v.UpCommand = gosettings.OverrideWithPointer(v.UpCommand, other.UpCommand)
	v.DownCommand = gosettings.OverrideWithPointer(v.DownCommand, other.DownCommand)
}

func (v *VPN) setDefaults() {
	v.Type = gosettings.DefaultComparable(v.Type, vpn.OpenVPN)
	v.Provider.setDefaults()
	v.AmneziaWg.setDefaults(v.Provider.Name)
	v.OpenVPN.setDefaults(v.Provider.Name)
	v.Wireguard.setDefaults(v.Provider.Name)
	v.PMTUD.setDefaults()
	v.UpCommand = gosettings.DefaultPointer(v.UpCommand, "")
	v.DownCommand = gosettings.DefaultPointer(v.DownCommand, "")
}

func (v VPN) String() string {
	return v.toLinesNode().String()
}

func (v VPN) toLinesNode() (node *gotree.Node) {
	node = gotree.New("VPN settings:")

	node.AppendNode(v.Provider.toLinesNode())

	switch v.Type {
	case vpn.AmneziaWg:
		node.AppendNode(v.AmneziaWg.toLinesNode())
	case vpn.OpenVPN:
		node.AppendNode(v.OpenVPN.toLinesNode())
	case vpn.Wireguard:
		node.AppendNode(v.Wireguard.toLinesNode())
	}
	node.AppendNode(v.PMTUD.toLinesNode())

	if *v.UpCommand != "" {
		node.Appendf("Up command: %s", *v.UpCommand)
	}
	if *v.DownCommand != "" {
		node.Appendf("Down command: %s", *v.DownCommand)
	}

	return node
}

func (v *VPN) read(r *reader.Reader) (err error) {
	v.Type = r.String("VPN_TYPE")

	err = v.Provider.read(r, v.Type)
	if err != nil {
		return fmt.Errorf("VPN provider: %w", err)
	}

	err = v.AmneziaWg.read(r)
	if err != nil {
		return fmt.Errorf("AmneziaWG: %w", err)
	}

	err = v.OpenVPN.read(r)
	if err != nil {
		return fmt.Errorf("OpenVPN: %w", err)
	}

	const amneziawg = false
	err = v.Wireguard.read(r, amneziawg)
	if err != nil {
		return fmt.Errorf("wireguard: %w", err)
	}

	err = v.PMTUD.read(r)
	if err != nil {
		return fmt.Errorf("PMTUD: %w", err)
	}

	v.UpCommand = r.Get("VPN_UP_COMMAND", reader.ForceLowercase(false))

	v.DownCommand = r.Get("VPN_DOWN_COMMAND", reader.ForceLowercase(false))

	return nil
}

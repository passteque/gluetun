package settings

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gosettings"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gosettings/validate"
	"github.com/qdm12/gotree"
)

// Provider contains settings specific to a VPN provider.
type Provider struct {
	// Name is the VPN service provider name.
	// It cannot be the empty string in the internal state.
	Name string `json:"name"`
	// ServerSelection is the settings to
	// select the VPN server.
	ServerSelection ServerSelection `json:"server_selection"`
	// PortForwarding is the settings about port forwarding.
	PortForwarding PortForwarding `json:"port_forwarding"`
	// AzirevpnToken is the API token used by AzireVPN.
	AzirevpnToken string `json:"azirevpn_token"`
}

// TODO v4 remove pointer for receiver (because of Surfshark).
func (p *Provider) validate(vpnType string, filterChoicesGetter FilterChoicesGetter, warner Warner) (err error) {
	// Validate Name
	var validNames []string
	switch vpnType {
	case vpn.AmneziaWg:
		validNames = []string{providers.Custom}
	case vpn.OpenVPN:
		validNames = providers.AllWithCustom()
		validNames = append(validNames, "pia") // Retro-compatibility
		// Remove Mullvad since it no longer supports OpenVPN as of January 15th, 2026
		mullvadIndex := slices.Index(validNames, providers.Mullvad)
		validNames[mullvadIndex], validNames[len(validNames)-1] = validNames[len(validNames)-1], validNames[mullvadIndex]
		validNames = validNames[:len(validNames)-1]
		// Remove AzireVPN since it is Wireguard only.
		azirevpnIndex := slices.Index(validNames, providers.Azirevpn)
		validNames[azirevpnIndex], validNames[len(validNames)-1] = validNames[len(validNames)-1], validNames[azirevpnIndex]
		validNames = validNames[:len(validNames)-1]
		sort.Strings(validNames)
	case vpn.Wireguard:
		validNames = []string{
			providers.Airvpn,
			providers.Azirevpn,
			providers.Custom,
			providers.Fastestvpn,
			providers.Ivpn,
			providers.Mullvad,
			providers.Nordvpn,
			providers.Protonvpn,
			providers.Surfshark,
			providers.Windscribe,
		}
	}
	if err = validate.IsOneOf(p.Name, validNames...); err != nil {
		return fmt.Errorf("VPN provider name is not valid for %s: %w", vpnType, err)
	}

	if p.Name == providers.Azirevpn && *p.PortForwarding.Enabled && p.AzirevpnToken == "" {
		return errors.New("azirevpn token is missing")
	}

	err = p.ServerSelection.validate(p.Name, filterChoicesGetter, warner)
	if err != nil {
		return fmt.Errorf("server selection: %w", err)
	}

	err = p.PortForwarding.Validate(p.Name)
	if err != nil {
		return fmt.Errorf("port forwarding: %w", err)
	}

	return nil
}

func (p *Provider) copy() (copied Provider) {
	return Provider{
		Name:            p.Name,
		ServerSelection: p.ServerSelection.copy(),
		PortForwarding:  p.PortForwarding.Copy(),
		AzirevpnToken:   p.AzirevpnToken,
	}
}

func (p *Provider) overrideWith(other Provider) {
	p.Name = gosettings.OverrideWithComparable(p.Name, other.Name)
	p.ServerSelection.overrideWith(other.ServerSelection)
	p.PortForwarding.OverrideWith(other.PortForwarding)
	p.AzirevpnToken = gosettings.OverrideWithComparable(p.AzirevpnToken, other.AzirevpnToken)
}

func (p *Provider) setDefaults() {
	p.Name = gosettings.DefaultComparable(p.Name, providers.PrivateInternetAccess)
	p.PortForwarding.setDefaults()
	p.ServerSelection.setDefaults(p.Name, *p.PortForwarding.Enabled)
	p.AzirevpnToken = gosettings.DefaultComparable(p.AzirevpnToken, "")
}

func (p Provider) String() string {
	return p.toLinesNode().String()
}

func (p Provider) toLinesNode() (node *gotree.Node) {
	node = gotree.New("VPN provider settings:")
	node.Appendf("Name: %s", p.Name)
	if p.AzirevpnToken != "" {
		node.Appendf("AzireVPN token: %s", gosettings.ObfuscateKey(p.AzirevpnToken))
	}
	node.AppendNode(p.ServerSelection.toLinesNode())
	node.AppendNode(p.PortForwarding.toLinesNode())
	return node
}

func (p *Provider) read(r *reader.Reader, vpnType string) (err error) {
	p.Name = readVPNServiceProvider(r, vpnType)
	p.AzirevpnToken = r.String("AZIREVPN_TOKEN", reader.ForceLowercase(false))

	err = p.ServerSelection.read(r, p.Name, vpnType)
	if err != nil {
		return fmt.Errorf("server selection: %w", err)
	}

	err = p.PortForwarding.read(r)
	if err != nil {
		return fmt.Errorf("port forwarding: %w", err)
	}

	return nil
}

func readVPNServiceProvider(r *reader.Reader, vpnType string) (vpnProvider string) {
	vpnProvider = r.String("VPN_SERVICE_PROVIDER", reader.RetroKeys("VPNSP"))
	if vpnProvider == "" {
		if vpnType != vpn.Wireguard && r.Get("OPENVPN_CUSTOM_CONFIG") != nil {
			// retro compatibility
			return providers.Custom
		}
		return ""
	}

	vpnProvider = strings.ToLower(vpnProvider)
	if vpnProvider == "pia" { // retro compatibility
		return providers.PrivateInternetAccess
	}

	return vpnProvider
}

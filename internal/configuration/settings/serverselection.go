package settings

import (
	"errors"
	"fmt"
	"strings"

	"github.com/qdm12/gluetun/internal/configuration/settings/helpers"
	"github.com/qdm12/gluetun/internal/configuration/settings/validation"
	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gosettings"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gosettings/validate"
	"github.com/qdm12/gotree"
)

type ServerSelection struct {
	// VPN is the VPN type which can be 'openvpn'
	// or 'wireguard'. It cannot be the empty string
	// in the internal state.
	VPN string `json:"vpn"`
	// Countries is the list of countries to filter VPN servers with.
	Countries []string `json:"countries"`
	// Categories is the list of categories to filter VPN servers with.
	Categories []string `json:"categories"`
	// Regions is the list of regions to filter VPN servers with.
	Regions []string `json:"regions"`
	// Cities is the list of cities to filter VPN servers with.
	Cities []string `json:"cities"`
	// ISPs is the list of ISP names to filter VPN servers with.
	ISPs []string `json:"isps"`
	// Names is the list of server names to filter VPN servers with.
	Names []string `json:"names"`
	// Numbers is the list of server numbers to filter VPN servers with.
	Numbers []uint16 `json:"numbers"`
	// Hostnames is the list of hostnames to filter VPN servers with.
	Hostnames []string `json:"hostnames"`
	// OwnedOnly is true if VPN provider servers that are not owned
	// should be filtered. This is used with Mullvad.
	OwnedOnly *bool `json:"owned_only"`
	// FreeOnly is true if VPN servers that are not free should
	// be filtered. This is used with ProtonVPN and VPN Unlimited.
	FreeOnly *bool `json:"free_only"`
	// PremiumOnly is true if VPN servers that are not premium should
	// be filtered. This is used with VPN Secure.
	// TODO extend to providers using FreeOnly.
	PremiumOnly *bool `json:"premium_only"`
	// StreamOnly is true if VPN servers not for streaming should
	// be filtered. This is used with ProtonVPN and VPNUnlimited.
	StreamOnly *bool `json:"stream_only"`
	// MultiHopOnly is true if VPN servers that are not multihop
	// should be filtered. This is used with Surfshark.
	MultiHopOnly *bool `json:"multi_hop_only"`
	// PortForwardOnly is true if VPN servers that don't support
	// port forwarding should be filtered. This is used with PIA
	// and ProtonVPN.
	PortForwardOnly *bool `json:"port_forward_only"`
	// SecureCoreOnly is true if VPN servers without secure core should
	// be filtered. This is used with ProtonVPN.
	SecureCoreOnly *bool `json:"secure_core_only"`
	// TorOnly is true if VPN servers without tor should
	// be filtered. This is used with ProtonVPN.
	TorOnly *bool `json:"tor_only"`
	// OpenVPN contains settings to select OpenVPN servers
	// and the final connection.
	OpenVPN OpenVPNSelection `json:"openvpn"`
	// Wireguard contains settings to select Wireguard servers
	// and the final connection.
	Wireguard WireguardSelection `json:"wireguard"`
}

var (
	ErrOwnedOnlyNotSupported       = errors.New("owned only filter is not supported")
	ErrFreeOnlyNotSupported        = errors.New("free only filter is not supported")
	ErrPremiumOnlyNotSupported     = errors.New("premium only filter is not supported")
	ErrStreamOnlyNotSupported      = errors.New("stream only filter is not supported")
	ErrMultiHopOnlyNotSupported    = errors.New("multi hop only filter is not supported")
	ErrPortForwardOnlyNotSupported = errors.New("port forwarding only filter is not supported")
	ErrFreePremiumBothSet          = errors.New("free only and premium only filters are both set")
	ErrSecureCoreOnlyNotSupported  = errors.New("secure core only filter is not supported")
	ErrTorOnlyNotSupported         = errors.New("tor only filter is not supported")
)

func (ss *ServerSelection) validate(vpnServiceProvider string,
	filterChoicesGetter FilterChoicesGetter, warner Warner,
) (err error) {
	switch ss.VPN {
	case vpn.AmneziaWg, vpn.OpenVPN, vpn.Wireguard:
	default:
		return fmt.Errorf("%w: %s", ErrVPNTypeNotValid, ss.VPN)
	}

	filterChoices, err := getLocationFilterChoices(vpnServiceProvider, ss, filterChoicesGetter, warner)
	if err != nil {
		return err // already wrapped error
	}

	// Retro-compatibility
	switch vpnServiceProvider {
	case providers.Nordvpn:
		*ss = nordvpnRetroRegion(*ss, filterChoices.Regions, filterChoices.Countries)
	case providers.Surfshark:
		*ss = surfsharkRetroRegion(*ss)
	}

	err = validateServerFilters(*ss, filterChoices, vpnServiceProvider, warner)
	if err != nil {
		return fmt.Errorf("for VPN service provider %s: %w", vpnServiceProvider, err)
	}

	err = validateSubscriptionTierFilters(*ss, vpnServiceProvider)
	if err != nil {
		return fmt.Errorf("for VPN service provider %s: %w", vpnServiceProvider, err)
	}

	err = validateFeatureFilters(*ss, vpnServiceProvider)
	if err != nil {
		return fmt.Errorf("for VPN service provider %s: %w", vpnServiceProvider, err)
	}

	if ss.VPN == vpn.OpenVPN {
		err = ss.OpenVPN.validate(vpnServiceProvider)
		if err != nil {
			return fmt.Errorf("OpenVPN server selection settings: %w", err)
		}
	} else {
		err = ss.Wireguard.validate(vpnServiceProvider)
		if err != nil {
			return fmt.Errorf("Wireguard server selection settings: %w", err)
		}
	}

	return nil
}

func getLocationFilterChoices(vpnServiceProvider string,
	ss *ServerSelection, filterChoicesGetter FilterChoicesGetter, warner Warner) (
	filterChoices models.FilterChoices, err error,
) {
	filterChoices = filterChoicesGetter.GetFilterChoices(vpnServiceProvider)

	if vpnServiceProvider == providers.Surfshark {
		// // Retro compatibility
		// TODO v4 remove
		newAndRetroRegions := append(filterChoices.Regions, validation.SurfsharkRetroLocChoices()...) //nolint:gocritic
		err := atLeastOneIsOneOfCaseInsensitive(ss.Regions, newAndRetroRegions, warner)
		if err != nil {
			// Only return error comparing with newer regions, we don't want to confuse the user
			// with the retro regions in the error message.
			err = atLeastOneIsOneOfCaseInsensitive(ss.Regions, filterChoices.Regions, warner)
			return models.FilterChoices{}, fmt.Errorf("%w: %w", ErrRegionNotValid, err)
		}
	}

	return filterChoices, nil
}

// validateServerFilters validates filters against the choices given as arguments.
// Set an argument to nil to pass the check for a particular filter.
func validateServerFilters(settings ServerSelection, filterChoices models.FilterChoices,
	vpnServiceProvider string, warner Warner,
) (err error) {
	err = atLeastOneIsOneOfCaseInsensitive(settings.Countries, filterChoices.Countries, warner)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCountryNotValid, err)
	}

	err = atLeastOneIsOneOfCaseInsensitive(settings.Regions, filterChoices.Regions, warner)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrRegionNotValid, err)
	}

	err = atLeastOneIsOneOfCaseInsensitive(settings.Cities, filterChoices.Cities, warner)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCityNotValid, err)
	}

	err = atLeastOneIsOneOfCaseInsensitive(settings.ISPs, filterChoices.ISPs, warner)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrISPNotValid, err)
	}

	err = atLeastOneIsOneOfCaseInsensitive(settings.Hostnames, filterChoices.Hostnames, warner)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrHostnameNotValid, err)
	}

	if vpnServiceProvider == providers.Custom {
		switch len(settings.Names) {
		case 0:
		case 1:
			// Allow a single name to be specified for the custom provider in case
			// the user wants to use VPN server side port forwarding with PIA
			// which requires a server name for TLS verification.
			filterChoices.Names = settings.Names
		default:
			return fmt.Errorf("%w: %d names specified instead of "+
				"0 or 1 for the custom provider",
				ErrNameNotValid, len(settings.Names))
		}
	}
	err = atLeastOneIsOneOfCaseInsensitive(settings.Names, filterChoices.Names, warner)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNameNotValid, err)
	}

	err = atLeastOneIsOneOfCaseInsensitive(settings.Categories, filterChoices.Categories, warner)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCategoryNotValid, err)
	}

	return nil
}

func atLeastOneIsOneOfCaseInsensitive(values, choices []string,
	warner Warner,
) (err error) {
	if len(values) > 0 && len(choices) == 0 {
		return fmt.Errorf("%w", validate.ErrNoChoice)
	}

	set := make(map[string]struct{}, len(choices))
	for _, choice := range choices {
		lowercaseChoice := strings.ToLower(choice)
		set[lowercaseChoice] = struct{}{}
	}

	invalidValues := make([]string, 0, len(values))
	for _, value := range values {
		lowercaseValue := strings.ToLower(value)
		_, ok := set[lowercaseValue]
		if ok {
			continue
		}
		invalidValues = append(invalidValues, value)
	}

	switch len(invalidValues) {
	case 0:
		return nil
	case len(values):
		return fmt.Errorf("%w: none of %s is one of the choices available %s",
			validate.ErrValueNotOneOf, strings.Join(values, ", "), strings.Join(choices, ", "))
	default:
		warner.Warn(fmt.Sprintf("values %s are not in choices %s",
			strings.Join(invalidValues, ", "), strings.Join(choices, ", ")))
	}

	return nil
}

func validateSubscriptionTierFilters(settings ServerSelection, vpnServiceProvider string) error {
	switch {
	case *settings.FreeOnly &&
		!helpers.IsOneOf(vpnServiceProvider, providers.Protonvpn, providers.VPNUnlimited):
		return fmt.Errorf("%w", ErrFreeOnlyNotSupported)
	case *settings.PremiumOnly &&
		!helpers.IsOneOf(vpnServiceProvider, providers.VPNSecure):
		return fmt.Errorf("%w", ErrPremiumOnlyNotSupported)
	case *settings.FreeOnly && *settings.PremiumOnly:
		return fmt.Errorf("%w", ErrFreePremiumBothSet)
	default:
		return nil
	}
}

func validateFeatureFilters(settings ServerSelection, vpnServiceProvider string) error {
	switch {
	case *settings.OwnedOnly && vpnServiceProvider != providers.Mullvad:
		return fmt.Errorf("%w", ErrOwnedOnlyNotSupported)
	case vpnServiceProvider == providers.Protonvpn && *settings.FreeOnly && *settings.PortForwardOnly:
		return fmt.Errorf("%w: together with free only filter", ErrPortForwardOnlyNotSupported)
	case *settings.StreamOnly &&
		!helpers.IsOneOf(vpnServiceProvider, providers.Protonvpn, providers.VPNUnlimited):
		return fmt.Errorf("%w", ErrStreamOnlyNotSupported)
	case *settings.MultiHopOnly && vpnServiceProvider != providers.Surfshark:
		return fmt.Errorf("%w", ErrMultiHopOnlyNotSupported)
	case *settings.PortForwardOnly &&
		!helpers.IsOneOf(vpnServiceProvider, providers.PrivateInternetAccess, providers.Protonvpn):
		return fmt.Errorf("%w", ErrPortForwardOnlyNotSupported)
	case *settings.SecureCoreOnly && vpnServiceProvider != providers.Protonvpn:
		return fmt.Errorf("%w", ErrSecureCoreOnlyNotSupported)
	case *settings.TorOnly && vpnServiceProvider != providers.Protonvpn:
		return fmt.Errorf("%w", ErrTorOnlyNotSupported)
	default:
		return nil
	}
}

func (ss *ServerSelection) copy() (copied ServerSelection) {
	return ServerSelection{
		VPN:             ss.VPN,
		Countries:       gosettings.CopySlice(ss.Countries),
		Categories:      gosettings.CopySlice(ss.Categories),
		Regions:         gosettings.CopySlice(ss.Regions),
		Cities:          gosettings.CopySlice(ss.Cities),
		ISPs:            gosettings.CopySlice(ss.ISPs),
		Hostnames:       gosettings.CopySlice(ss.Hostnames),
		Names:           gosettings.CopySlice(ss.Names),
		Numbers:         gosettings.CopySlice(ss.Numbers),
		OwnedOnly:       gosettings.CopyPointer(ss.OwnedOnly),
		FreeOnly:        gosettings.CopyPointer(ss.FreeOnly),
		PremiumOnly:     gosettings.CopyPointer(ss.PremiumOnly),
		StreamOnly:      gosettings.CopyPointer(ss.StreamOnly),
		SecureCoreOnly:  gosettings.CopyPointer(ss.SecureCoreOnly),
		TorOnly:         gosettings.CopyPointer(ss.TorOnly),
		PortForwardOnly: gosettings.CopyPointer(ss.PortForwardOnly),
		MultiHopOnly:    gosettings.CopyPointer(ss.MultiHopOnly),
		OpenVPN:         ss.OpenVPN.copy(),
		Wireguard:       ss.Wireguard.copy(),
	}
}

func (ss *ServerSelection) overrideWith(other ServerSelection) {
	ss.VPN = gosettings.OverrideWithComparable(ss.VPN, other.VPN)
	ss.Countries = gosettings.OverrideWithSlice(ss.Countries, other.Countries)
	ss.Categories = gosettings.OverrideWithSlice(ss.Categories, other.Categories)
	ss.Regions = gosettings.OverrideWithSlice(ss.Regions, other.Regions)
	ss.Cities = gosettings.OverrideWithSlice(ss.Cities, other.Cities)
	ss.ISPs = gosettings.OverrideWithSlice(ss.ISPs, other.ISPs)
	ss.Hostnames = gosettings.OverrideWithSlice(ss.Hostnames, other.Hostnames)
	ss.Names = gosettings.OverrideWithSlice(ss.Names, other.Names)
	ss.Numbers = gosettings.OverrideWithSlice(ss.Numbers, other.Numbers)
	ss.OwnedOnly = gosettings.OverrideWithPointer(ss.OwnedOnly, other.OwnedOnly)
	ss.FreeOnly = gosettings.OverrideWithPointer(ss.FreeOnly, other.FreeOnly)
	ss.PremiumOnly = gosettings.OverrideWithPointer(ss.PremiumOnly, other.PremiumOnly)
	ss.StreamOnly = gosettings.OverrideWithPointer(ss.StreamOnly, other.StreamOnly)
	ss.SecureCoreOnly = gosettings.OverrideWithPointer(ss.SecureCoreOnly, other.SecureCoreOnly)
	ss.TorOnly = gosettings.OverrideWithPointer(ss.TorOnly, other.TorOnly)
	ss.MultiHopOnly = gosettings.OverrideWithPointer(ss.MultiHopOnly, other.MultiHopOnly)
	ss.PortForwardOnly = gosettings.OverrideWithPointer(ss.PortForwardOnly, other.PortForwardOnly)
	ss.OpenVPN.overrideWith(other.OpenVPN)
	ss.Wireguard.overrideWith(other.Wireguard)
}

func (ss *ServerSelection) setDefaults(vpnProvider string, portForwardingEnabled bool) {
	ss.VPN = gosettings.DefaultComparable(ss.VPN, vpn.OpenVPN)
	ss.OwnedOnly = gosettings.DefaultPointer(ss.OwnedOnly, false)
	ss.FreeOnly = gosettings.DefaultPointer(ss.FreeOnly, false)
	ss.PremiumOnly = gosettings.DefaultPointer(ss.PremiumOnly, false)
	ss.StreamOnly = gosettings.DefaultPointer(ss.StreamOnly, false)
	ss.SecureCoreOnly = gosettings.DefaultPointer(ss.SecureCoreOnly, false)
	ss.TorOnly = gosettings.DefaultPointer(ss.TorOnly, false)
	ss.MultiHopOnly = gosettings.DefaultPointer(ss.MultiHopOnly, false)
	defaultPortForwardOnly := portForwardingEnabled &&
		helpers.IsOneOf(vpnProvider, providers.PrivateInternetAccess, providers.Protonvpn)
	ss.PortForwardOnly = gosettings.DefaultPointer(ss.PortForwardOnly, defaultPortForwardOnly)
	ss.OpenVPN.setDefaults(vpnProvider)
	ss.Wireguard.setDefaults()
}

func (ss ServerSelection) String() string {
	return ss.toLinesNode().String()
}

func (ss ServerSelection) toLinesNode() (node *gotree.Node) {
	node = gotree.New("Server selection settings:")
	node.Appendf("VPN type: %s", ss.VPN)

	if len(ss.Countries) > 0 {
		node.Appendf("Countries: %s", strings.Join(ss.Countries, ", "))
	}

	if len(ss.Categories) > 0 {
		node.Appendf("Categories: %s", strings.Join(ss.Categories, ", "))
	}

	if len(ss.Regions) > 0 {
		node.Appendf("Regions: %s", strings.Join(ss.Regions, ", "))
	}

	if len(ss.Cities) > 0 {
		node.Appendf("Cities: %s", strings.Join(ss.Cities, ", "))
	}

	if len(ss.ISPs) > 0 {
		node.Appendf("ISPs: %s", strings.Join(ss.ISPs, ", "))
	}

	if len(ss.Names) > 0 {
		node.Appendf("Server names: %s", strings.Join(ss.Names, ", "))
	}

	if len(ss.Numbers) > 0 {
		numbersNode := node.Appendf("Server numbers:")
		for _, number := range ss.Numbers {
			numbersNode.Appendf("%d", number)
		}
	}

	if len(ss.Hostnames) > 0 {
		node.Appendf("Hostnames: %s", strings.Join(ss.Hostnames, ", "))
	}

	if *ss.OwnedOnly {
		node.Appendf("Owned only servers: yes")
	}

	if *ss.FreeOnly {
		node.Appendf("Free only servers: yes")
	}

	if *ss.PremiumOnly {
		node.Appendf("Premium only servers: yes")
	}

	if *ss.StreamOnly {
		node.Appendf("Stream only servers: yes")
	}

	if *ss.SecureCoreOnly {
		node.Appendf("Secure Core only servers: yes")
	}

	if *ss.TorOnly {
		node.Appendf("Tor only servers: yes")
	}

	if *ss.MultiHopOnly {
		node.Appendf("Multi-hop only servers: yes")
	}

	if *ss.PortForwardOnly {
		node.Appendf("Port forwarding only servers: yes")
	}

	if ss.VPN == vpn.OpenVPN {
		node.AppendNode(ss.OpenVPN.toLinesNode())
	} else {
		node.AppendNode(ss.Wireguard.toLinesNode())
	}

	return node
}

// WithDefaults is a shorthand using setDefaults.
// It's used in unit tests in other packages.
func (ss ServerSelection) WithDefaults(provider string) ServerSelection {
	const portForwardingEnabled = false
	ss.setDefaults(provider, portForwardingEnabled)
	return ss
}

func (ss *ServerSelection) read(r *reader.Reader,
	vpnProvider, vpnType string,
) (err error) {
	ss.VPN = vpnType

	countriesRetroKeys := []string{"COUNTRY"}
	if vpnProvider == providers.Cyberghost {
		countriesRetroKeys = append(countriesRetroKeys, "REGION")
	}
	ss.Countries = r.CSV("SERVER_COUNTRIES", reader.RetroKeys(countriesRetroKeys...))

	ss.Regions = r.CSV("SERVER_REGIONS", reader.RetroKeys("REGION"))
	ss.Cities = r.CSV("SERVER_CITIES", reader.RetroKeys("CITY"))
	ss.ISPs = r.CSV("ISP")
	ss.Hostnames = r.CSV("SERVER_HOSTNAMES", reader.RetroKeys("SERVER_HOSTNAME"))
	ss.Names = r.CSV("SERVER_NAMES", reader.RetroKeys("SERVER_NAME"))
	ss.Numbers, err = r.CSVUint16("SERVER_NUMBER")
	ss.Categories = r.CSV("SERVER_CATEGORIES")
	if err != nil {
		return err
	}

	// Mullvad only
	ss.OwnedOnly, err = r.BoolPtr("OWNED_ONLY", reader.RetroKeys("OWNED"))
	if err != nil {
		return err
	}

	// VPNUnlimited and ProtonVPN only
	ss.FreeOnly, err = r.BoolPtr("FREE_ONLY")
	if err != nil {
		return err
	}

	// VPNSecure only
	ss.PremiumOnly, err = r.BoolPtr("PREMIUM_ONLY")
	if err != nil {
		return err
	}

	// Surfshark only
	ss.MultiHopOnly, err = r.BoolPtr("MULTIHOP_ONLY")
	if err != nil {
		return err
	}

	// VPNUnlimited and ProtonVPN only
	ss.StreamOnly, err = r.BoolPtr("STREAM_ONLY")
	if err != nil {
		return err
	}

	// ProtonVPN only
	ss.SecureCoreOnly, err = r.BoolPtr("SECURE_CORE_ONLY")
	if err != nil {
		return err
	}

	// ProtonVPN only
	ss.TorOnly, err = r.BoolPtr("TOR_ONLY")
	if err != nil {
		return err
	}

	// PIA and ProtonVPN only
	ss.PortForwardOnly, err = r.BoolPtr("PORT_FORWARD_ONLY")
	if err != nil {
		return err
	}

	err = ss.OpenVPN.read(r)
	if err != nil {
		return err
	}

	amneziawg := ss.VPN == vpn.AmneziaWg
	err = ss.Wireguard.read(r, amneziawg)
	if err != nil {
		return err
	}

	return nil
}

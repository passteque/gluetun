package settings

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/qdm12/gluetun/internal/configuration/settings/helpers"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/provider/privateinternetaccess/presets"
	"github.com/qdm12/gosettings"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gosettings/validate"
	"github.com/qdm12/gotree"
)

type OpenVPNSelection struct {
	// ConfFile is the custom configuration file path.
	// It can be set to an empty string to indicate to
	// NOT use a custom configuration file.
	// It cannot be nil in the internal state.
	ConfFile *string `json:"config_file_path"`
	// Protocol is the OpenVPN network protocol to use,
	// and can be udp or tcp. It cannot be the empty string
	// in the internal state.
	Protocol string `json:"protocol"`
	// EndpointIP is the server endpoint IP address.
	// If set, it overrides any IP address from the picked
	// built-in server connection. To indicate it should
	// not be used, it should be set to [netip.IPv4Unspecified].
	// It can never be the zero value in the internal state.
	EndpointIP netip.Addr `json:"endpoint_ip"`
	// CustomPort is the OpenVPN server endpoint port.
	// It can be set to 0 to indicate no custom port should
	// be used. It cannot be nil in the internal state.
	CustomPort *uint16 `json:"custom_port"`
	// PIAEncPreset is the encryption preset for
	// Private Internet Access. It can be set to an
	// empty string for other providers.
	PIAEncPreset *string `json:"pia_encryption_preset"`
}

func (o OpenVPNSelection) validate(vpnProvider string) (err error) {
	// Validate ConfFile
	if confFile := *o.ConfFile; confFile != "" {
		err := validate.FileExists(confFile)
		if err != nil {
			return fmt.Errorf("configuration file: %w", err)
		}
	}

	err = validate.IsOneOf(o.Protocol, constants.UDP, constants.TCP)
	if err != nil {
		return fmt.Errorf("network protocol: %w", err)
	}

	// Validate TCP
	if o.Protocol == constants.TCP && helpers.IsOneOf(vpnProvider,
		providers.Giganews,
		providers.Ipvanish,
		providers.Perfectprivacy,
		providers.Vyprvpn,
	) {
		return fmt.Errorf("TCP protocol is not supported: for VPN service provider %s", vpnProvider)
	}

	// Validate CustomPort
	if *o.CustomPort != 0 {
		switch vpnProvider {
		// no restriction on port
		case providers.Custom, providers.Cyberghost, providers.HideMyAss,
			providers.Privatevpn, providers.Torguard:
		// no custom port allowed
		case providers.Expressvpn, providers.Fastestvpn,
			providers.Giganews, providers.Ipvanish,
			providers.Nordvpn, providers.Purevpn,
			providers.Surfshark, providers.VPNSecure,
			providers.VPNUnlimited, providers.Vyprvpn:
			return fmt.Errorf("custom endpoint port is not allowed: for VPN service provider %s", vpnProvider)
		default:
			var allowedTCP, allowedUDP []uint16
			switch vpnProvider {
			case providers.Airvpn:
				allowedTCP = []uint16{
					53, 80, 443, // IP in 1, 3
					1194, 2018, 41185, // IP in 1, 2, 3, 4
				}
				allowedUDP = []uint16{53, 80, 443, 1194, 2018, 41185}
			case providers.Ivpn:
				allowedTCP = []uint16{80, 443, 1143}
				allowedUDP = []uint16{53, 1194, 2049, 2050}
			case providers.Mullvad:
				allowedTCP = []uint16{80, 443, 1401}
				allowedUDP = []uint16{53, 1194, 1195, 1196, 1197, 1300, 1301, 1302, 1303, 1400}
			case providers.Perfectprivacy:
				allowedTCP = []uint16{44, 443, 4433}
				allowedUDP = []uint16{44, 443, 4433}
			case providers.Privado:
				allowedTCP = []uint16{443, 1194, 8080, 8443}
				allowedUDP = []uint16{443, 1194, 8080, 8443}
			case providers.PrivateInternetAccess:
				allowedTCP = []uint16{80, 110, 443, 501, 502, 8443}
				allowedUDP = []uint16{53, 1194, 1197, 1198, 8080, 9201}
			case providers.Protonvpn:
				allowedTCP = []uint16{443, 5995, 8443}
				allowedUDP = []uint16{80, 443, 1194, 4569, 5060, 51820}
			case providers.SlickVPN:
				allowedTCP = []uint16{443, 8080, 8888}
				allowedUDP = []uint16{443, 8080, 8888}
			case providers.Windscribe:
				allowedTCP = []uint16{21, 22, 80, 123, 143, 443, 587, 1194, 3306, 8080, 54783}
				allowedUDP = []uint16{53, 80, 123, 443, 1194, 54783}
			default:
				panic(fmt.Sprintf("VPN provider %s has no registered allowed ports", vpnProvider))
			}

			allowedPorts := allowedUDP
			if o.Protocol == constants.TCP {
				allowedPorts = allowedTCP
			}
			err = validate.IsOneOf(*o.CustomPort, allowedPorts...)
			if err != nil {
				return fmt.Errorf("custom endpoint port is not allowed: for VPN service provider %s: %w", vpnProvider, err)
			}
		}
	}

	// Validate EncPreset
	if vpnProvider == providers.PrivateInternetAccess {
		validEncryptionPresets := []string{
			presets.Normal,
			presets.Strong,
		}
		if err = validate.IsOneOf(*o.PIAEncPreset, validEncryptionPresets...); err != nil {
			return fmt.Errorf("PIA encryption preset is not valid: %w", err)
		}
	}

	return nil
}

func (o *OpenVPNSelection) copy() (copied OpenVPNSelection) {
	return OpenVPNSelection{
		ConfFile:     gosettings.CopyPointer(o.ConfFile),
		Protocol:     o.Protocol,
		EndpointIP:   o.EndpointIP,
		CustomPort:   gosettings.CopyPointer(o.CustomPort),
		PIAEncPreset: gosettings.CopyPointer(o.PIAEncPreset),
	}
}

func (o *OpenVPNSelection) overrideWith(other OpenVPNSelection) {
	o.ConfFile = gosettings.OverrideWithPointer(o.ConfFile, other.ConfFile)
	o.Protocol = gosettings.OverrideWithComparable(o.Protocol, other.Protocol)
	o.CustomPort = gosettings.OverrideWithPointer(o.CustomPort, other.CustomPort)
	o.EndpointIP = gosettings.OverrideWithValidator(o.EndpointIP, other.EndpointIP)
	o.PIAEncPreset = gosettings.OverrideWithPointer(o.PIAEncPreset, other.PIAEncPreset)
}

func (o *OpenVPNSelection) setDefaults(vpnProvider string) {
	o.ConfFile = gosettings.DefaultPointer(o.ConfFile, "")
	o.Protocol = gosettings.DefaultComparable(o.Protocol, constants.UDP)
	o.EndpointIP = gosettings.DefaultValidator(o.EndpointIP, netip.IPv4Unspecified())
	o.CustomPort = gosettings.DefaultPointer(o.CustomPort, 0)

	var defaultEncPreset string
	if vpnProvider == providers.PrivateInternetAccess {
		defaultEncPreset = presets.Strong
	}
	o.PIAEncPreset = gosettings.DefaultPointer(o.PIAEncPreset, defaultEncPreset)
}

func (o OpenVPNSelection) String() string {
	return o.toLinesNode().String()
}

func (o OpenVPNSelection) toLinesNode() (node *gotree.Node) {
	node = gotree.New("OpenVPN server selection settings:")
	node.Appendf("Protocol: %s", strings.ToUpper(o.Protocol))

	if !o.EndpointIP.IsUnspecified() {
		node.Appendf("Endpoint IP address: %s", o.EndpointIP)
	}

	if *o.CustomPort != 0 {
		node.Appendf("Custom port: %d", *o.CustomPort)
	}

	if *o.PIAEncPreset != "" {
		node.Appendf("Private Internet Access encryption preset: %s", *o.PIAEncPreset)
	}

	if *o.ConfFile != "" {
		node.Appendf("Custom configuration file: %s", *o.ConfFile)
	}

	return node
}

func (o *OpenVPNSelection) read(r *reader.Reader) (err error) {
	o.ConfFile = r.Get("OPENVPN_CUSTOM_CONFIG", reader.ForceLowercase(false))

	o.Protocol = r.String("OPENVPN_PROTOCOL", reader.RetroKeys("PROTOCOL"))

	o.EndpointIP, err = r.NetipAddr("OPENVPN_ENDPOINT_IP",
		reader.RetroKeys("OPENVPN_TARGET_IP", "VPN_ENDPOINT_IP"))
	if err != nil {
		return err
	}

	o.CustomPort, err = r.Uint16Ptr("OPENVPN_ENDPOINT_PORT",
		reader.RetroKeys("PORT", "OPENVPN_PORT", "VPN_ENDPOINT_PORT"))
	if err != nil {
		return err
	}

	o.PIAEncPreset = r.Get("PRIVATE_INTERNET_ACCESS_OPENVPN_ENCRYPTION_PRESET",
		reader.RetroKeys("ENCRYPTION", "PIA_ENCRYPTION"))

	return nil
}

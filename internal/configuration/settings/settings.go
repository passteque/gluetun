package settings

import (
	"fmt"

	"github.com/qdm12/gluetun/internal/configuration/settings/helpers"
	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/pprof"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gotree"
)

type Settings struct {
	ControlServer ControlServer
	DNS           DNS
	Firewall      Firewall
	Health        Health
	HTTPProxy     HTTPProxy
	Log           Log
	PublicIP      PublicIP
	Shadowsocks   Shadowsocks
	Storage       Storage
	System        System
	Updater       Updater
	Version       Version
	VPN           VPN
	Pprof         pprof.Settings
	BoringPoll    BoringPoll
}

type FilterChoicesGetter interface {
	GetFilterChoices(provider string) models.FilterChoices
}

// Validate validates all the settings and returns an error
// if one of them is not valid.
// TODO v4 remove pointer for receiver (because of Surfshark).
func (s *Settings) Validate(filterChoicesGetter FilterChoicesGetter, ipv6Supported bool,
	warner Warner,
) (err error) {
	nameToValidation := map[string]func() error{
		"control server":  s.ControlServer.validate,
		"dns":             s.DNS.validate,
		"firewall":        s.Firewall.validate,
		"health":          s.Health.Validate,
		"http proxy":      s.HTTPProxy.validate,
		"log":             s.Log.validate,
		"public ip check": s.PublicIP.validate,
		"shadowsocks":     s.Shadowsocks.validate,
		"storage":         s.Storage.validate,
		"system":          s.System.validate,
		"updater":         s.Updater.Validate,
		"version":         s.Version.validate,
		// Pprof validation done in pprof constructor
		"VPN": func() error {
			return s.VPN.Validate(filterChoicesGetter, ipv6Supported, warner)
		},
		"boring poll": s.BoringPoll.validate,
	}

	for name, validation := range nameToValidation {
		err = validation()
		if err != nil {
			return fmt.Errorf("%s settings: %w", name, err)
		}
	}

	return nil
}

func (s *Settings) copy() (copied Settings) {
	return Settings{
		ControlServer: s.ControlServer.copy(),
		DNS:           s.DNS.Copy(),
		Firewall:      s.Firewall.copy(),
		Health:        s.Health.copy(),
		HTTPProxy:     s.HTTPProxy.copy(),
		Log:           s.Log.copy(),
		PublicIP:      s.PublicIP.copy(),
		Shadowsocks:   s.Shadowsocks.copy(),
		Storage:       s.Storage.copy(),
		System:        s.System.copy(),
		Updater:       s.Updater.copy(),
		Version:       s.Version.copy(),
		VPN:           s.VPN.Copy(),
		Pprof:         s.Pprof.Copy(),
		BoringPoll:    s.BoringPoll.Copy(),
	}
}

func (s *Settings) OverrideWith(other Settings,
	filterChoicesGetter FilterChoicesGetter, ipv6Supported bool, warner Warner,
) (err error) {
	patchedSettings := s.copy()
	patchedSettings.ControlServer.overrideWith(other.ControlServer)
	patchedSettings.DNS.overrideWith(other.DNS)
	patchedSettings.Firewall.overrideWith(other.Firewall)
	patchedSettings.Health.OverrideWith(other.Health)
	patchedSettings.HTTPProxy.overrideWith(other.HTTPProxy)
	patchedSettings.Log.overrideWith(other.Log)
	patchedSettings.PublicIP.overrideWith(other.PublicIP)
	patchedSettings.Shadowsocks.overrideWith(other.Shadowsocks)
	patchedSettings.Storage.overrideWith(other.Storage)
	patchedSettings.System.overrideWith(other.System)
	patchedSettings.Updater.overrideWith(other.Updater)
	patchedSettings.Version.overrideWith(other.Version)
	patchedSettings.VPN.OverrideWith(other.VPN)
	patchedSettings.Pprof.OverrideWith(other.Pprof)
	patchedSettings.BoringPoll.overrideWith(other.BoringPoll)
	err = patchedSettings.Validate(filterChoicesGetter, ipv6Supported, warner)
	if err != nil {
		return err
	}
	*s = patchedSettings
	return nil
}

func (s *Settings) SetDefaults() {
	s.ControlServer.setDefaults()
	s.DNS.setDefaults()
	s.Log.setDefaults()
	s.Firewall.setDefaults(s.Log.Level)
	s.Health.SetDefaults()
	s.HTTPProxy.setDefaults()
	s.PublicIP.setDefaults()
	s.Shadowsocks.setDefaults()
	s.Storage.setDefaults()
	s.System.setDefaults()
	s.Version.setDefaults()
	s.VPN.setDefaults()
	s.Updater.SetDefaults(s.VPN.Provider.Name)
	s.Pprof.SetDefaults()
	s.BoringPoll.setDefaults()
}

func (s Settings) String() string {
	return s.toLinesNode().String()
}

func (s Settings) toLinesNode() (node *gotree.Node) {
	node = gotree.New("Settings summary:")

	node.AppendNode(s.VPN.toLinesNode())
	node.AppendNode(s.DNS.toLinesNode())
	node.AppendNode(s.Firewall.toLinesNode())
	node.AppendNode(s.Log.toLinesNode())
	node.AppendNode(s.Health.toLinesNode())
	node.AppendNode(s.Shadowsocks.toLinesNode())
	node.AppendNode(s.HTTPProxy.toLinesNode())
	node.AppendNode(s.ControlServer.toLinesNode())
	node.AppendNode(s.Storage.toLinesNode())
	node.AppendNode(s.System.toLinesNode())
	node.AppendNode(s.PublicIP.toLinesNode())
	node.AppendNode(s.Updater.toLinesNode())
	node.AppendNode(s.Version.toLinesNode())
	node.AppendNode(s.Pprof.ToLinesNode())
	node.AppendNode(s.BoringPoll.toLinesNode())

	return node
}

func (s Settings) Warnings() (warnings []string) {
	if s.VPN.Provider.Name == providers.HideMyAss {
		warnings = append(warnings, "HideMyAss dropped support for Linux OpenVPN "+
			" so this will likely not work anymore. See https://github.com/qdm12/gluetun/issues/1498.")
	}

	if helpers.IsOneOf(s.VPN.Provider.Name, providers.SlickVPN) &&
		s.VPN.Type == vpn.OpenVPN {
		warnings = append(warnings, "OpenVPN 2.5 and 2.6 use OpenSSL 3 "+
			"which prohibits the usage of weak security in today's standards. "+
			s.VPN.Provider.Name+" uses weak security which is out "+
			"of Gluetun's control so the only workaround is to allow such weaknesses "+
			`using the OpenVPN option tls-cipher "DEFAULT:@SECLEVEL=0". `+
			"You might want to reach to your provider so they upgrade their certificates. "+
			"Once this is done, you will have to let the Gluetun maintainers know "+
			"by creating an issue, attaching the new certificate and we will update Gluetun.")
	}

	for _, upstreamAddress := range s.DNS.UpstreamPlainAddresses {
		if upstreamAddress.Addr().IsPrivate() {
			warnings = append(warnings, "DNS upstream address "+upstreamAddress.String()+" is private: "+
				"DNS traffic might leak out of the VPN tunnel to that address.")
		}
	}

	return warnings
}

func (s *Settings) Read(r *reader.Reader, warner Warner) (err error) {
	warnings := readObsolete(r)
	for _, warning := range warnings {
		warner.Warn(warning)
	}

	readFunctions := map[string]func(r *reader.Reader) error{
		"control server": s.ControlServer.read,
		"DNS":            s.DNS.read,
		"firewall":       s.Firewall.read,
		"health":         s.Health.Read,
		"http proxy":     s.HTTPProxy.read,
		"log":            s.Log.read,
		"public ip": func(r *reader.Reader) error {
			return s.PublicIP.read(r, warner)
		},
		"shadowsocks": s.Shadowsocks.read,
		"storage":     s.Storage.read,
		"system":      s.System.read,
		"updater":     s.Updater.read,
		"version":     s.Version.read,
		"VPN":         s.VPN.read,
		"profiling":   s.Pprof.Read,
		"boring poll": s.BoringPoll.read,
	}

	for name, read := range readFunctions {
		err = read(r)
		if err != nil {
			return fmt.Errorf("reading %s settings: %w", name, err)
		}
	}

	return nil
}

package vpn

import (
	"context"
	"fmt"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/openvpn"
	"github.com/qdm12/gluetun/internal/provider"
)

// setupOpenVPN sets OpenVPN up using the configurators and settings given.
// It returns a serverName for port forwarding (PIA) and an error if it fails.
func setupOpenVPN(ctx context.Context, fw Firewall,
	openvpnConf OpenVPN, providerConf provider.Provider,
	settings settings.VPN, ipv6Supported bool, starter Cmder,
	logger openvpn.Logger) (runner *openvpn.Runner, connection models.Connection, err error,
) {
	connection, err = providerConf.GetConnection(settings.Provider.ServerSelection, ipv6Supported)
	if err != nil {
		return nil, models.Connection{}, fmt.Errorf("finding a valid server connection: %w", err)
	}

	lines := providerConf.OpenVPNConfig(connection, settings.OpenVPN, ipv6Supported)

	if err := openvpnConf.WriteConfig(lines); err != nil {
		return nil, models.Connection{}, fmt.Errorf("writing configuration to file: %w", err)
	}

	if *settings.OpenVPN.User != "" {
		err := openvpnConf.WriteAuthFile(*settings.OpenVPN.User, *settings.OpenVPN.Password)
		if err != nil {
			return nil, models.Connection{}, fmt.Errorf("writing auth to file: %w", err)
		}
	}

	if *settings.OpenVPN.KeyPassphrase != "" {
		err := openvpnConf.WriteAskPassFile(*settings.OpenVPN.KeyPassphrase)
		if err != nil {
			return nil, models.Connection{}, fmt.Errorf("writing askpass file: %w", err)
		}
	}

	if err := fw.SetVPNConnection(ctx, connection, settings.OpenVPN.Interface); err != nil {
		return nil, models.Connection{}, fmt.Errorf("allowing VPN connection through firewall: %w", err)
	}

	runner = openvpn.NewRunner(settings.OpenVPN, starter, logger)

	return runner, connection, nil
}

package dns

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/qdm12/dns/v2/pkg/middlewares/filter/update"
	"github.com/qdm12/dns/v2/pkg/nameserver"
	"github.com/qdm12/dns/v2/pkg/server"
	"github.com/qdm12/gluetun/internal/configuration/settings"
)

func (l *Loop) setupServer(ctx context.Context, settings settings.DNS) (runError <-chan error, err error) {
	var updateSettings update.Settings
	updateSettings.SetRebindingProtectionExempt(settings.Blacklist.RebindingProtectionExemptHostnames)
	err = l.filter.Update(updateSettings)
	if err != nil {
		return nil, fmt.Errorf("updating filter for rebinding protection: %w", err)
	}

	serverSettings, err := buildServerSettings(settings, l.filter, l.localResolvers, l.localSubnets, l.logger)
	if err != nil {
		return nil, fmt.Errorf("building server settings: %w", err)
	}

	server, err := server.New(serverSettings)
	if err != nil {
		return nil, fmt.Errorf("creating server: %w", err)
	}

	runError, err = server.Start(ctx)
	if err != nil {
		return nil, fmt.Errorf("starting server: %w", err)
	}
	l.server = server

	// use internal DNS server
	nameserver.UseDNSInternally(nameserver.SettingsInternalDNS{})
	err = nameserver.UseDNSSystemWide(nameserver.SettingsSystemDNS{
		ResolvPath: l.resolvConf,
	})
	if err != nil {
		l.logger.Error(err.Error())
	}

	return runError, nil
}

func (l *Loop) usePlainServers(addrPorts []netip.AddrPort) (err error) {
	nameserver.UseDNSInternally(nameserver.SettingsInternalDNS{
		AddrPort: addrPorts[0],
	})
	addresses := make([]netip.Addr, len(addrPorts))
	for i, addrPort := range addrPorts {
		const defaultDNSPort = 53
		if addrPort.Port() != defaultDNSPort {
			return fmt.Errorf("invalid DNS port: %d, must be %d", addrPort.Port(), defaultDNSPort)
		}
		addresses[i] = addrPort.Addr()
	}
	err = nameserver.UseDNSSystemWide(nameserver.SettingsSystemDNS{
		IPs:        addresses,
		ResolvPath: l.resolvConf,
	})
	if err != nil {
		return fmt.Errorf("using DNS system wide: %w", err)
	}
	return nil
}

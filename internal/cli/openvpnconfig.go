package cli

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/netlink"
	"github.com/qdm12/gluetun/internal/openvpn/extract"
	"github.com/qdm12/gluetun/internal/provider"
	"github.com/qdm12/gluetun/internal/updater/resolver"
	"github.com/qdm12/gosettings/reader"
)

type OpenvpnConfigLogger interface {
	Info(s string)
	Warn(s string)
}

type Unzipper interface {
	FetchAndExtract(ctx context.Context, url string) (
		contents map[string][]byte, err error)
}

type ParallelResolver interface {
	Resolve(ctx context.Context, settings resolver.ParallelSettings) (
		hostToIPs map[string][]netip.Addr, warnings []string, err error)
}

type IPv6Checker interface {
	FindIPv6SupportLevel(ctx context.Context,
		checkAddresses []netip.AddrPort, firewall netlink.Firewall,
	) (level netlink.IPv6SupportLevel, err error)
}

func (c *CLI) OpenvpnConfig(logger OpenvpnConfigLogger, reader *reader.Reader,
	ipv6Checker IPv6Checker,
) error {
	storage, err := setupStorage(newNoopLogger())
	if err != nil {
		return fmt.Errorf("setting up storage: %w", err)
	}

	var allSettings settings.Settings
	err = allSettings.Read(reader, logger)
	if err != nil {
		return err
	}
	allSettings.SetDefaults()

	ipv6SupportLevel, err := ipv6Checker.FindIPv6SupportLevel(context.Background(),
		allSettings.IPv6.CheckAddresses, &noopFirewall{})
	if err != nil {
		return fmt.Errorf("checking for IPv6 support: %w", err)
	}

	err = allSettings.Validate(storage, ipv6SupportLevel.IsSupported(), logger)
	if err != nil {
		return fmt.Errorf("validating settings: %w", err)
	}

	// Unused by this CLI command
	unzipper := Unzipper(nil)
	client := (*http.Client)(nil)
	warner := Warner(nil)
	parallelResolver := ParallelResolver(nil)
	openvpnFileExtractor := extract.New()

	providers := provider.NewProviders(storage, time.Now, warner, client,
		unzipper, parallelResolver, openvpnFileExtractor, allSettings.Updater)
	providerConf := providers.Get(allSettings.VPN.Provider.Name)

	// Resolve the endpoint hostname from settings, if set. In CLI mode there
	// is no firewall, so the system resolver can be used directly.
	selection := &allSettings.VPN.Provider.ServerSelection
	if selection.OpenVPN.EndpointHostname != nil && *selection.OpenVPN.EndpointHostname != "" {
		ips, err := net.DefaultResolver.LookupIPAddr(context.Background(), *selection.OpenVPN.EndpointHostname)
		if err != nil {
			return fmt.Errorf("resolving endpoint hostname: %w", err)
		}
		if len(ips) == 0 {
			return fmt.Errorf("resolving endpoint hostname %q: no IP address found", *selection.OpenVPN.EndpointHostname)
		}
		addr, ok := netip.AddrFromSlice(ips[0].IP)
		if !ok {
			return fmt.Errorf("resolving endpoint hostname %q: invalid IP address", *selection.OpenVPN.EndpointHostname)
		}
		selection.OpenVPN.EndpointIP = addr.Unmap()
	}

	connection, err := providerConf.GetConnection(
		allSettings.VPN.Provider.ServerSelection, ipv6SupportLevel == netlink.IPv6Internet,
	)
	if err != nil {
		return err
	}

	// Handle a hostname in the remote line of a custom .ovpn file.
	if !connection.IP.IsValid() && connection.Hostname != "" {
		ips, err := net.DefaultResolver.LookupIPAddr(context.Background(), connection.Hostname)
		if err != nil {
			return fmt.Errorf("resolving endpoint hostname: %w", err)
		}
		if len(ips) == 0 {
			return fmt.Errorf("resolving endpoint hostname %q: no IP address found", connection.Hostname)
		}
		addr, ok := netip.AddrFromSlice(ips[0].IP)
		if !ok {
			return fmt.Errorf("resolving endpoint hostname %q: invalid IP address", connection.Hostname)
		}
		connection.IP = addr.Unmap()
	}

	lines := providerConf.OpenVPNConfig(connection,
		allSettings.VPN.OpenVPN, ipv6SupportLevel.IsSupported())

	fmt.Println(strings.Join(lines, "\n"))
	return nil
}

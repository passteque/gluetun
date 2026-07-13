package updater

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
)

// FetchWireguardServer obtains a Wireguard server directly from PIA's live
// server list. PIA Wireguard servers are registered dynamically and are not
// present in the embedded server list used by the other connection paths.
func (u *Updater) FetchWireguardServer(ctx context.Context, selection settings.ServerSelection) (
	server models.Server, err error,
) {
	data, err := fetchWireguardAPI(ctx, u.client)
	if err != nil {
		return server, fmt.Errorf("fetching PIA server list: %w", err)
	}

	return selectWireguardServer(data.Regions, selection)
}

func selectWireguardServer(regions []regionData, selection settings.ServerSelection) (
	server models.Server, err error,
) {
	for _, region := range regions {
		if region.Offline || (*selection.PortForwardOnly && !region.PortForward) ||
			!matchesAnyRegion(region, selection.Regions) ||
			!matchesAnyHostname(region, selection.Hostnames) {
			continue
		}

		for _, wireguardServer := range region.Servers.WG {
			if !matchesAnyServer(region, wireguardServer, selection.Names) {
				continue
			}

			return models.Server{
				VPN:              vpn.Wireguard,
				Region:           region.Name,
				ServerName:       wireguardServer.CN,
				Hostname:         region.DNS,
				WireguardDynamic: true,
				PortForward:      region.PortForward,
				IPs:              []netip.Addr{wireguardServer.IP},
			}, nil
		}
	}

	return server, errors.New("no Wireguard server found matching selection")
}

func matchesAnyRegion(region regionData, regions []string) bool {
	if len(regions) == 0 {
		return true
	}

	for _, selectedRegion := range regions {
		if strings.EqualFold(region.Name, selectedRegion) || strings.EqualFold(region.ID, selectedRegion) {
			return true
		}
	}

	return false
}

func matchesAnyHostname(region regionData, hostnames []string) bool {
	if len(hostnames) == 0 {
		return true
	}

	for _, selectedHostname := range hostnames {
		if strings.EqualFold(region.DNS, selectedHostname) {
			return true
		}
	}

	return false
}

func matchesAnyServer(region regionData, server serverData, names []string) bool {
	if len(names) == 0 {
		return true
	}

	for _, selectedName := range names {
		if strings.EqualFold(server.CN, selectedName) ||
			strings.EqualFold(region.Name, selectedName) || strings.EqualFold(region.ID, selectedName) {
			return true
		}
	}

	return false
}

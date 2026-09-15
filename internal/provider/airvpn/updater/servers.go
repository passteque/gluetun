package updater

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/common"
)

func (u *Updater) FetchServers(ctx context.Context, minServers int) (
	servers []models.Server, err error,
) {
	data, err := fetchAPI(ctx, u.client)
	if err != nil {
		return nil, fmt.Errorf("fetching API: %w", err)
	}

	// every API server model has:
	// - Wireguard server using IPv4In1 and IPv4In3
	// - Wiregard server using IPv6In1 and IPv4In3
	// - OpenVPN TCP+UDP+SSH+SSL server with tls-auth using IPv4In1 and IPv6In1
	// - OpenVPN TCP+UDP+SSH+SSL server with tls-auth using IPv4In2 and IPv6In2
	// - OpenVPN TCP+UDP+SSH+SSL server with tls-crypt using IPv4In3 and IPv6In3
	// - OpenVPN TCP+UDP+SSH+SSL server with tls-crypt using IPv6In4 and IPv6In4
	const numberOfServersPerAPIServer = 2 + // Wireguard server using IPv4In1, IPv4In3
		2 + // Wiregard server using IPv6In1, IPv4In3
		4 + // OpenVPN TCP server with tls-auth using IPv4In3, IPv6In3, IPv4In4, IPv6In4
		4 // OpenVPN UDP server with tls-auth using IPv4In3, IPv6In3, IPv4In4, IPv6In4
	projectedNumberOfServers := numberOfServersPerAPIServer * len(data.Servers)

	if projectedNumberOfServers < minServers {
		return nil, fmt.Errorf("%w: %d and expected at least %d",
			common.ErrNotEnoughServers, projectedNumberOfServers, minServers)
	}

	servers = make([]models.Server, 0, projectedNumberOfServers)
	for _, apiServer := range data.Servers {
		if apiServer.Health != "ok" {
			continue
		}

		city := strings.ReplaceAll(apiServer.Location, ", ", " ")
		city = strings.ReplaceAll(city, ",", "")
		baseServer := models.Server{
			ServerName: apiServer.PublicName,
			Country:    apiServer.CountryName,
			City:       city,
			Region:     apiServer.Continent,
		}

		baseWireguardServer := baseServer
		baseWireguardServer.VPN = vpn.Wireguard
		baseWireguardServer.WgPubKey = "PyLCXAQT8KkM4T+dUsOQfn+Ub3pGxfGlxkIApuig+hk="

		ipv4In1WireguadServer := baseWireguardServer
		ipv4In1WireguadServer.IPs = []netip.Addr{apiServer.IPv4In1}
		ipv4In1WireguadServer.Hostname = apiServer.CountryCode + ".vpn.airdns.org"
		servers = append(servers, ipv4In1WireguadServer)

		ipv6In1WireguadServer := baseWireguardServer
		ipv6In1WireguadServer.IPs = []netip.Addr{apiServer.IPv6In1}
		ipv6In1WireguadServer.Hostname = apiServer.CountryCode + ".ipv6.vpn.airdns.org"
		servers = append(servers, ipv6In1WireguadServer)

		ipv4In3WireguadServer := baseWireguardServer
		ipv4In3WireguadServer.IPs = []netip.Addr{apiServer.IPv4In3}
		ipv4In3WireguadServer.Hostname = apiServer.CountryCode + "3.vpn.airdns.org"
		servers = append(servers, ipv4In3WireguadServer)

		ipv6In3WireguadServer := baseWireguardServer
		ipv6In3WireguadServer.IPs = []netip.Addr{apiServer.IPv6In3}
		ipv6In3WireguadServer.Hostname = apiServer.CountryCode + "3.ipv6.vpn.airdns.org"
		servers = append(servers, ipv6In3WireguadServer)

		baseOpenVPNServer := baseServer
		baseOpenVPNServer.VPN = vpn.OpenVPN
		baseOpenVPNServer.UDP = true
		baseOpenVPNServer.TCP = true

		// Ignore IPs 1 and 2 since tls-crypt is superior to tls-auth really.

		ipv4In3OpenVPNServer := baseOpenVPNServer
		ipv4In3OpenVPNServer.IPs = []netip.Addr{apiServer.IPv4In3}
		ipv4In3OpenVPNServer.Hostname = apiServer.CountryCode + "3.vpn.airdns.org"
		servers = append(servers, ipv4In3OpenVPNServer)

		ipv6In3OpenVPNServer := baseOpenVPNServer
		ipv6In3OpenVPNServer.IPs = []netip.Addr{apiServer.IPv6In3}
		ipv6In3OpenVPNServer.Hostname = apiServer.CountryCode + "3.ipv6.vpn.airdns.org"
		servers = append(servers, ipv6In3OpenVPNServer)

		ipv4In4OpenVPNServer := baseOpenVPNServer
		ipv4In4OpenVPNServer.IPs = []netip.Addr{apiServer.IPv4In4}
		ipv4In4OpenVPNServer.Hostname = apiServer.CountryCode + "4.vpn.airdns.org"
		servers = append(servers, ipv4In4OpenVPNServer)

		ipv6In4OpenVPNServer := baseOpenVPNServer
		ipv6In4OpenVPNServer.IPs = []netip.Addr{apiServer.IPv6In4}
		ipv6In4OpenVPNServer.Hostname = apiServer.CountryCode + "4.ipv6.vpn.airdns.org"
		servers = append(servers, ipv6In4OpenVPNServer)
	}

	sort.Sort(models.SortableServers(servers))

	return servers, nil
}

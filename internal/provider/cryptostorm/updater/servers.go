package updater

import (
	"context"
	"fmt"
	"net"
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
	nodes, _, err := fetchNodes(ctx, u.client)
	if err != nil {
		return nil, fmt.Errorf("fetching nodes: %w", err)
	}

	hts := make(hostToServer)

	for _, node := range nodes {
		country, city := parseLocation(node.Location)

		// WireGuard server entry (only if public key is available).
		if node.WgPubKey != "" {
			server := models.Server{
				VPN:         vpn.Wireguard,
				Country:     country,
				City:        city,
				Hostname:    node.Hostname,
				WgPubKey:    node.WgPubKey,
				PortForward: true,
			}
			hts[node.Hostname+"/wg"] = server
		}

		// OpenVPN server entry.
		// Derive x509 name from hostname: "newyork.cstorm.is" -> "cryptostorm newyork server"
		location := strings.Split(node.Hostname, ".")[0]
		ovpnX509 := "cryptostorm " + location + " server"
		openvpnServer := models.Server{
			VPN:         vpn.OpenVPN,
			Country:     country,
			City:        city,
			Hostname:    node.Hostname,
			OvpnX509:    ovpnX509,
			TCP:         true,
			UDP:         true,
			PortForward: true,
		}
		hts[node.Hostname+"/ovpn"] = openvpnServer
	}

	hosts := hts.toUniqueHostsSlice()

	hostToIPs, err := resolveHosts(ctx, hosts)
	if err != nil {
		return nil, fmt.Errorf("resolving hosts: %w", err)
	}

	hts.adaptWithIPs(hostToIPs)

	servers = hts.toServersSlice()

	if len(servers) < minServers {
		return nil, fmt.Errorf("%w: %d and expected at least %d",
			common.ErrNotEnoughServers, len(servers), minServers)
	}

	sort.Sort(models.SortableServers(servers))

	return servers, nil
}

// resolveHosts resolves a list of hostnames to their IP addresses.
func resolveHosts(ctx context.Context, hosts []string) (hostToIPs map[string][]netip.Addr, err error) {
	hostToIPs = make(map[string][]netip.Addr, len(hosts))
	for _, host := range hosts {
		addrs, resolveErr := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if resolveErr != nil {
			// Non-fatal: skip hosts that fail to resolve
			continue
		}
		hostToIPs[host] = addrs
	}
	return hostToIPs, nil
}

// parseLocation splits a location string like "Canada - Montreal" into
// country and city. It handles these formats from cryptostorm:
//   - "Austria" (country only)
//   - "Canada - Montreal" (country - city)
//   - "US - Texas - Dallas" (country - state - city)
//   - "Sydney - Australia" (city - country, detected by known country names)
func parseLocation(location string) (country, city string) {
	parts := strings.Split(location, " - ")
	switch len(parts) {
	case 1:
		return parts[0], ""
	case 2:
		// Check if the second part is a known country name, indicating
		// a reversed "City - Country" format (e.g. "Sydney - Australia").
		if isCountryName(parts[1]) && !isCountryName(parts[0]) {
			return parts[1], parts[0]
		}
		return parts[0], parts[1]
	default:
		// "US - Texas - Dallas" -> country: first part, city: last part
		return parts[0], parts[len(parts)-1]
	}
}

// isCountryName returns true if the string matches a known country name
// that appears in the cryptostorm server list in a potentially reversed
// "City - Country" format.
func isCountryName(s string) bool {
	switch s {
	case "Australia", "Japan":
		return true
	default:
		return false
	}
}

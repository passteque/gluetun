package updater

import (
	"context"
	"fmt"
	"net/netip"
	"sort"

	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/common"
)

func (u *Updater) FetchServers(ctx context.Context, minServers int) (
	servers []models.Server, err error,
) {
	data, err := fetchAPI(ctx, u.client)
	if err != nil {
		return nil, err
	}

	for _, regionData := range data.Data {
		region := regionData.Region
		for _, group := range regionData.Groups {
			city := group.City
			x5090Name := group.OvpnX509
			wgPubKey := group.WgPubKey
			for _, node := range group.Nodes {
				ips := make([]netip.Addr, 0, 2) //nolint:mnd
				if node.IP.IsValid() {
					ips = append(ips, node.IP)
				}
				if node.IP2.IsValid() {
					ips = append(ips, node.IP2)
				}
				server := models.Server{
					VPN:      vpn.OpenVPN,
					TCP:      true,
					UDP:      true,
					Region:   region,
					City:     city,
					Hostname: node.Hostname,
					OvpnX509: x5090Name,
					IPs:      ips,
				}
				servers = append(servers, server)

				if !node.IP3.IsValid() { // Wireguard + Stealth
					continue
				} else if wgPubKey == "" {
					return nil, fmt.Errorf("no wireguard public key found: for node %s", node.Hostname)
				}

				server.VPN = vpn.Wireguard
				server.UDP = false
				server.TCP = false
				server.OvpnX509 = ""
				server.WgPubKey = wgPubKey
				server.IPs = []netip.Addr{node.IP3}
				servers = append(servers, server)
			}
		}
	}

	if len(servers) < minServers {
		return nil, fmt.Errorf("%w: %d and expected at least %d",
			common.ErrNotEnoughServers, len(servers), minServers)
	}

	sort.Sort(models.SortableServers(servers))

	return servers, nil
}

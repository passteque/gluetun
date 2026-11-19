package updater

import (
	"context"
	"fmt"
	"sort"

	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/common"
)

func (u *Updater) FetchServers(ctx context.Context, minServers int) (
	servers []models.Server, err error,
) {
	// Since SlickVPN website listing VPN servers https://www.slickvpn.com/locations/
	// went to become a pile of trash, we now hardcode the servers data below.
	//nolint:goconst
	servers = []models.Server{
		{Hostname: "gw1.akl1.slickvpn.com", Region: "Oceania", Country: "New Zealand", City: "Auckland"},
		{Hostname: "gw1.arn1.slickvpn.com", Region: "Europe", Country: "Sweden", City: "Stockholm"},
		{Hostname: "gw1.atl1.slickvpn.com", Region: "North America", Country: "United States", City: "Atlanta"},
		{Hostname: "gw1.bos1.slickvpn.com", Region: "North America", Country: "United States", City: "Boston"},
		{Hostname: "gw1.buf1.slickvpn.com", Region: "North America", Country: "United States", City: "Buffalo"},
		{Hostname: "gw1.buh2.slickvpn.com", Region: "Europe", Country: "Romania", City: "Bucharest"},
		{Hostname: "gw1.cdg1.slickvpn.com", Region: "Europe", Country: "France", City: "Paris"},
		{Hostname: "gw1.cmh1.slickvpn.com", Region: "North America", Country: "United States", City: "Columbus"},
		{Hostname: "gw1.fra1.slickvpn.com", Region: "Europe", Country: "Germany", City: "Frankfurt"},
		{Hostname: "gw1.lax2.slickvpn.com", Region: "North America", Country: "United States", City: "Los Angeles"},
		{Hostname: "gw1.lga2.slickvpn.com", Region: "North America", Country: "United States", City: "New York"},
		{Hostname: "gw1.man2.slickvpn.com", Region: "Europe", Country: "United Kingdom", City: "Manchester"},
		{Hostname: "gw1.mci2.slickvpn.com", Region: "North America", Country: "United States", City: "Kansas City"},
		{Hostname: "gw1.mxp1.slickvpn.com", Region: "Europe", Country: "Italy", City: "Milan"},
		{Hostname: "gw1.nrt1.slickvpn.com", Region: "Asia", Country: "Japan", City: "Tokyo"},
		{Hostname: "gw1.phx1.slickvpn.com", Region: "North America", Country: "United States", City: "Phoenix"},
		{Hostname: "gw1.stl1.slickvpn.com", Region: "North America", Country: "United States", City: "St Louis"},
		{Hostname: "gw1.syd1.slickvpn.com", Region: "Oceania", Country: "Australia", City: "Sydney"},
		{Hostname: "gw1.yul1.slickvpn.com", Region: "North America", Country: "Canada", City: "Montreal"},
		{Hostname: "gw1.yyz1.slickvpn.com", Region: "North America", Country: "Canada", City: "Toronto"},
		{Hostname: "gw2.ams3.slickvpn.com", Region: "Europe", Country: "Netherlands", City: "Amsterdam"},
		{Hostname: "gw2.hou1.slickvpn.com", Region: "North America", Country: "United States", City: "Houston"},
		{Hostname: "gw2.ord1.slickvpn.com", Region: "North America", Country: "United States", City: "Chicago"},
		{Hostname: "gw2.sin2.slickvpn.com", Region: "Asia", Country: "Singapore", City: "Singapore"},
		{Hostname: "gw2.slc1.slickvpn.com", Region: "North America", Country: "United States", City: "Salt Lake City"},
		{Hostname: "gw4.lhr1.slickvpn.com", Region: "Europe", Country: "United Kingdom", City: "London"},
	}

	hosts := make([]string, len(servers))
	for i := range servers {
		hosts[i] = servers[i].Hostname
	}

	resolveSettings := parallelResolverSettings(hosts)
	hostToIPs, warnings, err := u.parallelResolver.Resolve(ctx, resolveSettings)
	for _, warning := range warnings {
		u.warner.Warn(warning)
	}
	if err != nil {
		return nil, fmt.Errorf("resolving hosts: %w", err)
	}

	if len(hostToIPs) < minServers {
		return nil, fmt.Errorf("%w: %d and expected at least %d",
			common.ErrNotEnoughServers, len(hosts), minServers)
	}

	for i := range servers {
		servers[i].VPN = vpn.OpenVPN
		servers[i].TCP = true
		servers[i].UDP = true
		servers[i].IPs = hostToIPs[servers[i].Hostname]
	}

	sort.Sort(models.SortableServers(servers))

	return servers, nil
}

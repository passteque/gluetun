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
	servers, err = fetchServers(ctx, u.client, u.warner)
	if err != nil {
		return nil, fmt.Errorf("fetching servers: %w", err)
	} else if len(servers) < minServers {
		return nil, fmt.Errorf("%w: %d and expected at least %d",
			common.ErrNotEnoughServers, len(servers), minServers)
	}

	hts := make(hostToServer, len(servers))
	for _, server := range servers {
		hts[server.Hostname] = server
	}

	hosts := hts.toHostsSlice()

	resolveSettings := parallelResolverSettings(hosts)
	hostToIPs, warnings, err := u.parallelResolver.Resolve(ctx, resolveSettings)
	for _, warning := range warnings {
		u.warner.Warn(warning)
	}
	if err != nil {
		return nil, fmt.Errorf("resolving hosts: %w", err)
	}

	hts.adaptWithIPs(hostToIPs)

	if len(hts) < minServers {
		return nil, fmt.Errorf("%w: %d and expected at least %d",
			common.ErrNotEnoughServers, len(hts), minServers)
	}

	servers = hts.toServersSlice()

	for i := range servers {
		servers[i].VPN = vpn.OpenVPN
		servers[i].UDP = true
	}

	sort.Sort(models.SortableServers(servers))

	return servers, nil
}

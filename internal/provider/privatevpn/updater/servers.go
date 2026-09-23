package updater

import (
	"context"
	"fmt"
	"net/netip"
	"sort"

	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/common"
)

func (u *Updater) FetchServers(ctx context.Context, minServers int) (
	servers []models.Server, err error,
) {
	servers, warnings, err := fetchServersFromWebsite(ctx, u.client)
	if err != nil {
		return nil, err
	}
	for _, warning := range warnings {
		u.warner.Warn(warning)
	}

	if len(servers) < minServers {
		return nil, fmt.Errorf("%w: %d and expected at least %d",
			common.ErrNotEnoughServers, len(servers), minServers)
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
		return nil, err
	}

	servers = applyIPsToServers(servers, hostToIPs)

	if len(servers) < minServers {
		return nil, fmt.Errorf("%w: %d and expected at least %d",
			common.ErrNotEnoughServers, len(servers), minServers)
	}

	sort.Sort(models.SortableServers(servers))

	return servers, nil
}

func applyIPsToServers(servers []models.Server, hostToIPs map[string][]netip.Addr) (
	result []models.Server,
) {
	result = make([]models.Server, 0, len(servers))
	for _, server := range servers {
		if len(server.Hostname) > 0 {
			if ips, ok := hostToIPs[server.Hostname]; ok {
				server.IPs = ips
				result = append(result, server)
			}
			// Servers with unresolved hostnames are dropped silently
		} else {
			// Servers without hostnames (shouldn't happen with the new approach)
			result = append(result, server)
		}
	}
	return result
}

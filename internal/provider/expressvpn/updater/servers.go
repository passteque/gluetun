package updater

import (
	"context"
	"fmt"
	"sort"

	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/common"
)

func (u *Updater) FetchServers(ctx context.Context, minServers int) (
	servers []models.Server, err error,
) {
	servers, warnings, err := fetchServersFromWebsite(ctx, u.httpClient)
	for _, warning := range warnings {
		u.warner.Warn(warning)
	}
	if err != nil {
		return nil, fmt.Errorf("fetching servers: %w", err)
	}

	// Generate candidate hostnames for each location
	serverToCandidateHostnames := make(map[*models.Server][]string, len(servers))
	var allCandidateHostnames []string
	for _, server := range servers {
		candidateHostnames, err := generateCandidateHostnames(server)
		if err != nil {
			u.warner.Warn(fmt.Sprintf("generating candidate hostnames for %s - %s: %s",
				server.Country, server.City, err))
			continue
		}
		serverToCandidateHostnames[&server] = candidateHostnames
		allCandidateHostnames = append(allCandidateHostnames, candidateHostnames...)
	}

	// Resolve all candidate hostnames in parallel
	resolveSettings := parallelResolverSettings(allCandidateHostnames)
	hostToIPs, _, err := u.parallelResolver.Resolve(ctx, resolveSettings)
	// Ignore resolution warnings since we are mostly bruteforcing DNS records
	// so most candidate hostnames will fail resolving.
	if err != nil {
		return nil, fmt.Errorf("resolving hostnames: %w", err)
	}

	foundServers := make([]models.Server, 0, len(servers))
	for server, candidateHostnames := range serverToCandidateHostnames {
		success := false
		for _, candidate := range candidateHostnames {
			ips := hostToIPs[candidate]
			if len(ips) > 0 {
				success = true
				workingServer := *server
				workingServer.Hostname = candidate
				workingServer.IPs = ips
				foundServers = append(foundServers, workingServer)
			}
		}
		if success {
			continue
		}

		// Log a warning on the bad server location that did not resolve any IPs
		serverName := server.Country
		if server.City != "" {
			serverName += " - " + server.City
		}
		if server.Number > 0 {
			serverName += fmt.Sprintf(" (%d)", server.Number)
		}
		u.warner.Warn(fmt.Sprintf("no IPs resolved for %s (tried %v)", serverName, candidateHostnames))
	}

	servers = foundServers

	if len(servers) < minServers {
		return nil, fmt.Errorf("%w: %d and expected at least %d",
			common.ErrNotEnoughServers, len(servers), minServers)
	}

	sort.Sort(models.SortableServers(servers))

	return servers, nil
}

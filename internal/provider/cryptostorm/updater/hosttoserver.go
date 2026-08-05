package updater

import (
	"net/netip"
	"strings"

	"github.com/qdm12/gluetun/internal/models"
)

// hostToServer maps composite keys (hostname/protocol) to servers.
// The hostname portion is used for DNS resolution.
type hostToServer map[string]models.Server

func (hts hostToServer) toUniqueHostsSlice() (hosts []string) {
	seen := make(map[string]struct{}, len(hts))
	hosts = make([]string, 0, len(hts))
	for key := range hts {
		host := extractHost(key)
		if _, ok := seen[host]; !ok {
			seen[host] = struct{}{}
			hosts = append(hosts, host)
		}
	}
	return hosts
}

func (hts hostToServer) adaptWithIPs(hostToIPs map[string][]netip.Addr) {
	for key, server := range hts {
		host := extractHost(key)
		ips, ok := hostToIPs[host]
		if !ok || len(ips) == 0 {
			delete(hts, key)
			continue
		}
		server.IPs = ips
		hts[key] = server
	}
}

func (hts hostToServer) toServersSlice() (servers []models.Server) {
	servers = make([]models.Server, 0, len(hts))
	for _, server := range hts {
		servers = append(servers, server)
	}
	return servers
}

// extractHost returns the hostname from a composite key like "host.example.com/wg".
func extractHost(key string) string {
	if idx := strings.LastIndex(key, "/"); idx >= 0 {
		return key[:idx]
	}
	return key
}

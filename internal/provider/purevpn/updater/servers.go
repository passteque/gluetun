package updater

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/qdm12/dns/v2/pkg/plain"
	"github.com/qdm12/dns/v2/pkg/provider"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/common"
	"github.com/qdm12/gluetun/internal/updater/resolver"
)

func (u *Updater) FetchServers(ctx context.Context, minServers int) (
	servers []models.Server, err error,
) {
	if !u.ipFetcher.CanFetchAnyIP() {
		return nil, fmt.Errorf("IP fetcher %s does not support fetching any IP", u.ipFetcher.String())
	}

	debURL, err := fetchDebURL(ctx, u.client)
	if err != nil {
		return nil, fmt.Errorf("fetching .deb URL: %w", err)
	}

	debContent, err := fetchURL(ctx, u.client, debURL)
	if err != nil {
		return nil, fmt.Errorf("fetching PureVPN .deb file %q: %w", debURL, err)
	}

	asarContent, err := extractAsarFromDeb(debContent)
	if err != nil {
		return nil, fmt.Errorf("extracting app.asar from .deb: %w", err)
	}

	endpointsContent, endpointsPath, err := extractFirstFileFromAsar(asarContent,
		inventoryEndpointsAsarPath,
		"node_modules/atom-sdk/node_modules/inventory/node_modules/utils/lib/constants/end-points.js")
	if err != nil {
		return nil, fmt.Errorf("extracting inventory endpoints file from app.asar: %w", err)
	}

	inventoryURLTemplate, err := parseInventoryURLTemplate(endpointsContent)
	if err != nil {
		return nil, fmt.Errorf("parsing inventory URL template from %q: %w", endpointsPath, err)
	}

	offlineInventoryContent, offlineInventoryPath, err := extractFirstFileFromAsar(asarContent,
		inventoryOfflineAsarPath,
		"node_modules/atom-sdk/node_modules/inventory/src/offline-data/inventory-data.js")
	if err != nil {
		return nil, fmt.Errorf("extracting inventory offline data from app.asar: %w", err)
	}

	resellerUID, err := parseResellerUIDFromInventoryOffline(offlineInventoryContent)
	if err != nil {
		return nil, fmt.Errorf("parsing reseller UID from %q: %w", offlineInventoryPath, err)
	}

	inventoryURL, err := buildInventoryURL(inventoryURLTemplate, resellerUID)
	if err != nil {
		return nil, fmt.Errorf("building inventory URL: %w", err)
	}

	inventoryContent, err := fetchURL(ctx, u.client, inventoryURL)
	if err != nil {
		return nil, fmt.Errorf("fetching inventory JSON %q: %w", inventoryURL, err)
	}

	hts, hostToFallbackIPs, err := parseInventoryJSON(inventoryContent)
	if err != nil {
		return nil, fmt.Errorf("parsing inventory JSON from %q: %w", inventoryURL, err)
	}

	localDataContent, err := extractFileFromAsar(asarContent, localDataAsarPath)
	if err != nil {
		u.warner.Warn(fmt.Sprintf("extracting app-bundled local data from app.asar: %v", err))
	} else {
		localHTS, parseErr := parseLocalData(localDataContent)
		if parseErr != nil {
			u.warner.Warn(fmt.Sprintf("parsing app-bundled local data: %v", parseErr))
		} else {
			mergeHostToServer(hts, localHTS)
		}

		localFallbackIPs := parseLocalDataFallbackIPs(localDataContent)
		hostToFallbackIPs = mergeHostToFallbackIPs(hostToFallbackIPs, localFallbackIPs)
	}

	if len(hts) < minServers {
		return nil, fmt.Errorf("%w: %d and expected at least %d",
			common.ErrNotEnoughServers, len(hts), minServers)
	}

	hosts := hts.toHostsSlice()
	resolveSettings := parallelResolverSettings(hosts)
	hostToIPs, warnings, err := resolveWithMultipleResolvers(ctx, u.parallelResolver, resolveSettings)
	warnAll(u.warner, warnings)
	if err != nil {
		return nil, err
	}

	applyFallbackIPs(hostToIPs, hostToFallbackIPs, hosts)

	if len(hostToIPs) < minServers {
		return nil, fmt.Errorf("%w: %d and expected at least %d",
			common.ErrNotEnoughServers, len(hostToIPs), minServers)
	}

	hts.adaptWithIPs(hostToIPs)

	servers = hts.toServersSlice()

	for i := range servers {
		country, city, warnings := parseHostname(servers[i].Hostname)
		for _, warning := range warnings {
			u.warner.Warn(warning)
		}
		servers[i].Country = country
		servers[i].City = city
	}

	enrichLocationBlanks(ctx, u.ipFetcher, u.warner, servers)

	sort.Sort(models.SortableServers(servers))

	return servers, nil
}

func enrichLocationBlanks(ctx context.Context, ipFetcher common.IPFetcher,
	warner common.Warner, servers []models.Server,
) {
	for i := range servers {
		if !needsGeolocationEnrichment(servers[i]) || len(servers[i].IPs) == 0 {
			continue
		}

		result, err := ipFetcher.FetchInfo(ctx, servers[i].IPs[0])
		if err != nil {
			warner.Warn(fmt.Sprintf("fetching geolocation for %s (%s): %v",
				servers[i].Hostname, servers[i].IPs[0], err))
			continue
		}

		if !canApplyGeolocationCountry(servers[i].Country, result.Country) {
			warner.Warn(fmt.Sprintf("discarding geolocation for %s (%s): country mismatch %q vs %q",
				servers[i].Hostname, servers[i].IPs[0], servers[i].Country, result.Country))
			continue
		}

		if servers[i].Country == "" {
			servers[i].Country = strings.TrimSpace(result.Country)
		}
		if servers[i].Region == "" {
			servers[i].Region = strings.TrimSpace(result.Region)
		}
		if servers[i].City == "" {
			servers[i].City = strings.TrimSpace(result.City)
		}
	}
}

func needsGeolocationEnrichment(server models.Server) bool {
	if strings.TrimSpace(server.Country) == "" {
		return true
	}
	if strings.TrimSpace(server.City) != "" {
		return false
	}
	return hostnameHasCityCode(server.Hostname)
}

func hostnameHasCityCode(hostname string) bool {
	twoMinusIndex := strings.Index(hostname, "2-")
	return twoMinusIndex > 2 //nolint:mnd
}

func canApplyGeolocationCountry(inventoryCountry, geolocationCountry string) bool {
	inventoryCountry = strings.TrimSpace(inventoryCountry)
	geolocationCountry = strings.TrimSpace(geolocationCountry)
	if inventoryCountry == "" || geolocationCountry == "" {
		return true
	}
	return strings.EqualFold(inventoryCountry, geolocationCountry)
}

func mergeHostToServer(base, overlay hostToServer) {
	for host, server := range overlay {
		if server.TCP {
			if len(server.TCPPorts) == 0 {
				base.add(host, true, false, 0, false)
			} else {
				for _, port := range server.TCPPorts {
					base.add(host, true, false, port, false)
				}
			}
		}
		if server.UDP {
			if len(server.UDPPorts) == 0 {
				base.add(host, false, true, 0, false)
			} else {
				for _, port := range server.UDPPorts {
					base.add(host, false, true, port, false)
				}
			}
		}
	}
}

func mergeHostToFallbackIPs(base, overlay map[string][]netip.Addr) map[string][]netip.Addr {
	if len(overlay) == 0 {
		return base
	}
	if base == nil {
		base = make(map[string][]netip.Addr)
	}
	for host, ips := range overlay {
		for _, ip := range ips {
			base[host] = appendIPIfMissing(base[host], ip)
		}
	}
	return base
}

func resolveWithMultipleResolvers(ctx context.Context, primary common.ParallelResolver,
	settings resolver.ParallelSettings,
) (hostToIPs map[string][]netip.Addr, warnings []string, err error) {
	hostToIPs = make(map[string][]netip.Addr, len(settings.Hosts))

	mergeResult := func(newHostToIPs map[string][]netip.Addr) {
		for host, ips := range newHostToIPs {
			existing := hostToIPs[host]
			for _, ip := range ips {
				existing = appendIPIfMissing(existing, ip)
			}
			hostToIPs[host] = existing
		}
	}

	primaryHostToIPs, primaryWarnings, primaryErr := primary.Resolve(ctx, settings)
	warnings = append(warnings, primaryWarnings...)
	if primaryErr == nil {
		mergeResult(primaryHostToIPs)
	} else {
		warnings = append(warnings, primaryErr.Error())
	}

	// Try multiple DNS resolvers to recover hosts that are flaky or resolver-specific.
	for _, dnsProvider := range []provider.Provider{provider.Google(), provider.Cloudflare(), provider.Quad9()} {
		dialer, err := plain.New(plain.Settings{
			UpstreamResolvers: []provider.Provider{dnsProvider},
		})
		if err != nil {
			return nil, warnings, fmt.Errorf("creating plain resolver: %w", err)
		}
		parallelResolver := resolver.NewParallelResolver(dialer)
		hostToIPsCandidate, candidateWarnings, candidateErr := parallelResolver.Resolve(ctx, settings)
		warnings = append(warnings, candidateWarnings...)
		if candidateErr != nil {
			warnings = append(warnings, candidateErr.Error())
			continue
		}
		mergeResult(hostToIPsCandidate)
	}

	if len(hostToIPs) == 0 {
		return nil, warnings, fmt.Errorf("%w", common.ErrNotEnoughServers)
	}

	return hostToIPs, warnings, nil
}

func applyFallbackIPs(hostToIPs map[string][]netip.Addr, hostToFallbackIPs map[string][]netip.Addr, hosts []string) {
	if len(hostToFallbackIPs) == 0 {
		return
	}
	for _, host := range hosts {
		if len(hostToIPs[host]) > 0 {
			continue
		}
		fallbackIPs := hostToFallbackIPs[host]
		if len(fallbackIPs) == 0 {
			continue
		}
		hostToIPs[host] = append([]netip.Addr(nil), fallbackIPs...)
	}
}

func warnAll(warner common.Warner, warnings []string) {
	for _, warning := range warnings {
		warner.Warn(warning)
	}
}

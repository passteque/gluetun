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

const (
	asarUtilsEndpointsPath     = "node_modules/atom-sdk/node_modules/utils/lib/constants/end-points.js"
	asarInventoryEndpointsPath = "node_modules/atom-sdk/node_modules/inventory/lib/constants/end-points.js"
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
		asarUtilsEndpointsPath, asarInventoryEndpointsPath)
	if err != nil {
		return nil, fmt.Errorf("extracting inventory endpoints file from app.asar: %w", err)
	}

	inventoryURLTemplate, err := parseInventoryURLTemplate(endpointsContent)
	if err != nil {
		return nil, fmt.Errorf("parsing inventory URL template from %q: %w", endpointsPath, err)
	}

	offlineInventoryContent, offlineInventoryPath, err := extractFirstFileFromAsar(asarContent,
		asarLibInventoryDataPath, asarSrcInventoryDataPath)
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

	hts, err := parseInventoryJSON(inventoryContent)
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
			hts.mergeWith(localHTS)
		}

		localFallbackIPs := parseLocalDataFallbackIPs(localDataContent)
		const override = false // prefer IPs found in [parseInventoryJSON] over IPs found in [parseLocalDataFallbackIPs]
		hts.adaptWithIPs(localFallbackIPs, override)
	}

	if len(hts) < minServers {
		return nil, fmt.Errorf("%w: %d and expected at least %d",
			common.ErrNotEnoughServers, len(hts), minServers)
	}

	hosts := hts.toHostsSlice()
	resolveSettings := parallelResolverSettings(hosts)
	hostToIPs, warnings, err := resolveWithMultipleResolvers(ctx, u.parallelResolver, resolveSettings)
	for _, warning := range warnings {
		u.warner.Warn(warning)
	}
	if err != nil {
		return nil, err
	}

	// prefer IPs found in [resolveWithMultipleResolvers] over IPs found either in
	// [parseInventoryJSON] or [parseLocalDataFallbackIPs]
	const override = true
	hts.adaptWithIPs(hostToIPs, override)

	for host, server := range hts {
		if len(server.IPs) == 0 {
			delete(hts, host)
		}
	}

	if len(hts) < minServers {
		return nil, fmt.Errorf("%w: %d and expected at least %d",
			common.ErrNotEnoughServers, len(hts), minServers)
	}

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

func resolveWithMultipleResolvers(ctx context.Context, primary common.ParallelResolver,
	settings resolver.ParallelSettings,
) (hostToIPs map[string][]netip.Addr, warnings []string, err error) {
	hostToIPs = make(map[string][]netip.Addr, len(settings.Hosts))

	mergeResult := func(newHostToIPs map[string][]netip.Addr) {
		for host, ips := range newHostToIPs {
			existing := hostToIPs[host]
			for _, ip := range ips {
				existing = appendIfMissing(existing, ip)
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

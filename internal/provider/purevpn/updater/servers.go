package updater

import (
	"bytes"
	"context"
	"fmt"
	"sort"

	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/common"
)

func (u *Updater) FetchServers(ctx context.Context, minServers int) (
	servers []models.Server, err error,
) {
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

	const (
		asarUtilsEndpointsPath     = "node_modules/atom-sdk/node_modules/utils/lib/constants/end-points.js"
		asarInventoryEndpointsPath = "node_modules/atom-sdk/node_modules/inventory/lib/constants/end-points.js"
	)
	endpointsContent, endpointsPath, err := extractFirstFileFromAsar(asarContent,
		asarUtilsEndpointsPath, asarInventoryEndpointsPath)
	if err != nil {
		return nil, fmt.Errorf("extracting inventory endpoints file from app.asar: %w", err)
	}

	inventoryURLTemplate, err := parseInventoryURLTemplate(endpointsContent)
	if err != nil {
		return nil, fmt.Errorf("parsing inventory URL template from %q: %w", endpointsPath, err)
	}

	const (
		asarSrcInventoryDataPath = "node_modules/atom-sdk/node_modules/inventory/src/offline-data/inventory-data.js"
		asarLibInventoryDataPath = "node_modules/atom-sdk/node_modules/inventory/lib/offline-data/inventory-data.js"
	)
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

	hts, err := parseInventoryJSON(bytes.NewReader(inventoryContent))
	if err != nil {
		return nil, fmt.Errorf("parsing inventory JSON from %q: %w", inventoryURL, err)
	}

	localDataContent, err := extractFileFromAsar(asarContent, localDataAsarPath)
	if err != nil {
		u.logger.Warn(fmt.Sprintf("extracting app-bundled local data from app.asar: %v", err))
	} else {
		localHTS, parseErr := parseLocalData(localDataContent)
		if parseErr != nil {
			u.logger.Warn(fmt.Sprintf("parsing app-bundled local data: %v", parseErr))
		} else {
			hts.mergeWithFallback(localHTS)
		}
	}

	if len(hts) < minServers {
		return nil, fmt.Errorf("%w: %d and expected at least %d",
			common.ErrNotEnoughServers, len(hts), minServers)
	}

	hosts := hts.toHostsSlice()
	resolveSettings := parallelResolverSettings(hosts)
	hostToIPs, warnings, err := u.parallelResolver.Resolve(ctx, resolveSettings)
	for _, warning := range warnings {
		u.logger.Warn(warning)
	}
	if err != nil {
		return nil, err
	}

	// override IPs with the ones found in [resolveWithMultipleResolvers]
	hts.adaptWithIPs(hostToIPs)

	if len(hts) < minServers {
		return nil, fmt.Errorf("%w: %d and expected at least %d",
			common.ErrNotEnoughServers, len(hts), minServers)
	}

	servers = hts.toServersSlice()

	for i := 0; i < len(servers); i++ {
		country, city, warnings := parseHostname(servers[i].Hostname)
		for _, warning := range warnings {
			u.logger.Warn(warning)
		}
		if country == "" && city == "" {
			servers[i], servers[len(servers)-1] = servers[len(servers)-1], servers[i]
			servers = servers[:len(servers)-1]
			i--
			continue
		}
		servers[i].Country = country
		servers[i].City = city
		servers[i].Region = getRegionFromCountryCity(country, city) // TODO v4: retro-compatibility, remove this
	}

	sort.Sort(models.SortableServers(servers))

	return servers, nil
}

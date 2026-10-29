package updater

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/common"
)

var errFileNotFound = errors.New("file not found in the application archive")

func (u *Updater) FetchServers(ctx context.Context, minServers int) (
	servers []models.Server, err error,
) {
	debURL, err := fetchDebURL(ctx, u.client)
	if err != nil {
		return nil, fmt.Errorf("fetching .deb URL: %w", err)
	}

	debBody, err := fetchURL(ctx, u.client, debURL, "cloudfront.net", "purevpn.com")
	if err != nil {
		return nil, fmt.Errorf("fetching PureVPN .deb file: %w", err)
	}
	defer debBody.Close()

	// The file layout of the Electron application archive varies between
	// PureVPN application versions, hence the several candidate paths.
	const (
		appEndpointsPath        = "node_modules/atom-sdk/node_modules/utils/lib/constants/end-points.js"
		inventoryEndpointsPath  = "node_modules/atom-sdk/node_modules/inventory/lib/constants/end-points.js"
		inventoryOfflinePath    = "node_modules/atom-sdk/node_modules/inventory/lib/offline-data/inventory-data.js"
		inventoryOfflineSrcPath = "node_modules/atom-sdk/node_modules/inventory/src/offline-data/inventory-data.js"
	)
	files, err := extractFilesFromDeb(debBody,
		appEndpointsPath, inventoryEndpointsPath,
		inventoryOfflinePath, inventoryOfflineSrcPath, localDataAsarPath)
	if err != nil {
		return nil, fmt.Errorf("extracting files from PureVPN .deb file: %w", err)
	}

	endpointsContent, endpointsPath, err := firstFile(files,
		appEndpointsPath, inventoryEndpointsPath)
	if err != nil {
		return nil, fmt.Errorf("extracting inventory endpoints: %w", err)
	}

	inventoryURLTemplate, err := parseInventoryURLTemplate(endpointsContent)
	if err != nil {
		return nil, fmt.Errorf("parsing inventory URL template from %q: %w", endpointsPath, err)
	}

	offlineContent, offlinePath, err := firstFile(files,
		inventoryOfflinePath, inventoryOfflineSrcPath)
	if err != nil {
		return nil, fmt.Errorf("extracting inventory offline data: %w", err)
	}

	resellerUID, err := parseResellerUIDFromInventoryOffline(offlineContent)
	if err != nil {
		return nil, fmt.Errorf("parsing reseller UID from %q: %w", offlinePath, err)
	}

	inventoryURL, err := buildInventoryURL(inventoryURLTemplate, resellerUID)
	if err != nil {
		return nil, fmt.Errorf("building inventory URL: %w", err)
	}

	inventoryBody, err := fetchURL(ctx, u.client, inventoryURL, "s3.serverwild.com", "purevpn.com")
	if err != nil {
		return nil, fmt.Errorf("fetching inventory JSON: %w", err)
	}
	defer inventoryBody.Close()

	hts, err := parseInventoryJSON(inventoryBody)
	if err != nil {
		return nil, fmt.Errorf("parsing inventory JSON from %q: %w", inventoryURL, err)
	}

	localHTS, err := parseLocalDataFromFiles(files)
	if err != nil {
		return nil, fmt.Errorf("parsing app-bundled local data: %w", err)
	}
	hts.mergeWithFallback(localHTS)

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

	hts.adaptWithIPs(hostToIPs)

	if len(hts) < minServers {
		return nil, fmt.Errorf("%w: %d and expected at least %d",
			common.ErrNotEnoughServers, len(hts), minServers)
	}

	servers = u.withLocations(hts.toServersSlice())

	sort.Sort(models.SortableServers(servers))

	return servers, nil
}

// withLocations sets the country and region of each server based on the
// location codes contained in its hostname, keeping the city from the
// inventory if the hostname does not contain one, and discards any server
// for which no location could be found.
func (u *Updater) withLocations(servers []models.Server) (kept []models.Server) {
	kept = make([]models.Server, 0, len(servers))
	for _, server := range servers {
		country, hostCity, warnings := parseHostname(server.Hostname)
		for _, warning := range warnings {
			u.logger.Warn(warning)
		}
		if country == "" && server.City == "" {
			continue
		}
		server.Country = country
		if server.City == "" {
			server.City = hostCity
		}
		// TODO v4: retro-compatibility, remove this
		server.Region = getRegionFromCountryCity(country, server.City)
		kept = append(kept, server)
	}
	return kept
}

// firstFile returns the content of the first path present in the files,
// along with the path used.
func firstFile(files map[string][]byte, paths ...string) (content []byte, usedPath string, err error) {
	for _, path := range paths {
		content, ok := files[path]
		if ok {
			return content, path, nil
		}
	}
	return nil, "", fmt.Errorf("%w: none of %q", errFileNotFound, paths)
}

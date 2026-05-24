package updater

import (
	"context"
	"fmt"
	"sort"

	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/common"
)

func (u *Updater) FetchServers(ctx context.Context, minServers int) (
	servers []models.Server, err error,
) {
	switch {
	case u.email == "":
		return nil, fmt.Errorf("%w: email is empty", common.ErrCredentialsMissing)
	case u.password == "":
		return nil, fmt.Errorf("%w: password is empty", common.ErrCredentialsMissing)
	}

	apiClient, err := newAPIClient(ctx, u.client, u.warner)
	if err != nil {
		return nil, fmt.Errorf("creating API client: %w", err)
	}

	cookie, err := apiClient.authenticate(ctx, u.email, u.password)
	if err != nil {
		return nil, fmt.Errorf("authentifying with Proton: %w", err)
	}

	data, err := apiClient.fetchServers(ctx, cookie)
	if err != nil {
		return nil, fmt.Errorf("fetching logical servers: %w", err)
	}

	countryCodes := constants.CountryCodes()

	var count int
	for _, logicalServer := range data.LogicalServers {
		count += len(logicalServer.Servers)
	}

	if count < minServers {
		return nil, fmt.Errorf("%w: %d and expected at least %d",
			common.ErrNotEnoughServers, count, minServers)
	}

	ipToServer := make(ipToServers, count)
	for _, logicalServer := range data.LogicalServers {
		region := getStringValue(logicalServer.Region)
		city := getStringValue(logicalServer.City)
		// TODO v4 remove `name` field because of
		// https://github.com/qdm12/gluetun/issues/1018#issuecomment-1151750179
		name := logicalServer.Name

		//nolint:lll
		// See https://github.com/ProtonVPN/protonvpn-nm-lib/blob/31d5f99fbc89274e4e977a11e7432c0eab5a3ef8/protonvpn_nm_lib/enums.py#L44-L49
		featuresBits := logicalServer.Features
		features := features{
			secureCore: featuresBits&1 != 0,
			tor:        featuresBits&2 != 0,
			p2p:        featuresBits&4 != 0,
			stream:     featuresBits&8 != 0,
			// ipv6: featuresBits&16 != 0, - unused.
		}

		//nolint:lll
		// See https://github.com/ProtonVPN/protonvpn-nm-lib/blob/31d5f99fbc89274e4e977a11e7432c0eab5a3ef8/protonvpn_nm_lib/enums.py#L56-L62
		free := false
		if logicalServer.Tier == nil {
			u.warner.Warn("tier field not set for server " + logicalServer.Name)
		} else if *logicalServer.Tier == 0 {
			free = true
		}

		for _, physicalServer := range logicalServer.Servers {
			if physicalServer.Status == 0 { // disabled so skip server
				u.warner.Warn("ignoring server " + physicalServer.Domain + " with status 0")
				continue
			}

			hostname := physicalServer.Domain
			entryIP := physicalServer.EntryIP
			wgPubKey := physicalServer.X25519PublicKey

			// Note: for multi-hop use the server name or hostname
			// instead of the country
			countryCode := logicalServer.ExitCountry
			country, warning := codeToCountry(countryCode, countryCodes)
			if warning != "" {
				u.warner.Warn(warning)
			}

			ipToServer.add(country, region, city, name, hostname, wgPubKey, free, entryIP, features)
		}
	}

	if ipToServer.numberOfServers() < minServers {
		return nil, fmt.Errorf("%w: %d and expected at least %d",
			common.ErrNotEnoughServers, len(ipToServer), minServers)
	}

	servers = ipToServer.toServersSlice()

	sort.Sort(models.SortableServers(servers))

	return servers, nil
}

func getStringValue(ptr *string) string {
	if ptr == nil {
		return ""
	}
	return *ptr
}

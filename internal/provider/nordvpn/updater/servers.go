package updater

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/common"
)

func (u *Updater) FetchServers(ctx context.Context, minServers int) (
	servers []models.Server, err error,
) {
	const limit = 0
	data, err := fetchAPI(ctx, u.client, limit)
	if err != nil {
		return nil, err
	}

	servers = make([]models.Server, 0, len(data.Servers))
	groups, services, locations, technologies := data.idToData()

	for _, jsonServer := range data.Servers {
		newServers, warnings := extractServers(jsonServer, groups, services, locations, technologies)
		for _, warning := range warnings {
			u.warner.Warn(warning)
		}
		servers = append(servers, newServers...)
	}

	if len(servers) < minServers {
		return nil, fmt.Errorf("%w: %d and expected at least %d",
			common.ErrNotEnoughServers, len(servers), minServers)
	}

	sort.Sort(models.SortableServers(servers))

	return servers, nil
}

func extractServers(jsonServer serverData, groups map[uint32]groupData,
	services map[uint32]serviceData, locations map[uint32]locationData,
	technologies map[uint32]technologyData) (servers []models.Server,
	warnings []string,
) {
	ignoreReason := ""
	switch {
	case jsonServer.Status != "online":
		ignoreReason = "status is " + jsonServer.Status
	case len(jsonServer.LocationIDs) == 0:
		ignoreReason = "no location"
	case len(jsonServer.IPs) == 0:
		ignoreReason = "no IP address"
	case !jsonServer.hasVPNService(services):
		ignoreReason = "no VPN service"
	}
	if ignoreReason != "" {
		warning := fmt.Sprintf("ignoring server %s: %s", jsonServer.Name, ignoreReason)
		return nil, []string{warning}
	}

	location, ok := locations[jsonServer.LocationIDs[0]]
	if !ok {
		warning := fmt.Sprintf("location with id %d not found in %v",
			jsonServer.LocationIDs[0], locations)
		return nil, []string{warning}
	}

	region := jsonServer.region(groups)
	if region == "" {
		warning := fmt.Sprintf("no region found for server %s", jsonServer.Name)
		return nil, []string{warning}
	}

	server := models.Server{
		Country:    location.Country.Name,
		Region:     region,
		City:       location.Country.City.Name,
		Categories: jsonServer.categories(groups),
		Hostname:   jsonServer.Hostname,
		IPs:        jsonServer.ips(),
	}

	number, err := parseServerName(jsonServer.Name)
	switch {
	case errors.Is(err, ErrNoIDInServerName):
		warning := fmt.Sprintf("%s - leaving server number as 0", err)
		warnings = append(warnings, warning)
	case err != nil:
		warning := fmt.Sprintf("failed parsing server name: %s", err)
		return nil, []string{warning}
	default: // no error
		server.Number = number
	}

	var wireguardFound, openvpnFound bool
	wireguardServer := server
	wireguardServer.VPN = vpn.Wireguard
	openVPNServer := server // accumulate UDP+TCP technologies
	openVPNServer.VPN = vpn.OpenVPN

	for _, technology := range jsonServer.Technologies {
		if technology.Status != "online" {
			continue
		}
		technologyData, ok := technologies[technology.ID]
		if !ok {
			warning := fmt.Sprintf("technology with id %d not found in %v",
				technology.ID, technologies)
			warnings = append(warnings, warning)
			continue
		}

		switch technologyData.Identifier {
		case "openvpn_udp", "openvpn_dedicated_udp":
			openvpnFound = true
			openVPNServer.UDP = true
		case "openvpn_tcp", "openvpn_dedicated_tcp":
			openvpnFound = true
			openVPNServer.TCP = true
		case "wireguard_udp":
			wireguardFound = true
			wireguardServer.WgPubKey, err = jsonServer.wireguardPublicKey(technologies)
			if err != nil {
				warning := fmt.Sprintf("ignoring Wireguard server %s: %s", jsonServer.Name, err)
				warnings = append(warnings, warning)
				wireguardFound = false
				continue
			}
		default: // Ignore other technologies
			continue
		}
	}

	const maxServers = 2
	servers = make([]models.Server, 0, maxServers)
	if openvpnFound {
		servers = append(servers, openVPNServer)
	}
	if wireguardFound {
		servers = append(servers, wireguardServer)
	}

	return servers, warnings
}

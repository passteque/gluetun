package storage

import (
	"errors"
	"fmt"
	"strings"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
)

// FilterServers filter servers for the given provider and according
// to the given selection. The filtered servers are deep copied so they
// are safe for mutation by the caller.
func (s *Storage) FilterServers(provider string, selection settings.ServerSelection) (
	servers []models.Server, err error,
) {
	if provider == providers.Custom {
		return nil, nil
	}

	s.mergedMutex.RLock()
	defer s.mergedMutex.RUnlock()

	serversObject := s.getMergedServersObject(provider)
	allServers := serversObject.Servers

	if len(allServers) == 0 {
		return nil, errors.New("no server found")
	}

	for _, server := range allServers {
		if filterServer(server, selection) {
			continue
		}

		server = copyServer(server)
		servers = append(servers, server)
	}

	if len(servers) == 0 {
		return nil, noServerFoundError(selection)
	}

	return servers, nil
}

func filterServer(server models.Server,
	selection settings.ServerSelection,
) (filtered bool) {
	// Note each condition is split to make sure
	// we have full testing coverage.
	if server.VPN != selection.VPN {
		return true
	}

	if server.VPN != vpn.Wireguard &&
		filterByProtocol(selection, server.TCP, server.UDP) {
		return true
	}

	if *selection.MultiHopOnly && !server.MultiHop {
		return true
	}

	if *selection.FreeOnly && !server.Free {
		return true
	}

	if *selection.StreamOnly && !server.Stream {
		return true
	}

	if *selection.OwnedOnly && !server.Owned {
		return true
	}

	if *selection.PortForwardOnly && !server.PortForward {
		return true
	}

	if *selection.SecureCoreOnly && !server.SecureCore {
		return true
	}

	if *selection.TorOnly && !server.Tor {
		return true
	}

	if filterByPossibilities(server.Country, selection.Countries) {
		return true
	}

	if filterAnyByPossibilities(server.Categories, selection.Categories) {
		return true
	}

	if filterByPossibilities(server.Region, selection.Regions) {
		return true
	}

	if filterByPossibilities(server.City, selection.Cities) {
		return true
	}

	if filterByPossibilities(server.ISP, selection.ISPs) {
		return true
	}

	if filterByPossibilities(server.Number, selection.Numbers) {
		return true
	}

	if filterByPossibilities(server.ServerName, selection.Names) {
		return true
	}

	if filterByPossibilities(server.Hostname, selection.Hostnames) {
		return true
	}

	// TODO filter port forward server for PIA

	return false
}

func filterByPossibilities[T string | uint16](value T, possibilities []T) (filtered bool) {
	if len(possibilities) == 0 {
		return false
	}
	for _, possibility := range possibilities {
		if strings.EqualFold(fmt.Sprint(value), fmt.Sprint(possibility)) {
			return false
		}
	}
	return true
}

func filterAnyByPossibilities(values, possibilities []string) (filtered bool) {
	if len(possibilities) == 0 {
		return false
	}

	for _, value := range values {
		if !filterByPossibilities(value, possibilities) {
			return false // found a valid value
		}
	}

	return true
}

func filterByProtocol(selection settings.ServerSelection,
	serverTCP, serverUDP bool,
) (filtered bool) {
	switch selection.VPN {
	case vpn.Wireguard:
		return !serverUDP
	default: // OpenVPN
		wantTCP := selection.OpenVPN.Protocol == constants.TCP
		wantUDP := !wantTCP
		return (wantTCP && !serverTCP) || (wantUDP && !serverUDP)
	}
}

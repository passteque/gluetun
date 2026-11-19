package utils

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/models"
)

// sortServersByTier sorts the servers in place by their priority
// tier (i.e. the position of the matching value in the narrowest
// set server selection filter list), then by servers with IPv6
// addresses first.
func sortServersByTier(servers []models.Server,
	selection settings.ServerSelection,
) {
	type tieredServer struct {
		server models.Server
		tier   uint
		ipv6   bool
	}

	tieredServers := make([]tieredServer, len(servers))
	for i, server := range servers {
		tieredServers[i] = tieredServer{
			server: server,
			tier:   selectionTier(server, selection),
			ipv6:   hasIPv6(server),
		}
	}

	ipv6Compare := ipv6First(func(tieredServer tieredServer) bool {
		return tieredServer.ipv6
	})
	slices.SortStableFunc(tieredServers, func(a, b tieredServer) int {
		if cmp := cmp.Compare(a.tier, b.tier); cmp != 0 {
			return cmp
		}
		return ipv6Compare(a, b)
	})

	for i, tieredServer := range tieredServers {
		servers[i] = tieredServer.server
	}
}

// selectionTier returns the priority tier of the server,
// which is the index of the matching value in the narrowest
// set server selection filter list. The narrowness order,
// from the narrowest to the broadest filter list, is:
// hostnames, server names, server numbers, cities, regions,
// countries, ISPs, categories. A server that does not match
// any value of the list gets tier 0.
func selectionTier(server models.Server,
	selection settings.ServerSelection,
) uint {
	switch {
	case len(selection.Hostnames) > 0:
		return matchIndex(server.Hostname, selection.Hostnames)
	case len(selection.Names) > 0:
		return matchIndex(server.ServerName, selection.Names)
	case len(selection.Numbers) > 0:
		return matchIndex(server.Number, selection.Numbers)
	case len(selection.Cities) > 0:
		return matchIndex(server.City, selection.Cities)
	case len(selection.Regions) > 0:
		return matchIndex(server.Region, selection.Regions)
	case len(selection.Countries) > 0:
		return matchIndex(server.Country, selection.Countries)
	case len(selection.ISPs) > 0:
		return matchIndex(server.ISP, selection.ISPs)
	case len(selection.Categories) > 0:
		return matchIndexAny(server.Categories, selection.Categories)
	default:
		return 0
	}
}

// matchIndex returns the index of the first possibility
// matching the value given as argument, case-insensitively,
// or 0 if there is no match.
func matchIndex[T string | uint16](value T, possibilities []T) uint {
	for i, possibility := range possibilities {
		if strings.EqualFold(fmt.Sprint(value), fmt.Sprint(possibility)) {
			return uint(i)
		}
	}
	return 0
}

// matchIndexAny returns the index of the first possibility
// matching any of the values given as argument,
// case-insensitively, or 0 if there is no match.
func matchIndexAny(values, possibilities []string) uint {
	noMatch := uint(len(possibilities))
	bestMatch := noMatch
	for _, value := range values {
		if i := matchIndex(value, possibilities); i < bestMatch {
			bestMatch = i
		}
	}
	if bestMatch == noMatch {
		return 0
	}
	return bestMatch
}

// hasIPv6 returns true if the server has at least one
// IPv6 address.
func hasIPv6(server models.Server) bool {
	for _, ip := range server.IPs {
		if ip.Is6() {
			return true
		}
	}
	return false
}

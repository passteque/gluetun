package updater

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Check out the JSON data from https://api.nordvpn.com/v2/servers?limit=10
type serversData struct {
	Servers      []serverData     `json:"servers"`
	Groups       []groupData      `json:"groups"`
	Services     []serviceData    `json:"services"`
	Locations    []locationData   `json:"locations"`
	Technologies []technologyData `json:"technologies"`
}

type serverData struct {
	// Name is the server name, for example 'Poland #128'
	Name string `json:"name"`
	// Stations is, it seems, the entry IP address.
	// However it is ignored in favor of the 'ips' entry field.
	Station netip.Addr `json:"station"`
	// IPv6Station is mostly empty, so we ignore it for now.
	IPv6Station netip.Addr `json:"station_ipv6"`
	// Hostname is the server hostname, for example 'pl128.nordvpn.com'
	Hostname string `json:"hostname"`
	// Status is the server status, for example 'online'
	Status string `json:"status"`
	// Locations is the list of location IDs for the server.
	// Only the first location is taken into account for now.
	LocationIDs  []uint32 `json:"location_ids"`
	Technologies []struct {
		ID       uint32 `json:"id"`
		Status   string `json:"status"`
		Metadata []struct {
			// Name can notably be 'public_key'.
			Name string `json:"name"`
			// Value can notably the Wireguard public key value.
			Value string `json:"value"`
		} `json:"metadata"`
	} `json:"technologies"`
	GroupIDs   []uint32 `json:"group_ids"`
	ServiceIDs []uint32 `json:"service_ids"`
	// IPs is the list of IP addresses for the server.
	IPs []struct {
		// Type can notably be 'entry'.
		Type string `json:"type"`
		IP   struct {
			IP netip.Addr `json:"ip"`
		} `json:"ip"`
	} `json:"ips"`
}

type groupData struct {
	ID    uint32 `json:"id"`
	Title string `json:"title"` // "Europe", "Standard VPN servers", etc.
	Type  struct {
		Identifier string `json:"identifier"` // 'regions', 'legacy_group_category', etc.
	} `json:"type"`
}

type serviceData struct {
	ID         uint32 `json:"id"`
	Identifier string `json:"identifier"` // 'vpn', 'proxy', etc.
}

type locationData struct {
	ID      uint32 `json:"id"`
	Country struct {
		Name string `json:"name"` // for example "Poland"
		City struct {
			Name string `json:"name"` // for example "Warsaw"
		} `json:"city"`
	} `json:"country"`
}

type technologyData struct {
	ID uint32 `json:"id"`
	// Identifier is the technology identifier name and relevant values are:
	// 'openvpn_udp', 'openvpn_tcp', 'openvpn_dedicated_udp',
	// 'openvpn_dedicated_tcp' and 'wireguard_udp'
	Identifier string `json:"identifier"`
}

func (s serversData) idToData() (
	groups map[uint32]groupData,
	services map[uint32]serviceData,
	locations map[uint32]locationData,
	technologies map[uint32]technologyData,
) {
	groups = make(map[uint32]groupData, len(s.Groups))
	for _, group := range s.Groups {
		if group.Type.Identifier == "regions" { //nolint:goconst
			group.Title = strings.ReplaceAll(group.Title, ",", "")
		}
		groups[group.ID] = group
	}

	services = make(map[uint32]serviceData, len(s.Services))
	for _, service := range s.Services {
		services[service.ID] = service
	}

	locations = make(map[uint32]locationData, len(s.Locations))
	for _, location := range s.Locations {
		locations[location.ID] = location
	}

	technologies = make(map[uint32]technologyData, len(s.Technologies))
	for _, technology := range s.Technologies {
		technologies[technology.ID] = technology
	}

	return groups, services, locations, technologies
}

func (s *serverData) region(groups map[uint32]groupData) (region string) {
	for _, groupID := range s.GroupIDs {
		group, ok := groups[groupID]
		if !ok {
			continue
		}
		if group.Type.Identifier == "regions" {
			return group.Title
		}
	}
	return ""
}

func (s *serverData) hasVPNService(services map[uint32]serviceData) (ok bool) {
	for _, serviceID := range s.ServiceIDs {
		service, ok := services[serviceID]
		if !ok {
			continue
		}
		if service.Identifier == "vpn" {
			return true
		}
	}
	return false
}

// categories returns the list of categories for the server.
func (s *serverData) categories(groups map[uint32]groupData) (categories []string) {
	categories = make([]string, 0, len(s.GroupIDs))
	for _, groupID := range s.GroupIDs {
		data, ok := groups[groupID]
		if !ok || data.Type.Identifier == "regions" {
			continue
		}
		categories = append(categories, data.Title)
	}
	return categories
}

// ips returns the list of IP addresses for the server.
func (s *serverData) ips() (ips []netip.Addr) {
	ips = make([]netip.Addr, 0, len(s.IPs))
	for _, ipObject := range s.IPs {
		if ipObject.Type != "entry" {
			continue
		}
		ips = append(ips, ipObject.IP.IP)
	}
	return ips
}

// wireguardPublicKey returns the Wireguard public key for the server.
func (s *serverData) wireguardPublicKey(technologies map[uint32]technologyData) (
	wgPubKey string, err error,
) {
	for _, technology := range s.Technologies {
		data, ok := technologies[technology.ID]
		if !ok || data.Identifier != "wireguard_udp" {
			continue
		}
		for _, metadata := range technology.Metadata {
			if metadata.Name != "public_key" {
				continue
			}
			wgPubKey = metadata.Value
			_, err = base64.StdEncoding.DecodeString(wgPubKey)
			if err != nil {
				return "", fmt.Errorf("wireguard public key is malformed: %s cannot be decoded: %s", wgPubKey, err)
			}
			return metadata.Value, nil
		}
	}
	return "", errors.New("wireguard public key not found")
}

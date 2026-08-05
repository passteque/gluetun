package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"time"

	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/common"
)

const locationsURL = "https://api.azirevpn.com/v3/locations"

type locationsResponse struct {
	Status    string     `json:"status"`
	Locations []location `json:"locations"`
}

type location struct {
	Name    string `json:"name"`
	City    string `json:"city"`
	Country string `json:"country"`
	ISO     string `json:"iso"`
	Pool    string `json:"pool"`
	PubKey  string `json:"pubkey"`
}

func (u *Updater) FetchServers(ctx context.Context, minServers int) (
	servers []models.Server, err error,
) {
	locations, err := u.fetchLocations(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching locations: %w", err)
	}

	servers = make([]models.Server, 0, len(locations))
	for _, location := range locations {
		hostname := location.Pool
		if hostname == "" {
			u.warner.Warn("location has empty pool, skipping location " + location.Name)
			continue
		}

		ips, resolveErr := resolveIPs(ctx, hostname)
		if resolveErr != nil {
			u.warner.Warn("resolving host " + hostname + ": " + resolveErr.Error())
			continue
		}

		server := models.Server{
			VPN:         vpn.Wireguard,
			Country:     location.Country,
			City:        location.City,
			ServerName:  location.Name,
			Hostname:    hostname,
			WgPubKey:    location.PubKey,
			Owned:       true,
			PortForward: true,
			IPs:         ips,
		}
		servers = append(servers, server)
	}

	if len(servers) < minServers {
		return nil, fmt.Errorf("%w: %d and expected at least %d",
			common.ErrNotEnoughServers, len(servers), minServers)
	}

	sort.Sort(models.SortableServers(servers))

	return servers, nil
}

func (u *Updater) fetchLocations(ctx context.Context) (
	locations []location, err error,
) {
	const timeout = 15 * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, locationsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	if u.token != "" {
		request.Header.Set("Authorization", "Bearer "+u.token)
	}

	response, err := u.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("doing request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status code not OK: %d %s",
			response.StatusCode, response.Status)
	}

	decoder := json.NewDecoder(response.Body)
	var responseData locationsResponse
	err = decoder.Decode(&responseData)
	if err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return responseData.Locations, nil
}

func resolveIPs(ctx context.Context, hostname string) (ips []netip.Addr, err error) {
	lookupIPs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", hostname)
	if err != nil {
		return nil, err
	}

	ipSet := make(map[netip.Addr]struct{}, len(lookupIPs))
	for _, ip := range lookupIPs {
		ipSet[ip.Unmap()] = struct{}{}
	}

	if len(ipSet) == 0 {
		return nil, fmt.Errorf("host %s resolved to no IP addresses", hostname)
	}

	ips = make([]netip.Addr, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		return ips[i].Compare(ips[j]) < 0
	})

	return ips, nil
}

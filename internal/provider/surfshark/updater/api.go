package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/qdm12/gluetun/internal/provider/surfshark/servers"
)

func addServersFromAPI(ctx context.Context, client *http.Client,
	hts hostToServers,
) (err error) {
	data, err := fetchAPI(ctx, client)
	if err != nil {
		return err
	}

	locationData := servers.LocationData()
	hostToLocation := hostToLocation(locationData)

	for _, serverData := range data {
		locationData := hostToLocation[serverData.Host] // TODO remove in v4
		retroLoc := locationData.RetroLoc               // empty string if the host has no retro-compatible region

		tcp, udp := true, true // OpenVPN servers from API supports both TCP and UDP
		hts.addOpenVPN(serverData.Host, serverData.Region, serverData.Country,
			serverData.Location, retroLoc, tcp, udp)

		if serverData.PubKey != "" {
			hts.addWireguard(serverData.Host, serverData.Region, serverData.Country,
				serverData.Location, retroLoc, serverData.PubKey)
		}
	}

	return nil
}

type serverData struct {
	Host     string `json:"connectionName"`
	Region   string `json:"region"`
	Country  string `json:"country"`
	Location string `json:"location"`
	PubKey   string `json:"pubKey"`
}

func fetchAPI(ctx context.Context, client *http.Client) (
	servers []serverData, err error,
) {
	const url = "https://api.surfshark.com/v4/server/clusters"

	for _, clustersType := range [...]string{"generic", "double", "static", "obfuscated"} {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"/"+clustersType, nil)
		if err != nil {
			return nil, err
		}

		response, err := client.Do(request)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()

		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("HTTP status code not OK: %d %s",
				response.StatusCode, response.Status)
		}

		decoder := json.NewDecoder(response.Body)
		var newServers []serverData
		err = decoder.Decode(&newServers)
		if err != nil {
			return nil, fmt.Errorf("decoding response body: %w", err)
		}

		err = response.Body.Close()
		if err != nil {
			return nil, err
		}

		servers = append(servers, newServers...)
	}

	return servers, nil
}

package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type serverData struct {
	Hostname string `json:"hostname"`
	Country  string `json:"country_name"`
	City     string `json:"city_name"`
	Active   bool   `json:"active"`
	Owned    bool   `json:"owned"`
	Provider string `json:"provider"`
	IPv4     string `json:"ipv4_addr_in"`
	IPv6     string `json:"ipv6_addr_in"`
	Type     string `json:"type"`
	PubKey   string `json:"pubkey"` // Wireguard public key
}

func fetchAPI(ctx context.Context, client *http.Client) (data []serverData, err error) {
	const url = "https://api.mullvad.net/www/relays/all/"

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status code not OK: %d %s", response.StatusCode, response.Status)
	}

	decoder := json.NewDecoder(response.Body)
	if err := decoder.Decode(&data); err != nil {
		return nil, fmt.Errorf("failed decoding response body: %s", err)
	}

	if err := response.Body.Close(); err != nil {
		return nil, err
	}

	return data, nil
}

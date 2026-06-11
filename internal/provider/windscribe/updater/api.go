package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"time"
)

type apiData struct {
	Data []regionData `json:"data"`
}

type regionData struct {
	Region string      `json:"name"`
	Groups []groupData `json:"groups"`
}

type groupData struct {
	City     string       `json:"city"`
	Nodes    []serverData `json:"nodes"`
	OvpnX509 string       `json:"ovpn_x509"`
	WgPubKey string       `json:"wg_pubkey"`
}

type serverData struct {
	Hostname string     `json:"hostname"`
	IP       netip.Addr `json:"ip"`
	IP2      netip.Addr `json:"ip2"`
	IP3      netip.Addr `json:"ip3"`
}

func fetchAPI(ctx context.Context, client *http.Client) (
	data apiData, err error,
) {
	const baseURL = "https://assets.windscribe.com/serverlist/mob-v2/1/"
	cacheBreaker := time.Now().Unix()
	url := baseURL + strconv.Itoa(int(cacheBreaker))

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return data, err
	}

	response, err := client.Do(request)
	if err != nil {
		return data, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return data, fmt.Errorf("HTTP status code not OK: %d %s",
			response.StatusCode, response.Status)
	}

	decoder := json.NewDecoder(response.Body)
	if err := decoder.Decode(&data); err != nil {
		return data, fmt.Errorf("decoding response body: %w", err)
	}

	return data, nil
}

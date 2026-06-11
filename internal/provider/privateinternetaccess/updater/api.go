package updater

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
)

type apiData struct {
	Regions []regionData `json:"regions"`
}

type regionData struct {
	Name        string `json:"name"`
	DNS         string `json:"dns"`
	PortForward bool   `json:"port_forward"`
	Offline     bool   `json:"offline"`
	Servers     struct {
		UDP []serverData `json:"ovpnudp"`
		TCP []serverData `json:"ovpntcp"`
	} `json:"servers"`
}

type serverData struct {
	IP netip.Addr `json:"ip"`
	CN string     `json:"cn"`
}

func fetchAPI(ctx context.Context, client *http.Client) (
	data apiData, err error,
) {
	const url = "https://serverlist.piaservers.net/vpninfo/servers/v7"

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

	b, err := io.ReadAll(response.Body)
	if err != nil {
		return data, err
	}

	if err := response.Body.Close(); err != nil {
		return data, err
	}

	// remove key/signature at the bottom
	i := bytes.IndexRune(b, '\n')
	b = b[:i]

	if err := json.Unmarshal(b, &data); err != nil {
		return data, err
	}

	return data, nil
}

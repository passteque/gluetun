package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

func fetchAPI(ctx context.Context, client *http.Client,
	limit uint,
) (data serversData, err error) {
	url := "https://api.nordvpn.com/v2/servers"
	url += fmt.Sprintf("?limit=%d", limit) // 0 means no limit

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return serversData{}, err
	}

	response, err := client.Do(request)
	if err != nil {
		return serversData{}, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return serversData{}, fmt.Errorf("HTTP status code not OK: %s", response.Status)
	}

	decoder := json.NewDecoder(response.Body)
	if err := decoder.Decode(&data); err != nil {
		return serversData{}, fmt.Errorf("decoding response body: %w", err)
	}

	if err := response.Body.Close(); err != nil {
		return serversData{}, err
	}

	return data, nil
}

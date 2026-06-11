package unzip

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

func (u *Unzipper) FetchAndExtract(ctx context.Context, url string) (
	contents map[string][]byte, err error,
) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "gluetun")

	response, err := u.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status code not OK: %s: %d %s",
			url, response.StatusCode, response.Status)
	}

	b, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	if err := response.Body.Close(); err != nil {
		return nil, err
	}

	return zipExtractAll(b)
}

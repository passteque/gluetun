package openvpn

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

func FetchFile(ctx context.Context, client *http.Client, url string) (
	host string, err error,
) {
	b, err := fetchData(ctx, client, url)
	if err != nil {
		return "", err
	}

	const rejectIP = true
	const rejectDomain = false
	hosts := extractRemoteHosts(b, rejectIP, rejectDomain)
	if len(hosts) == 0 {
		return "", fmt.Errorf("remote host not found for url %s", url)
	}

	return hosts[0], nil
}

func fetchData(ctx context.Context, client *http.Client, url string) (
	b []byte, err error,
) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	return io.ReadAll(response.Body)
}

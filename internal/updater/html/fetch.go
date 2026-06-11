package html

import (
	"context"
	"fmt"
	"net/http"

	"golang.org/x/net/html"
)

func Fetch(ctx context.Context, client *http.Client, url string) (
	rootNode *html.Node, err error,
) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating HTTP request: %w", err)
	}

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status code not OK: %d %s",
			response.StatusCode, response.Status)
	}

	rootNode, err = html.Parse(response.Body)
	if err != nil {
		_ = response.Body.Close()
		return nil, fmt.Errorf("parsing HTML code: %w", err)
	}

	err = response.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("closing response body: %w", err)
	}

	return rootNode, nil
}

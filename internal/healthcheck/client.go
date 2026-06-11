package healthcheck

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	httpClient *http.Client
}

func NewClient(httpClient *http.Client) *Client {
	return &Client{
		httpClient: httpClient,
	}
}

func (c *Client) Check(ctx context.Context, url string) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusOK {
		return nil
	}
	b, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	return fmt.Errorf("HTTP response status is not OK: %d %s: %s",
		response.StatusCode, response.Status, string(b))
}

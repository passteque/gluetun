package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// getMostRecentStableTag finds the most recent proton-account stable tag version,
// in order to use it in the x-pm-appversion http request header. Because if we do
// fall behind on versioning, Proton doesn't like it because they like to create
// complications where there is no need for it. Hence this function.
func getMostRecentStableTag(ctx context.Context, client *http.Client) (version string, err error) {
	page := 1
	regexVersion := regexp.MustCompile(`^proton-account@(\d+\.\d+\.\d+\.\d+)$`)
	for ctx.Err() == nil {
		// Define a timeout since the default client has a large timeout and we don't
		// want to wait too long.
		const timeout = 5 * time.Second
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		url := "https://api.github.com/repos/ProtonMail/WebClients/tags?per_page=30&page=" + fmt.Sprint(page)

		request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return "", fmt.Errorf("creating request: %w", err)
		}
		request.Header.Set("Accept", "application/vnd.github.v3+json")

		response, err := client.Do(request)
		if err != nil {
			return "", err
		}
		defer response.Body.Close()

		data, err := io.ReadAll(response.Body)
		if err != nil {
			return "", fmt.Errorf("reading response body: %w", err)
		}

		if response.StatusCode != http.StatusOK {
			return "", fmt.Errorf("HTTP status code not OK: %s: %s", response.Status, data)
		}

		var tags []struct {
			Name string `json:"name"`
		}
		err = json.Unmarshal(data, &tags)
		if err != nil {
			return "", fmt.Errorf("decoding JSON response: %w", err)
		}

		for _, tag := range tags {
			if !regexVersion.MatchString(tag.Name) {
				continue
			}
			version := "web-account@" + strings.TrimPrefix(tag.Name, "proton-account@")
			return version, nil
		}

		page++
	}

	return "", fmt.Errorf("%w (queried %d pages)", context.Canceled, page)
}

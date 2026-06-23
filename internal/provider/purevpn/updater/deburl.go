package updater

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

func fetchDebURL(ctx context.Context, client *http.Client) (debURL string, err error) {
	const url = "https://www.purevpn.com/download/linux-vpn"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}

	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("performing request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("querying %s returned HTTP status code %d", url, response.StatusCode)
	}

	html, err := io.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("reading response body: %w", err)
	}

	debURL, err = extractDebURL(string(html), url)
	if err != nil {
		return "", fmt.Errorf("extracting .deb URLs from download page: %w", err)
	}
	return debURL, nil
}

func fetchURL(ctx context.Context, client *http.Client, rawURL string) (content []byte, err error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("performing request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status code %d", response.StatusCode)
	}

	content, err = io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	return content, nil
}

var (
	debURLPattern  = regexp.MustCompile(`https?://[^"'\s<>]+\.deb`)
	hrefDebPattern = regexp.MustCompile(`href=["']([^"']+\.deb)["']`)
)

func extractDebURL(pageHTML, baseURL string) (debURL string, err error) {
	baseParsed, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parsing base url %q: %w", baseURL, err)
	}

	debURL = debURLPattern.FindString(pageHTML)
	if debURL != "" {
		return debURL, nil
	}

	for _, groups := range hrefDebPattern.FindAllStringSubmatch(pageHTML, -1) {
		const minGroups = 2
		if len(groups) < minGroups {
			continue
		}
		href, err := url.Parse(strings.TrimSpace(groups[1]))
		if err != nil {
			continue
		}
		debURL = baseParsed.ResolveReference(href).String()
		return debURL, nil
	}

	return "", errors.New("no .deb URL found")
}

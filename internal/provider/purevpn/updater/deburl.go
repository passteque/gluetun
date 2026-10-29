package updater

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
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

// fetchURL performs a GET request and returns the response body,
// which the caller is responsible for closing.
// The URL and any redirect URL must be https and have a host that is
// one of the allowed hosts, purevpn.com or a subdomain of purevpn.com.
func fetchURL(ctx context.Context, client *http.Client, rawURL string,
	allowedHosts ...string,
) (body io.ReadCloser, err error) {
	err = checkURL(rawURL, allowedHosts)
	if err != nil {
		return nil, fmt.Errorf("checking URL: %w", err)
	}

	restrictedClient := *client
	restrictedClient.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		err := checkURL(request.URL.String(), allowedHosts)
		if err != nil {
			return fmt.Errorf("checking redirect URL: %w", err)
		}
		const maxRedirects = 10
		switch {
		case len(via) >= maxRedirects:
			return fmt.Errorf("stopped after %d redirects", maxRedirects)
		case client.CheckRedirect != nil:
			return client.CheckRedirect(request, via)
		}
		return nil
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	response, err := restrictedClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("performing request: %w", err)
	}

	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		return nil, fmt.Errorf("HTTP status code %d", response.StatusCode)
	}

	return response.Body, nil
}

func checkURL(rawURL string, allowedHosts []string) error {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parsing URL: %w", err)
	}

	if parsedURL.Scheme != "https" {
		return fmt.Errorf("URL scheme %q is not https", parsedURL.Scheme)
	}

	host := strings.ToLower(parsedURL.Hostname())
	switch {
	case host == "purevpn.com",
		strings.HasSuffix(host, ".purevpn.com"),
		slices.Contains(allowedHosts, host):
		return nil
	}
	return fmt.Errorf("URL host %q is not allowed", host)
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

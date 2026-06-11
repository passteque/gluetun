package updater

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const pureVPNLinuxDownloadPageURL = "https://www.purevpn.com/download/linux-vpn"

var (
	debURLPattern  = regexp.MustCompile(`https?://[^"'\s<>]+\.deb`)
	hrefDebPattern = regexp.MustCompile(`href=["']([^"']+\.deb)["']`)
	semverPattern  = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)
)

type debCandidate struct {
	url      string
	score    int
	major    int
	minor    int
	patch    int
	position int
}

func fetchDebURL(ctx context.Context, client *http.Client) (debURL string, err error) {
	pageContent, err := fetchURL(ctx, client, pureVPNLinuxDownloadPageURL)
	if err != nil {
		return "", fmt.Errorf("fetching PureVPN Linux download page: %w", err)
	}

	debURLs, err := extractDebURLs(string(pageContent), pureVPNLinuxDownloadPageURL)
	if err != nil {
		return "", fmt.Errorf("extracting .deb URLs from download page: %w", err)
	}

	debURL, err = chooseDebURL(debURLs)
	if err != nil {
		return "", err
	}
	return debURL, nil
}

func fetchURL(ctx context.Context, client *http.Client, rawURL string) (content []byte, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("performing request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode < http.StatusOK || response.StatusCode > 299 {
		return nil, fmt.Errorf("HTTP status code %d", response.StatusCode)
	}

	content, err = io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	return content, nil
}

func extractDebURLs(pageHTML, baseURL string) (debURLs []string, err error) {
	baseParsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parsing base url %q: %w", baseURL, err)
	}

	urlsSet := make(map[string]struct{})

	for _, match := range debURLPattern.FindAllString(pageHTML, -1) {
		urlsSet[match] = struct{}{}
	}

	for _, groups := range hrefDebPattern.FindAllStringSubmatch(pageHTML, -1) {
		if len(groups) < 2 {
			continue
		}
		href := strings.TrimSpace(groups[1])
		parsedHref, parseErr := url.Parse(href)
		if parseErr != nil {
			continue
		}
		resolved := baseParsed.ResolveReference(parsedHref).String()
		urlsSet[resolved] = struct{}{}
	}

	debURLs = make([]string, 0, len(urlsSet))
	for rawURL := range urlsSet {
		debURLs = append(debURLs, rawURL)
	}
	sort.Strings(debURLs)

	if len(debURLs) == 0 {
		return nil, fmt.Errorf("no .deb URL found")
	}

	return debURLs, nil
}

func chooseDebURL(debURLs []string) (bestURL string, err error) {
	if len(debURLs) == 0 {
		return "", fmt.Errorf("no .deb URL candidates")
	}

	candidates := make([]debCandidate, 0, len(debURLs))
	for i, debURL := range debURLs {
		score := scoreDebURL(debURL)
		major, minor, patch := parseSemverFromURL(debURL)
		candidates = append(candidates, debCandidate{
			url:      debURL,
			score:    score,
			major:    major,
			minor:    minor,
			patch:    patch,
			position: i,
		})
	}

	sort.Slice(candidates, func(i, j int) bool {
		left := candidates[i]
		right := candidates[j]
		if left.score != right.score {
			return left.score > right.score
		}
		if left.major != right.major {
			return left.major > right.major
		}
		if left.minor != right.minor {
			return left.minor > right.minor
		}
		if left.patch != right.patch {
			return left.patch > right.patch
		}
		if left.position != right.position {
			return left.position < right.position
		}
		return left.url < right.url
	})

	return candidates[0].url, nil
}

func scoreDebURL(debURL string) (score int) {
	lower := strings.ToLower(debURL)

	if strings.Contains(lower, "purevpn") {
		score += 40
	}
	if strings.Contains(lower, "linux") {
		score += 30
	}
	if strings.Contains(lower, "gui") {
		score += 20
	}
	if strings.Contains(lower, "amd64") {
		score += 20
	}

	if strings.Contains(lower, "arm") || strings.Contains(lower, "aarch") {
		score -= 25
	}
	if strings.Contains(lower, "i386") || strings.Contains(lower, "x86") {
		score -= 25
	}

	return score
}

func parseSemverFromURL(rawURL string) (major, minor, patch int) {
	match := semverPattern.FindStringSubmatch(rawURL)
	if len(match) != 4 {
		return 0, 0, 0
	}

	major, _ = strconv.Atoi(match[1])
	minor, _ = strconv.Atoi(match[2])
	patch, _ = strconv.Atoi(match[3])

	return major, minor, patch
}

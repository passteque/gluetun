package updater

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
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

	debURLs, err := extractDebURLs(string(html), url)
	if err != nil {
		return "", fmt.Errorf("extracting .deb URLs from download page: %w", err)
	}

	return findBestDebURL(debURLs), nil
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

	if response.StatusCode < http.StatusOK || response.StatusCode > 299 {
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
		const minGroups = 2
		if len(groups) < minGroups {
			continue
		}
		href, err := url.Parse(strings.TrimSpace(groups[1]))
		if err != nil {
			continue
		}
		resolved := baseParsed.ResolveReference(href).String()
		urlsSet[resolved] = struct{}{}
	}

	if len(urlsSet) == 0 {
		return nil, errors.New("no .deb URL found")
	}

	return slices.Collect(maps.Keys(urlsSet)), nil
}

func findBestDebURL(debURLs []string) (bestURL string) {
	type debCandidate struct {
		url      string
		score    int
		major    uint16
		minor    uint16
		patch    uint16
		position uint
	}
	candidates := make([]debCandidate, len(debURLs))
	for i, debURL := range debURLs {
		score := scoreDebURL(debURL)
		major, minor, patch := parseSemverFromURL(debURL)
		candidates[i] = debCandidate{
			url:      debURL,
			score:    score,
			major:    major,
			minor:    minor,
			patch:    patch,
			position: uint(i), //nolint:gosec
		}
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

	return candidates[0].url
}

func scoreDebURL(debURL string) (score int) {
	keywordToPoints := map[string]int{
		"purevpn": 40,
		"linux":   30,
		"gui":     20,
		"amd64":   20,
		"arm":     -25,
		"aarch":   -25,
		"i386":    -25,
		"x86":     -25,
	}

	debURL = strings.ToLower(debURL)
	for keyword, points := range keywordToPoints {
		if strings.Contains(debURL, keyword) {
			score += points
		}
	}

	return score
}

var semverPattern = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)

func parseSemverFromURL(rawURL string) (major, minor, patch uint16) {
	match := semverPattern.FindStringSubmatch(rawURL)
	const expectedMatchesPlusOne = 4 // full match + 3 groups
	if len(match) != expectedMatchesPlusOne {
		return 0, 0, 0
	}

	const base, bitSize = 10, 16
	majorUint64, _ := strconv.ParseUint(match[1], base, bitSize)
	minorUint64, _ := strconv.ParseUint(match[2], base, bitSize)
	patchUint64, _ := strconv.ParseUint(match[3], base, bitSize)
	return uint16(majorUint64), uint16(minorUint64), uint16(patchUint64)
}

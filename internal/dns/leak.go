package dns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net/http"
	"sort"
	"strings"
)

func leakCheck(ctx context.Context, client *http.Client) (report string, err error) {
	const sessionLength = 40
	session := generateRandomString(sessionLength)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		dnsToCount map[string]uint
		err        error
	}
	resultsCh := make(chan result)

	const requestsCount = 5
	for range requestsCount {
		go func() {
			dnsToCount, err := triggerDNSQuery(ctx, client, session)
			resultsCh <- result{dnsToCount: dnsToCount, err: err}
		}()
	}

	dnsToCount := make(map[string]uint)
	for range requestsCount {
		result := <-resultsCh
		if result.err != nil {
			if err == nil {
				cancel()
				err = fmt.Errorf("request failed: %w", result.err)
			}
			continue
		}
		for dns, count := range result.dnsToCount {
			dnsToCount[dns] += count
		}
	}

	if err != nil {
		return "", err
	}

	return formatPercentages(dnsToCount), nil
}

func generateRandomString(length uint) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.IntN(len(charset))] //nolint:gosec
	}
	return string(b)
}

var errIPLeakSessionMismatch = errors.New("ipleak.net session mismatch")

func triggerDNSQuery(ctx context.Context, client *http.Client, session string) (
	dnsToCount map[string]uint, err error,
) {
	const randomLength = 12
	randomPart := generateRandomString(randomLength)
	url := fmt.Sprintf("https://%s-%s.ipleak.net/dnsdetection/", session, randomPart)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("performing request: %w", err)
	}
	defer response.Body.Close()

	type ipLeakData struct {
		Session string          `json:"session"`
		IP      map[string]uint `json:"ip"`
	}

	decoder := json.NewDecoder(response.Body)
	var data ipLeakData
	err = decoder.Decode(&data)
	if err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	} else if data.Session != session {
		return nil, fmt.Errorf("%w: expected %s, got %s", errIPLeakSessionMismatch, session, data.Session)
	}

	return data.IP, nil
}

func formatPercentages(data map[string]uint) string {
	if len(data) == 0 {
		return ""
	}

	var total uint
	keys := make([]string, 0, len(data))
	for k, v := range data {
		total += v
		keys = append(keys, k)
	}

	sort.Slice(keys, func(i, j int) bool {
		if data[keys[i]] == data[keys[j]] {
			return keys[i] < keys[j] // Tie-breaker: alphabetical
		}
		return data[keys[i]] > data[keys[j]]
	})

	results := make([]string, len(keys))
	for i, key := range keys {
		var pct float64
		if total > 0 {
			pct = math.Ceil((float64(data[key]) / float64(total)) * 100) //nolint:mnd
		}
		results[i] = fmt.Sprintf("%s (%.0f%%)", key, pct)
	}

	return strings.Join(results, ", ")
}

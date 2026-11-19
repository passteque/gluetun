package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"slices"
)

// checkResolvers logs the DNS resolvers detected through the tunnel by the
// ipleak.net service, when the resolver check is enabled. This is purely
// informational: it cannot tell if the detected resolvers are the expected ones.
func (l *Loop) checkResolvers(ctx context.Context, checkEnabled bool) {
	if !checkEnabled {
		return
	}

	resolvers, err := detectResolvers(ctx, l.client)
	if err != nil {
		l.logger.Warnf("detecting DNS resolvers through the tunnel: %s", err)
		return
	}

	l.logger.Infof("DNS resolvers detected through the tunnel: %v", resolvers)
}

// detectResolvers resolves the name of a randomly generated subdomain of
// ipleak.net several times, and returns the IP addresses of the DNS resolvers
// that answered, sorted by address.
func detectResolvers(ctx context.Context, client *http.Client) (
	resolvers []netip.Addr, err error,
) {
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
		return nil, err
	} else if len(dnsToCount) == 0 {
		// ipleak.net does not see every resolver, Google Public DNS for example.
		return nil, errors.New("no DNS resolver detected")
	}

	resolvers = make([]netip.Addr, 0, len(dnsToCount))
	for resolver := range dnsToCount {
		addr, err := netip.ParseAddr(resolver)
		if err != nil {
			return nil, fmt.Errorf("parsing resolver address %s: %w", resolver, err)
		}
		resolvers = append(resolvers, addr)
	}
	slices.SortFunc(resolvers, netip.Addr.Compare)

	return resolvers, nil
}

func generateRandomString(length uint) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.IntN(len(charset))] //nolint:gosec
	}
	return string(b)
}

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

	data, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%d %s: %s",
			response.StatusCode, response.Status, string(data))
	}

	var parsed ipLeakData
	err = json.Unmarshal(data, &parsed)
	if err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	} else if parsed.Session != session {
		return nil, fmt.Errorf("ipleak.net session mismatch: expected %s, got %s", session, parsed.Session)
	}

	return parsed.IP, nil
}

type ipLeakData struct {
	Session string      `json:"session"`
	IP      dnsCounters `json:"ip"`
}

// dnsCounters maps each DNS resolver IP address detected to the number
// of times it was detected.
type dnsCounters map[string]uint

// UnmarshalJSON accepts an empty JSON array `[]` as an empty map, since
// ipleak.net encodes the "ip" field as `[]` instead of `{}` when no DNS
// resolver was detected for the session (yet).
func (d *dnsCounters) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("[]")) {
		*d = dnsCounters{}
		return nil
	}
	var m map[string]uint
	err := json.Unmarshal(data, &m)
	if err != nil {
		return err
	}
	*d = m
	return nil
}

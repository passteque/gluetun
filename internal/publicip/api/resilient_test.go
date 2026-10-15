package api

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testFetcher struct {
	name          string
	canFetchAnyIP bool
	result        models.PublicIP
	err           error
	calls         atomic.Uint32
}

func (f *testFetcher) String() string      { return f.name }
func (f *testFetcher) CanFetchAnyIP() bool { return f.canFetchAnyIP }
func (f *testFetcher) Token() string       { return "" }

func (f *testFetcher) FetchInfo(context.Context, netip.Addr) (models.PublicIP, error) {
	f.calls.Add(1)
	return f.result, f.err
}

func Test_ResilientFetcher_FetchInfo(t *testing.T) {
	t.Parallel()

	errTest := errors.New("test error")

	testCases := map[string]struct {
		fetchers      []*testFetcher
		banned        []int // indices of fetchers banned before the call
		ip            netip.Addr
		expectedCalls []uint32
		result        models.PublicIP
		errMessage    string
	}{
		"first_fetcher_banned": {
			fetchers: []*testFetcher{
				{name: "a", result: models.PublicIP{Country: "France"}},
				{name: "b", result: models.PublicIP{Country: "Germany"}},
				{name: "c", result: models.PublicIP{Country: "Italy"}},
			},
			banned:        []int{0},
			expectedCalls: []uint32{0, 1, 1},
			result:        models.PublicIP{Country: "Germany"},
		},
		"middle_fetcher_banned": {
			fetchers: []*testFetcher{
				{name: "a", result: models.PublicIP{Country: "France"}},
				{name: "b", result: models.PublicIP{Country: "Germany"}},
				{name: "c", result: models.PublicIP{Country: "Italy"}},
				{name: "d", result: models.PublicIP{Country: "Italy"}},
			},
			banned:        []int{1},
			expectedCalls: []uint32{1, 0, 1, 1},
			result:        models.PublicIP{Country: "Italy"},
		},
		"all_fetchers_banned": {
			fetchers: []*testFetcher{
				{name: "a", result: models.PublicIP{Country: "France"}},
				{name: "b", result: models.PublicIP{Country: "Germany"}},
			},
			banned:        []int{0, 1},
			expectedCalls: []uint32{0, 0},
			errMessage:    "no fetcher available: all fetchers are banned",
		},
		"specific_ip_without_capable_fetcher": {
			fetchers: []*testFetcher{
				{name: "a", result: models.PublicIP{Country: "France"}},
			},
			ip:            netip.MustParseAddr("1.2.3.4"),
			expectedCalls: []uint32{0},
			errMessage: "no fetcher available for ip address 1.2.3.4: " +
				"all fetchers are banned or can only fetch their own public ip address",
		},
		"all_fetchers_fail": {
			fetchers: []*testFetcher{
				{name: "a", err: errTest},
				{name: "b", err: errTest},
			},
			expectedCalls: []uint32{1, 1},
			errMessage:    "all fetchers failed: a: test error\nb: test error",
		},
		"one_fetcher_fails": {
			fetchers: []*testFetcher{
				{name: "a", err: errTest},
				{name: "b", result: models.PublicIP{Country: "Germany"}},
			},
			expectedCalls: []uint32{1, 1},
			result:        models.PublicIP{Country: "Germany"},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fetchers := make([]Fetcher, len(testCase.fetchers))
			for i, fetcher := range testCase.fetchers {
				fetchers[i] = fetcher
			}
			resilient := NewResilient(fetchers, nil)
			for _, i := range testCase.banned {
				resilient.setBanned(fetchers[i])
			}

			result, err := resilient.FetchInfo(context.Background(), testCase.ip)

			if testCase.errMessage != "" {
				require.EqualError(t, err, testCase.errMessage)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, testCase.result, result)
			for i, fetcher := range testCase.fetchers {
				assert.Equal(t, testCase.expectedCalls[i], fetcher.calls.Load(),
					"calls to fetcher %s", fetcher.name)
			}
		})
	}
}

func Test_ResilientFetcher_FetchInfo_bansFetcher(t *testing.T) {
	t.Parallel()

	fetcher := &testFetcher{name: "a", err: ErrTooManyRequests}
	resilient := NewResilient([]Fetcher{fetcher}, nil)

	_, err := resilient.FetchInfo(context.Background(), netip.Addr{})
	require.EqualError(t, err, "all fetchers failed: a: too many requests sent for this month")
	assert.True(t, resilient.isBanned(fetcher))

	_, err = resilient.FetchInfo(context.Background(), netip.Addr{})
	require.EqualError(t, err, "no fetcher available: all fetchers are banned")
	assert.Equal(t, uint32(1), fetcher.calls.Load())
}

func Test_GetMostPopularResult(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		input    []models.PublicIP
		expected models.PublicIP
	}{
		"exact_matches": {
			input: []models.PublicIP{
				{Country: "France", City: "Paris"},
				{Country: "USA", City: "New York"},
				{Country: "France", City: "Paris"},
			},
			expected: models.PublicIP{Country: "France", City: "Paris"},
		},
		"fuzzy_country_matching": {
			input: []models.PublicIP{
				{Country: "Germany", Region: "Bavaria", City: "Munich"},
				{Country: "Germani", Region: "Bavaria", City: "Munich"},
				{Country: "France", Region: "IDF", City: "Paris"},
			},
			expected: models.PublicIP{Country: "Germany", Region: "Bavaria", City: "Munich"},
		},
		"hierarchy_priority": {
			input: []models.PublicIP{
				{Country: "Italy", Region: "Sicily", City: "Syracuse"},
				{Country: "Italy", Region: "Sicily", City: "Syracuse"},
				{Country: "USA", Region: "New York", City: "Syracuse"},
				{Country: "Italy", Region: "Sicily", City: "Syracuse"},
			},
			expected: models.PublicIP{Country: "Italy", Region: "Sicily", City: "Syracuse"},
		},
		"normalization_check": {
			input: []models.PublicIP{
				{Country: "Canada", City: "Montréal"},
				{Country: "Canada", City: "Montreal "},
				{Country: "UK", City: "London"},
			},
			expected: models.PublicIP{Country: "Canada", City: "Montréal"},
		},
		"all_different": {
			input: []models.PublicIP{
				{Country: "Canada", City: "Montréal"},
				{Country: "US", City: "New York"},
				{Country: "UK", City: "London"},
			},
			expected: models.PublicIP{Country: "US", City: "New York"},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := getMostPopularResult(testCase.input)

			assert.Equal(t, testCase.expected.Country, result.Country)
			assert.Equal(t, testCase.expected.Region, result.Region)
			assert.Equal(t, testCase.expected.City, result.City)
		})
	}
}

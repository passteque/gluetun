package api

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func Test_ResilientFetcher_FetchInfo(t *testing.T) {
	t.Parallel()

	errTest := errors.New("test error")

	testCases := map[string]struct {
		// makeFetchers returns the fetchers to use and which of
		// them are banned before the call.
		makeFetchers func(t *testing.T) (fetchers, banned []Fetcher)
		ip           netip.Addr
		result       models.PublicIP
		errMessage   string
	}{
		"first_fetcher_banned": {
			makeFetchers: func(t *testing.T) (fetchers, banned []Fetcher) {
				t.Helper()
				ctrl := gomock.NewController(t)
				fetcherA := NewMockFetcher(ctrl)
				fetcherB := NewMockFetcher(ctrl)
				fetcherB.EXPECT().FetchInfo(t.Context(), netip.Addr{}).
					Return(models.PublicIP{Country: "Germany"}, nil).Times(1)
				fetcherC := NewMockFetcher(ctrl)
				fetcherC.EXPECT().FetchInfo(t.Context(), netip.Addr{}).
					Return(models.PublicIP{Country: "Italy"}, nil).Times(1)
				return []Fetcher{fetcherA, fetcherB, fetcherC}, []Fetcher{fetcherA}
			},
			result: models.PublicIP{Country: "Germany"},
		},
		"middle_fetcher_banned": {
			makeFetchers: func(t *testing.T) (fetchers, banned []Fetcher) {
				t.Helper()
				ctrl := gomock.NewController(t)
				fetcherA := NewMockFetcher(ctrl)
				fetcherA.EXPECT().FetchInfo(t.Context(), netip.Addr{}).
					Return(models.PublicIP{Country: "France"}, nil).Times(1)
				fetcherB := NewMockFetcher(ctrl)
				fetcherC := NewMockFetcher(ctrl)
				fetcherC.EXPECT().FetchInfo(t.Context(), netip.Addr{}).
					Return(models.PublicIP{Country: "Italy"}, nil).Times(1)
				fetcherD := NewMockFetcher(ctrl)
				fetcherD.EXPECT().FetchInfo(t.Context(), netip.Addr{}).
					Return(models.PublicIP{Country: "Italy"}, nil).Times(1)
				return []Fetcher{fetcherA, fetcherB, fetcherC, fetcherD}, []Fetcher{fetcherB}
			},
			result: models.PublicIP{Country: "Italy"},
		},
		"all_fetchers_banned": {
			makeFetchers: func(t *testing.T) (fetchers, banned []Fetcher) {
				t.Helper()
				ctrl := gomock.NewController(t)
				fetcherA := NewMockFetcher(ctrl)
				fetcherB := NewMockFetcher(ctrl)
				return []Fetcher{fetcherA, fetcherB}, []Fetcher{fetcherA, fetcherB}
			},
			errMessage: "all fetchers are banned",
		},
		"specific_ip_without_capable_fetcher": {
			makeFetchers: func(t *testing.T) (fetchers, banned []Fetcher) {
				t.Helper()
				ctrl := gomock.NewController(t)
				fetcherA := NewMockFetcher(ctrl)
				fetcherA.EXPECT().CanFetchAnyIP().Return(false).Times(1)
				return []Fetcher{fetcherA}, nil
			},
			ip:         netip.MustParseAddr("1.2.3.4"),
			errMessage: "no fetcher available for ip address 1.2.3.4",
		},
		"all_fetchers_fail": {
			makeFetchers: func(t *testing.T) (fetchers, banned []Fetcher) {
				t.Helper()
				ctrl := gomock.NewController(t)
				fetcherA := NewMockFetcher(ctrl)
				fetcherA.EXPECT().FetchInfo(t.Context(), netip.Addr{}).
					Return(models.PublicIP{}, errTest).Times(1)
				fetcherA.EXPECT().String().Return("a").Times(1)
				fetcherB := NewMockFetcher(ctrl)
				fetcherB.EXPECT().FetchInfo(t.Context(), netip.Addr{}).
					Return(models.PublicIP{}, errTest).Times(1)
				fetcherB.EXPECT().String().Return("b").Times(1)
				return []Fetcher{fetcherA, fetcherB}, nil
			},
			errMessage: "all fetchers failed: a: test error\nb: test error",
		},
		"one_fetcher_fails": {
			makeFetchers: func(t *testing.T) (fetchers, banned []Fetcher) {
				t.Helper()
				ctrl := gomock.NewController(t)
				fetcherA := NewMockFetcher(ctrl)
				fetcherA.EXPECT().FetchInfo(t.Context(), netip.Addr{}).
					Return(models.PublicIP{}, errTest).Times(1)
				fetcherA.EXPECT().String().Return("a").Times(1)
				fetcherB := NewMockFetcher(ctrl)
				fetcherB.EXPECT().FetchInfo(t.Context(), netip.Addr{}).
					Return(models.PublicIP{Country: "Germany"}, nil).Times(1)
				return []Fetcher{fetcherA, fetcherB}, nil
			},
			result: models.PublicIP{Country: "Germany"},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fetchers, banned := testCase.makeFetchers(t)
			resilient := NewResilient(fetchers, nil)
			for _, fetcher := range banned {
				resilient.setBanned(fetcher)
			}

			result, err := resilient.FetchInfo(t.Context(), testCase.ip)

			if testCase.errMessage != "" {
				require.ErrorContains(t, err, testCase.errMessage)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, testCase.result, result)
		})
	}
}

func Test_ResilientFetcher_FetchInfo_bansFetcher(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	fetcher := NewMockFetcher(ctrl)
	fetcher.EXPECT().FetchInfo(t.Context(), netip.Addr{}).
		Return(models.PublicIP{}, ErrTooManyRequests).Times(1)
	fetcher.EXPECT().String().Return("a").Times(1)
	resilient := NewResilient([]Fetcher{fetcher}, nil)

	_, err := resilient.FetchInfo(t.Context(), netip.Addr{})
	require.ErrorContains(t, err, "all fetchers failed: a: too many requests sent for this month")
	assert.True(t, resilient.isBanned(fetcher))

	_, err = resilient.FetchInfo(t.Context(), netip.Addr{})
	require.ErrorContains(t, err, "all fetchers are banned")
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

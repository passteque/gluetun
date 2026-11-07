package api

import (
	"context"
	"errors"
	"net/netip"
	"slices"
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
		makeFetchers func(ctx context.Context, ctrl *gomock.Controller) []Fetcher
		bannedBefore []int // indexes of the fetchers banned before the call
		ip           netip.Addr
		result       models.PublicIP
		errMessage   string
		bannedAfter  []int // indexes of the fetchers banned after the call
	}{
		"first_fetcher_banned": {
			makeFetchers: func(ctx context.Context, ctrl *gomock.Controller) []Fetcher {
				fetcherA := NewMockFetcher(ctrl)
				fetcherB := NewMockFetcher(ctrl)
				fetcherB.EXPECT().FetchInfo(ctx, netip.Addr{}).
					Return(models.PublicIP{Country: "Germany"}, nil)
				fetcherC := NewMockFetcher(ctrl)
				fetcherC.EXPECT().FetchInfo(ctx, netip.Addr{}).
					Return(models.PublicIP{Country: "Italy"}, nil)
				return []Fetcher{fetcherA, fetcherB, fetcherC}
			},
			bannedBefore: []int{0},
			result:       models.PublicIP{Country: "Germany"},
			bannedAfter:  []int{0},
		},
		"middle_fetcher_banned": {
			makeFetchers: func(ctx context.Context, ctrl *gomock.Controller) []Fetcher {
				fetcherA := NewMockFetcher(ctrl)
				fetcherA.EXPECT().FetchInfo(ctx, netip.Addr{}).
					Return(models.PublicIP{Country: "France"}, nil)
				fetcherB := NewMockFetcher(ctrl)
				fetcherC := NewMockFetcher(ctrl)
				fetcherC.EXPECT().FetchInfo(ctx, netip.Addr{}).
					Return(models.PublicIP{Country: "Italy"}, nil)
				fetcherD := NewMockFetcher(ctrl)
				fetcherD.EXPECT().FetchInfo(ctx, netip.Addr{}).
					Return(models.PublicIP{Country: "Italy"}, nil)
				return []Fetcher{fetcherA, fetcherB, fetcherC, fetcherD}
			},
			bannedBefore: []int{1},
			result:       models.PublicIP{Country: "Italy"},
			bannedAfter:  []int{1},
		},
		"all_fetchers_banned": {
			makeFetchers: func(ctx context.Context, ctrl *gomock.Controller) []Fetcher {
				fetcherA := NewMockFetcher(ctrl)
				fetcherB := NewMockFetcher(ctrl)
				return []Fetcher{fetcherA, fetcherB}
			},
			bannedBefore: []int{0, 1},
			errMessage:   "all fetchers are banned",
			bannedAfter:  []int{0, 1},
		},
		"specific_ip_without_capable_fetcher": {
			makeFetchers: func(ctx context.Context, ctrl *gomock.Controller) []Fetcher {
				fetcherA := NewMockFetcher(ctrl)
				fetcherA.EXPECT().CanFetchAnyIP().Return(false)
				return []Fetcher{fetcherA}
			},
			ip:         netip.MustParseAddr("1.2.3.4"),
			errMessage: "no fetcher available for ip address 1.2.3.4",
		},
		"all_fetchers_fail": {
			makeFetchers: func(ctx context.Context, ctrl *gomock.Controller) []Fetcher {
				fetcherA := NewMockFetcher(ctrl)
				fetcherA.EXPECT().FetchInfo(ctx, netip.Addr{}).
					Return(models.PublicIP{}, errTest)
				fetcherA.EXPECT().String().Return("a")
				fetcherB := NewMockFetcher(ctrl)
				fetcherB.EXPECT().FetchInfo(ctx, netip.Addr{}).
					Return(models.PublicIP{}, errTest)
				fetcherB.EXPECT().String().Return("b")
				return []Fetcher{fetcherA, fetcherB}
			},
			errMessage: "all fetchers failed: a: test error\nb: test error",
		},
		"one_fetcher_fails": {
			makeFetchers: func(ctx context.Context, ctrl *gomock.Controller) []Fetcher {
				fetcherA := NewMockFetcher(ctrl)
				fetcherA.EXPECT().FetchInfo(ctx, netip.Addr{}).
					Return(models.PublicIP{}, errTest)
				fetcherA.EXPECT().String().Return("a")
				fetcherB := NewMockFetcher(ctrl)
				fetcherB.EXPECT().FetchInfo(ctx, netip.Addr{}).
					Return(models.PublicIP{Country: "Germany"}, nil)
				return []Fetcher{fetcherA, fetcherB}
			},
			result: models.PublicIP{Country: "Germany"},
		},
		"too_many_requests_bans_fetcher": {
			makeFetchers: func(ctx context.Context, ctrl *gomock.Controller) []Fetcher {
				fetcher := NewMockFetcher(ctrl)
				fetcher.EXPECT().FetchInfo(ctx, netip.Addr{}).
					Return(models.PublicIP{}, ErrTooManyRequests)
				fetcher.EXPECT().String().Return("a")
				return []Fetcher{fetcher}
			},
			errMessage:  "all fetchers failed: a: too many requests sent for this month",
			bannedAfter: []int{0},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			ctrl := gomock.NewController(t)
			fetchers := testCase.makeFetchers(ctx, ctrl)
			resilient := NewResilient(fetchers, nil)
			for _, i := range testCase.bannedBefore {
				resilient.setBanned(fetchers[i])
			}

			result, err := resilient.FetchInfo(ctx, testCase.ip)

			if testCase.errMessage != "" {
				require.ErrorContains(t, err, testCase.errMessage)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, testCase.result, result)
			for i, fetcher := range fetchers {
				assert.Equal(t, slices.Contains(testCase.bannedAfter, i),
					resilient.isBanned(fetcher), "banned state of fetcher %d", i)
			}
		})
	}
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

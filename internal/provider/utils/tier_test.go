package utils

import (
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
)

func Test_sortServersByTier(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		servers   []models.Server
		selection settings.ServerSelection
		expected  []models.Server
	}{
		"narrowest_filter_list_takes_priority": {
			servers: []models.Server{
				{ServerName: "pl-warsaw", Country: "Poland", City: "Warsaw"},
				{ServerName: "de-berlin", Country: "Germany", City: "Berlin"},
				{ServerName: "pl-berlin", Country: "Poland", City: "Berlin"},
			},
			selection: settings.ServerSelection{
				Countries: []string{"Germany", "Poland"},
				Cities:    []string{"Berlin", "Warsaw"},
			},
			expected: []models.Server{
				{ServerName: "de-berlin", Country: "Germany", City: "Berlin"},
				{ServerName: "pl-berlin", Country: "Poland", City: "Berlin"},
				{ServerName: "pl-warsaw", Country: "Poland", City: "Warsaw"},
			},
		},
		"countries_priority_order": {
			servers: []models.Server{
				{ServerName: "cz-1", Country: "Czechia"},
				{ServerName: "pl-1", Country: "Poland"},
				{ServerName: "de-1", Country: "Germany"},
				{ServerName: "pl-2", Country: "Poland"},
			},
			selection: settings.ServerSelection{
				Countries: []string{"Poland", "Germany", "Czechia"},
			},
			expected: []models.Server{
				{ServerName: "pl-1", Country: "Poland"},
				{ServerName: "pl-2", Country: "Poland"},
				{ServerName: "de-1", Country: "Germany"},
				{ServerName: "cz-1", Country: "Czechia"},
			},
		},
		"IPv6_servers_first_within_a_tier": {
			servers: []models.Server{
				{
					ServerName: "pl-v4",
					Country:    "Poland",
					IPs:        []netip.Addr{netip.MustParseAddr("1.1.1.1")},
				},
				{
					ServerName: "de-v4",
					Country:    "Germany",
					IPs:        []netip.Addr{netip.MustParseAddr("2.2.2.1")},
				},
				{
					ServerName: "pl-v6",
					Country:    "Poland",
					IPs: []netip.Addr{
						netip.MustParseAddr("1.1.1.2"),
						netip.MustParseAddr("2001:db8::2"),
					},
				},
			},
			selection: settings.ServerSelection{
				Countries: []string{"Poland", "Germany"},
			},
			expected: []models.Server{
				{
					ServerName: "pl-v6",
					Country:    "Poland",
					IPs: []netip.Addr{
						netip.MustParseAddr("1.1.1.2"),
						netip.MustParseAddr("2001:db8::2"),
					},
				},
				{
					ServerName: "pl-v4",
					Country:    "Poland",
					IPs:        []netip.Addr{netip.MustParseAddr("1.1.1.1")},
				},
				{
					ServerName: "de-v4",
					Country:    "Germany",
					IPs:        []netip.Addr{netip.MustParseAddr("2.2.2.1")},
				},
			},
		},
		"empty_servers": {
			servers:   []models.Server{},
			selection: settings.ServerSelection{},
			expected:  []models.Server{},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			sortServersByTier(testCase.servers, testCase.selection)

			assert.Equal(t, testCase.expected, testCase.servers)
		})
	}
}

func Test_selectionTier(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		server    models.Server
		selection settings.ServerSelection
		expected  uint
	}{
		"no_filters": {
			server: models.Server{Country: "Poland", City: "Warsaw"},
		},
		"countries": {
			server:    models.Server{Country: "Germany"},
			selection: settings.ServerSelection{Countries: []string{"Poland", "Germany", "Czechia"}},
			expected:  1,
		},
		"countries_case_insensitive": {
			server:    models.Server{Country: "germany"},
			selection: settings.ServerSelection{Countries: []string{"Poland", "GERMANY", "Czechia"}},
			expected:  1,
		},
		"categories": {
			server:    models.Server{Categories: []string{"fast"}},
			selection: settings.ServerSelection{Categories: []string{"free", "fast"}},
			expected:  1,
		},
		"categories_multiple_values_use_lowest_index": {
			server:    models.Server{Categories: []string{"fast", "free"}},
			selection: settings.ServerSelection{Categories: []string{"free", "fast"}},
			expected:  0,
		},
		"regions": {
			server:    models.Server{Region: "norway"},
			selection: settings.ServerSelection{Regions: []string{"denmark", "norway"}},
			expected:  1,
		},
		"cities": {
			server:    models.Server{City: "Berlin"},
			selection: settings.ServerSelection{Cities: []string{"Warsaw", "Berlin"}},
			expected:  1,
		},
		"isps": {
			server:    models.Server{ISP: "Hetzner"},
			selection: settings.ServerSelection{ISPs: []string{"OVH", "Hetzner"}},
			expected:  1,
		},
		"numbers": {
			server:    models.Server{Number: 2},
			selection: settings.ServerSelection{Numbers: []uint16{1, 2, 3}},
			expected:  1,
		},
		"names": {
			server:    models.Server{ServerName: "us-59"},
			selection: settings.ServerSelection{Names: []string{"us-121", "us-59"}},
			expected:  1,
		},
		"hostnames": {
			server:    models.Server{Hostname: "node-us-59.protonvpn.net"},
			selection: settings.ServerSelection{Hostnames: []string{"node-us-121.protonvpn.net", "node-us-59.protonvpn.net"}},
			expected:  1,
		},
		"cities_narrower_than_countries": {
			server: models.Server{
				Country: "Poland",
				City:    "Berlin",
			},
			selection: settings.ServerSelection{
				Countries: []string{"Poland", "Germany"},
				Cities:    []string{"Warsaw", "Berlin"},
			},
			expected: 1,
		},
		"hostnames_narrower_than_cities": {
			server: models.Server{
				City:     "Warsaw",
				Hostname: "node-pl-59.protonvpn.net",
			},
			selection: settings.ServerSelection{
				Cities:    []string{"Warsaw", "Berlin"},
				Hostnames: []string{"node-pl-58.protonvpn.net", "node-pl-59.protonvpn.net"},
			},
			expected: 1,
		},
		"server_not_matching_narrowest_list_gets_tier_0": {
			server: models.Server{
				ServerName: "us-59",
				Hostname:   "node-us-59.protonvpn.net",
			},
			selection: settings.ServerSelection{
				Names:     []string{"us-121", "us-59"},
				Hostnames: []string{"node-us-121.protonvpn.net"},
			},
			expected: 0,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, testCase.expected,
				selectionTier(testCase.server, testCase.selection))
		})
	}
}

func Test_matchIndex(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		value         string
		possibilities []string
		expected      uint
	}{
		"empty_possibilities": {
			value: "abc",
		},
		"first_match": {
			value:         "abc",
			possibilities: []string{"abc", "def"},
			expected:      0,
		},
		"second_match": {
			value:         "def",
			possibilities: []string{"abc", "def"},
			expected:      1,
		},
		"case_insensitive": {
			value:         "AbC",
			possibilities: []string{"abc", "def"},
			expected:      0,
		},
		"no_match": {
			value:         "ghi",
			possibilities: []string{"abc", "def"},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, testCase.expected,
				matchIndex(testCase.value, testCase.possibilities))
		})
	}
}

func Test_matchIndexAny(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		values        []string
		possibilities []string
		expected      uint
	}{
		"empty_values": {
			possibilities: []string{"abc"},
		},
		"empty_possibilities": {
			values: []string{"abc"},
		},
		"first_match": {
			values:        []string{"abc"},
			possibilities: []string{"abc", "def"},
			expected:      0,
		},
		"lowest_index_match": {
			values:        []string{"def", "abc"},
			possibilities: []string{"abc", "def"},
			expected:      0,
		},
		"no_match": {
			values:        []string{"ghi"},
			possibilities: []string{"abc", "def"},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, testCase.expected,
				matchIndexAny(testCase.values, testCase.possibilities))
		})
	}
}

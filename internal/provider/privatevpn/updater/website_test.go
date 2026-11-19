package updater

import (
	"os"
	"strings"
	"testing"

	htmlutils "github.com/qdm12/gluetun/internal/updater/html"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/html"
)

func Test_parseServerListTable(t *testing.T) {
	t.Parallel()

	rootNode := parseTestHTML(t, "testdata/index.html")

	servers, warnings, err := parseServerListTable(rootNode)
	require.NoError(t, err)
	assert.Empty(t, warnings)

	// Verify we got a reasonable number of servers (expected 70+)
	assert.Greater(t, len(servers), 50)
}

func Test_parseServerListTable_hasValidServers(t *testing.T) {
	t.Parallel()

	rootNode := parseTestHTML(t, "testdata/index.html")

	servers, _, err := parseServerListTable(rootNode)
	require.NoError(t, err)

	testCases := map[string]struct {
		findByHostname string
		wantCountry    string
		wantCity       string
	}{
		"australia_sydney": {
			findByHostname: "au-syd.pvdata.host",
			wantCountry:    "Australia",
			wantCity:       "Sydney",
		},
		"netherlands_amsterdam": {
			findByHostname: "nl-ams.pvdata.host",
			wantCountry:    "Netherlands",
			wantCity:       "Amsterdam",
		},
		"germany_frankfurt": {
			findByHostname: "de-fra.pvdata.host",
			wantCountry:    "Germany",
			wantCity:       "Frankfurt",
		},
		"united_kingdom_london": {
			findByHostname: "uk-lon.pvdata.host",
			wantCountry:    "United Kingdom",
			wantCity:       "London",
		},
		"us_new_york": {
			findByHostname: "us-nyc.pvdata.host",
			wantCountry:    "United States of America",
			wantCity:       "New York",
		},
		"france_paris": {
			findByHostname: "fr-par.pvdata.host",
			wantCountry:    "France",
			wantCity:       "Paris",
		},
		"italy_milan": {
			findByHostname: "it-mil.pvdata.host",
			wantCountry:    "Italy",
			wantCity:       "Milan",
		},
		"poland_torun": {
			findByHostname: "pl-tor.pvdata.host",
			wantCountry:    "Poland",
			wantCity:       "Torun",
		},
		"singapore_no_city_format": {
			findByHostname: "sg-sin.pvdata.host",
			wantCountry:    "Singapore",
			wantCity:       "",
		},
		"japan_tokyo": {
			findByHostname: "jp-tok.pvdata.host",
			wantCountry:    "Japan",
			wantCity:       "Tokyo",
		},
		"united_ae_dubai": {
			findByHostname: "ae-dub.pvdata.host",
			wantCountry:    "United Arab Emirates",
			wantCity:       "Dubai",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			found := false
			for _, server := range servers {
				if server.Hostname == testCase.findByHostname {
					found = true
					assert.Equal(t, testCase.wantCountry, server.Country, "country mismatch")
					assert.Equal(t, testCase.wantCity, server.City, "city mismatch")
					break
				}
			}
			assert.True(t, found, "server with hostname %q not found", testCase.findByHostname)
		})
	}
}

func Test_parseServerListTable_noDeadServers(t *testing.T) {
	t.Parallel()

	rootNode := parseTestHTML(t, "testdata/index.html")

	servers, _, err := parseServerListTable(rootNode)
	require.NoError(t, err)

	// These are the dead hostnames that were in the old 2019 zip file
	deadHostnames := []string{
		"au-syd2.pvdata.host",
		"nl-ams2.pvdata.host",
		"uk-lon3.pvdata.host",
		"uk-lon5.pvdata.host",
		"uk-lon6.pvdata.host",
		"de-fra2.pvdata.host",
		"it-mil2.pvdata.host",
		"fr-par3.pvdata.host",
		"pl-war.pvdata.host",
		"us-nyc4.pvdata.host",
	}

	for _, deadHostname := range deadHostnames {
		t.Run("no_"+deadHostname, func(t *testing.T) {
			t.Parallel()

			for _, server := range servers {
				assert.NotEqual(t, deadHostname, server.Hostname,
					"dead hostname %q should not be in the server list", deadHostname)
			}
		})
	}
}

func Test_parseLocation(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		location    string
		wantCountry string
		wantCity    string
	}{
		"country_and_city": {
			location:    "Germany - Frankfurt",
			wantCountry: "Germany",
			wantCity:    "Frankfurt",
		},
		"country_only": {
			location:    "Singapore",
			wantCountry: "Singapore",
			wantCity:    "",
		},
		"long_country_name": {
			location:    "United States of America - New York",
			wantCountry: "United States of America",
			wantCity:    "New York",
		},
		"city_with_dash": {
			location:    "United States of America - New York City",
			wantCountry: "United States of America",
			wantCity:    "New York City",
		},
		"hong_kong": {
			location:    "Hong Kong",
			wantCountry: "Hong Kong",
			wantCity:    "",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			country, city := parseLocation(testCase.location)
			assert.Equal(t, testCase.wantCountry, country)
			assert.Equal(t, testCase.wantCity, city)
		})
	}
}

func Test_extractTextFromCell(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		htmlInput string
		wantText  string
	}{
		"simple_text": {
			htmlInput: "<table><tr><td><div><p>Germany - Frankfurt</p></div></td></tr></table>",
			wantText:  "Germany - Frankfurt",
		},
		"nested_divs": {
			htmlInput: "<table><tr><td>" +
				"<div class=\"intercom-interblocks-paragraph\">" +
				"<p>hostname.pvdata.host</p>" +
				"</div></td></tr></table>",
			wantText: "hostname.pvdata.host",
		},
		"whitespace_handling": {
			htmlInput: "<table><tr><td>   United Kingdom - London   </td></tr></table>",
			wantText:  "United Kingdom - London",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			node, err := html.Parse(strings.NewReader(testCase.htmlInput))
			require.NoError(t, err)

			// Find the td node
			tdNode := findTDNode(node)
			require.NotNil(t, tdNode, "td node not found")

			text := extractTextFromCell(tdNode)
			assert.Equal(t, testCase.wantText, text)
		})
	}
}

func parseTestHTML(t *testing.T, filepath string) *html.Node {
	t.Helper()

	content, err := os.ReadFile(filepath)
	require.NoError(t, err)

	rootNode, err := html.Parse(strings.NewReader(string(content)))
	require.NoError(t, err)

	return rootNode
}

func findTDNode(node *html.Node) *html.Node {
	return htmlutils.BFS(node, htmlutils.MatchData("td"))
}

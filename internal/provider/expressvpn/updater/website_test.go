package updater

import (
	"os"
	"strings"
	"testing"

	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/html"
)

func Test_parseServerListTable(t *testing.T) {
	t.Parallel()

	htmlContent, err := os.ReadFile("testdata/index.html")
	require.NoError(t, err)

	rootNode, err := html.Parse(strings.NewReader(string(htmlContent)))
	require.NoError(t, err)

	servers, warnings := parseServerListTable(rootNode)
	require.NoError(t, err)
	assert.Empty(t, warnings)
	// The ExpressVPN server list should have hundreds of servers
	assert.Greater(t, len(servers), 200,
		"expected at least 200 servers from the ExpressVPN server list, got %d", len(servers))

	// Check that all servers have required fields
	for _, server := range servers {
		assert.NotEmpty(t, server.Country, "server country should not be empty")
		assert.True(t, server.TCP, "TCP should be enabled")
		assert.True(t, server.UDP, "UDP should be enabled")
	}

	// Check some specific servers are found
	foundServers := make(map[string]models.Server)
	for _, server := range servers {
		key := server.Country
		if server.City != "" {
			key += " - " + server.City
		}
		foundServers[key] = server
	}

	// Verify countries without cities
	assert.NotEmpty(t, foundServers["Albania"])
	assert.NotEmpty(t, foundServers["Singapore"])
}

func Test_parseLocation(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		input   string
		country string
		city    string
		number  uint16
	}{
		"country only": {
			input:   "Argentina",
			country: "Argentina",
		},
		"country with city": {
			input:   "Australia - Adelaide",
			country: "Australia",
			city:    "Adelaide",
		},
		"country with numbered location": {
			input:   "Canada - Toronto - 2",
			country: "Canada",
			city:    "Toronto",
			number:  2,
		},
		"virtual location": {
			input:   "India (via Singapore)",
			country: "India (via Singapore)",
		},
		"country with multiple dashes in city": {
			input:   "USA - Los Angeles - 1",
			country: "USA",
			city:    "Los Angeles",
			number:  1,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			country, city, number, err := parseLocation(testCase.input)
			assert.Equal(t, testCase.country, country)
			assert.Equal(t, testCase.city, city)
			assert.Equal(t, testCase.number, number)
			assert.NoError(t, err)
		})
	}
}

func Test_generateCandidateHostnames(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		input          models.Server
		mustContain    []string
		mustNotContain []string
		expectedCount  int // exact count expected (0 if flexible)
	}{
		"simple country": {
			input: models.Server{Country: "Argentina"},
			mustContain: []string{
				"argentina-ca-version-2.expressnetw.com",
				"argentina1-ca-version-2.expressnetw.com",
				"argentina-1-ca-version-2.expressnetw.com",
			},
		},
		"country with city": {
			input: models.Server{Country: "USA", City: "New York"},
			mustContain: []string{
				"usa-newyork-ca-version-2.expressnetw.com",
				"us-newyork-ca-version-2.expressnetw.com", // alias
				"usa-newyork-1-ca-version-2.expressnetw.com",
				"usa-newyork1-ca-version-2.expressnetw.com",
			},
		},
		"North Macedonia abbreviation": {
			input: models.Server{Country: "North Macedonia"},
			mustContain: []string{
				"macedonia-ca-version-2.expressnetw.com",
			},
			expectedCount: 1, // single hardcoded hostname
		},
		"India via Singapore": {
			input: models.Server{Country: "India (via Singapore)"},
			mustContain: []string{
				"india-sg-ca-version-2.expressnetw.com",
			},
			expectedCount: 1, // single hardcoded hostname
		},
		"India via UK": {
			input: models.Server{Country: "India (via UK)"},
			mustContain: []string{
				"india-uk-ca-version-2.expressnetw.com",
			},
			expectedCount: 1, // single hardcoded hostname
		},
		"France Paris": {
			input: models.Server{Country: "France", City: "Paris"},
			mustContain: []string{
				"france-paris-ca-version-2.expressnetw.com",
				"france-paris-1-ca-version-2.expressnetw.com",
				"france-paris-2-ca-version-2.expressnetw.com",
				"france-paris1-ca-version-2.expressnetw.com",
				"france-paris2-ca-version-2.expressnetw.com",
			},
		},
		"UK with alias": {
			input: models.Server{Country: "UK", City: "London"},
			mustContain: []string{
				"uk-london-ca-version-2.expressnetw.com",
				"gb-london-ca-version-2.expressnetw.com", // alias
			},
		},
		"Germany": {
			input: models.Server{Country: "Germany"},
			mustContain: []string{
				"germany-ca-version-2.expressnetw.com",
				"de-ca-version-2.expressnetw.com", // alias
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			candidates, err := generateCandidateHostnames(testCase.input)
			assert.NoError(t, err)

			// Check exact count if specified
			if testCase.expectedCount > 0 {
				assert.Len(t, candidates, testCase.expectedCount,
					"expected exactly %d candidates", testCase.expectedCount)
			}

			// Check required candidates exist
			for _, expected := range testCase.mustContain {
				assert.Contains(t, candidates, expected,
					"expected candidate %q in candidates", expected)
			}

			// Check excluded candidates don't exist
			for _, excluded := range testCase.mustNotContain {
				assert.NotContains(t, candidates, excluded,
					"did not expect candidate %q in candidates", excluded)
			}

			// All candidates should end with the expected suffix
			for _, candidate := range candidates {
				assert.True(t, strings.HasSuffix(candidate, hostnameSuffix),
					"candidate %q should end with %q", candidate, hostnameSuffix)
			}
		})
	}
}

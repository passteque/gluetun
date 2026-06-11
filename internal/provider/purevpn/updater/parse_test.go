package updater

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_parseHostname_CanadaCityCodes(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		hostname string
		country  string
		city     string
	}{
		"country only no city code": {
			hostname: "ca2-auto-udp.ptoserver.com",
			country:  "Canada",
			city:     "",
		},
		"single-letter city code q": {
			hostname: "caq2-auto-udp.ptoserver.com",
			country:  "Canada",
			city:     "Montreal",
		},
		"australia brisbane code bb": {
			hostname: "aubb2-auto-udp.ptoserver.com",
			country:  "Australia",
			city:     "Brisbane",
		},
		"australia brisbane code bn": {
			hostname: "aubn2-auto-udp.ptoserver.com",
			country:  "Australia",
			city:     "Brisbane",
		},
		"single-letter city code v": {
			hostname: "cav2-auto-udp.ptoserver.com",
			country:  "Canada",
			city:     "Vancouver",
		},
		"two-letter city code to": {
			hostname: "cato2-auto-udp.ptoserver.com",
			country:  "Canada",
			city:     "Toronto",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			country, city, warnings := parseHostname(testCase.hostname)
			assert.Equal(t, testCase.country, country)
			assert.Equal(t, testCase.city, city)
			assert.Empty(t, warnings)
		})
	}
}

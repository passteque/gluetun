package updater

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_parseHostname(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		hostname string
		country  string
		city     string
	}{
		"country_only_no_city_code": {
			hostname: "ca2-auto-udp.ptoserver.com",
			country:  "Canada",
			city:     "",
		},
		"single_letter_city_code_q": {
			hostname: "caq2-auto-udp.ptoserver.com",
			country:  "Canada",
			city:     "Montreal",
		},
		"australia_brisbane_code_bb": {
			hostname: "aubb2-auto-udp.ptoserver.com",
			country:  "Australia",
			city:     "Brisbane",
		},
		"australia_brisbane_code_bn": {
			hostname: "aubn2-auto-udp.ptoserver.com",
			country:  "Australia",
			city:     "Brisbane",
		},
		"single_letter_city_code_v": {
			hostname: "cav2-auto-udp.ptoserver.com",
			country:  "Canada",
			city:     "Vancouver",
		},
		"two_letter_city_code_to": {
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

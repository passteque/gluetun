package updater

import (
	"fmt"
	"strings"

	"github.com/qdm12/gluetun/internal/constants"
)

var countryCodeToName = constants.CountryCodes() //nolint:gochecknoglobals

//nolint:gochecknoglobals
var countryCityCodeToCityName = map[string]string{
	"aume":  "Melbourne",
	"aupe":  "Perth",
	"aubb":  "Brisbane",
	"aubn":  "Brisbane",
	"ausd":  "Sydney",
	"caq":   "Montreal",
	"cato":  "Toronto",
	"cav":   "Vancouver",
	"ukl":   "London",
	"ukm":   "Manchester",
	"usca":  "Los Angeles",
	"usfl":  "Miami",
	"usga":  "Atlanta",
	"usil":  "Chicago",
	"usnj":  "Newark",
	"usny":  "New York",
	"uspe":  "Perth",
	"usphx": "Phoenix",
	"ussa":  "Seattle",
	"ussf":  "San Francisco",
	"ustx":  "Houston",
	"usut":  "Salt Lake City",
	"usva":  "Ashburn",
	"uswdc": "Washington DC",
}

func parseHostname(hostname string) (country, city string, warnings []string) {
	const minHostnameLength = 2 + 3 + 2 // 2 country code + 3 city code + "2-"
	if len(hostname) < minHostnameLength {
		warnings = append(warnings,
			fmt.Sprintf("hostname %q is too short to parse country and city codes", hostname))
	}
	countryCode := strings.ToLower(hostname[0:2])
	country, ok := countryCodeToName[countryCode]
	if !ok {
		warnings = append(warnings, fmt.Sprintf("unknown country code %q in hostname %q",
			countryCode, hostname))
	}

	twoMinusIndex := strings.Index(hostname, "2-")
	switch twoMinusIndex {
	case -1:
		warnings = append(warnings,
			fmt.Sprintf("hostname %q does not contain '2-'", hostname))
		return country, city, warnings
	case 2: //nolint:mnd
		// no city code
		return country, "", warnings
	}
	countryCityCode := strings.ToLower(hostname[:twoMinusIndex])
	city, ok = countryCityCodeToCityName[countryCityCode]
	if !ok {
		warnings = append(warnings, fmt.Sprintf("unknown country-city code %q in hostname %q",
			countryCityCode, hostname))
	}
	return country, city, warnings
}

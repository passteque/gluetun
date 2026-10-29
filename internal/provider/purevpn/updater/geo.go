package updater

import (
	"fmt"
	"strings"
)

func parseHostname(hostname string) (country, city string, warnings []string) {
	const (
		countryCodeLength = 2
		// Location codes are followed by a number and a dash, for example
		// `us2-udp.ptoserver.com` or `usva2-tcp.ptoserver.com`.
		locationSeparator = "2-"
	)

	if len(hostname) < countryCodeLength {
		return "", "", append(warnings,
			fmt.Sprintf("hostname %q is too short to contain a country code", hostname))
	}
	countryCode := strings.ToLower(hostname[:countryCodeLength])
	country, ok := countryCodeToName[countryCode]
	if !ok {
		warnings = append(warnings, fmt.Sprintf("unknown country code %q in hostname %q",
			countryCode, hostname))
	}

	twoMinusIndex := strings.Index(hostname, locationSeparator)
	switch twoMinusIndex {
	case -1:
		warnings = append(warnings,
			fmt.Sprintf("hostname %q does not contain %q", hostname, locationSeparator))
		return country, city, warnings
	case countryCodeLength:
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

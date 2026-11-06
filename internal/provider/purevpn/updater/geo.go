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
		// Virtual locations are PureVPN locations sold under a region name
		// instead of the country hosting them, for example a virtual Belgium
		// server sold under the European region, which physically terminates
		// in another country. Their hostname is prefixed with the region, for
		// example `vleu-be2-ovpn-tcp.pointtoserver.com`, which hides the
		// country code. They are kept since PureVPN applications offer them
		// under the same location name, and the real hosting country is used
		// here. Any other unknown prefix is left alone and the server is
		// discarded by [Updater.withLocations].
		virtualRegionPrefix = "vleu-"
	)

	location := hostname
	if stripped, found := strings.CutPrefix(location, virtualRegionPrefix); found {
		location = stripped
	}

	if len(location) < countryCodeLength {
		return "", "", append(warnings,
			fmt.Sprintf("hostname %q is too short to contain a country code", hostname))
	}
	countryCode := strings.ToLower(location[:countryCodeLength])
	country, ok := countryCodeToName[countryCode]
	if !ok {
		warnings = append(warnings, fmt.Sprintf("unknown country code %q in hostname %q",
			countryCode, hostname))
	}

	twoMinusIndex := strings.Index(location, locationSeparator)
	switch twoMinusIndex {
	case -1:
		warnings = append(warnings,
			fmt.Sprintf("hostname %q does not contain %q", hostname, locationSeparator))
		return country, city, warnings
	case countryCodeLength:
		return country, "", warnings
	}
	countryCityCode := strings.ToLower(location[:twoMinusIndex])
	city, ok = countryCityCodeToCityName[countryCityCode]
	if !ok {
		warnings = append(warnings, fmt.Sprintf("unknown country-city code %q in hostname %q",
			countryCityCode, hostname))
	}
	return country, city, warnings
}

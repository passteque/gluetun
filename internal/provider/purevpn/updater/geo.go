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

// locationWithRegion is a struct that represents a location with its country, city, and region,
// and is to be used to hardcoded locations with a region field set in older data (see [locationsWithRegions]).
// TODO v4: remove region field from purevpn.
type locationWithRegion struct {
	country string
	city    string
	region  string
}

var locationsWithRegions = []locationWithRegion{ //nolint:gochecknoglobals
	{country: "Albania", city: "Tirana", region: "Tirana"},
	{country: "Argentina", city: "Buenos Aires", region: "Buenos Aires F.D."},
	{country: "Australia", city: "Sydney", region: "New South Wales"},
	{country: "Australia", city: "Sydney", region: "New South Wales"},
	{country: "Australia", city: "Perth", region: "Western Australia"},
	{country: "Australia", city: "Perth", region: "Western Australia"},
	{country: "Australia", city: "Perth", region: "Western Australia"},
	{country: "Australia", city: "Perth", region: "Western Australia"},
	{country: "Austria", city: "Vienna", region: "Vienna"},
	{country: "Austria", city: "Vienna", region: "Vienna"},
	{country: "Belgium", city: "Zaventem", region: "Flanders"},
	{country: "Belgium", city: "Zaventem", region: "Flanders"},
	{country: "Brazil", city: "São Paulo", region: "São Paulo"},
	{country: "Brazil", city: "São Paulo", region: "São Paulo"},
	{country: "Bulgaria", city: "Sofia", region: "Sofia-Capital"},
	{country: "Bulgaria", city: "Sofia", region: "Sofia-Capital"},
	{country: "Canada", city: "Vancouver", region: "British Columbia"},
	{country: "Canada", city: "Toronto", region: "Ontario"},
	{country: "Chile", city: "Santiago", region: "Santiago Metropolitan"},
	{country: "Chile", city: "Santiago", region: "Santiago Metropolitan"},
	{country: "Czech Republic", city: "Prague", region: "Prague"},
	{country: "Czech Republic", city: "Prague", region: "Prague"},
	{country: "Denmark", city: "Copenhagen", region: "Capital Region"},
	{country: "Denmark", city: "Copenhagen", region: "Capital Region"},
	{country: "Estonia", city: "Tallinn", region: "Harjumaa"},
	{country: "Estonia", city: "Tallinn", region: "Harjumaa"},
	{country: "Finland", city: "Helsinki", region: "Uusimaa"},
	{country: "Finland", city: "Helsinki", region: "Uusimaa"},
	{country: "France", city: "Paris", region: "Île-de-France"},
	{country: "France", city: "Paris", region: "Île-de-France"},
	{country: "Germany", city: "Frankfurt am Main", region: "Hesse"},
	{country: "Germany", city: "Frankfurt am Main", region: "Hesse"},
	{country: "Greece", city: "Athens", region: "Attica"},
	{country: "Greece", city: "Athens", region: "Attica"},
	{country: "Hong Kong", city: "Hong Kong", region: "Hong Kong"},
	{country: "Hong Kong", city: "Tung Chung", region: "Islands"},
	{country: "Hungary", city: "Budapest", region: "Budapest"},
	{country: "Hungary", city: "Budapest", region: "Budapest"},
	{country: "Ireland", city: "Dublin", region: "Leinster"},
	{country: "Ireland", city: "Dublin", region: "Leinster"},
	{country: "Italy", city: "Figino", region: "Lombardy"},
	{country: "Italy", city: "Milan", region: "Lombardy"},
	{country: "Japan", city: "Tokyo", region: "Tokyo"},
	{country: "Japan", city: "Tokyo", region: "Tokyo"},
	{country: "Korea", city: "Seoul", region: "Seoul"},
	{country: "Korea", city: "Seoul", region: "Seoul"},
	{country: "Latvia", city: "Riga", region: "Riga"},
	{country: "Latvia", city: "Riga", region: "Riga"},
	{country: "Lithuania", city: "Vilnius", region: "Vilnius"},
	{country: "Lithuania", city: "Vilnius", region: "Vilnius"},
	{country: "Luxembourg", city: "Luxembourg", region: "Luxembourg"},
	{country: "Luxembourg", city: "Luxembourg", region: "Luxembourg"},
	{country: "Moldova", city: "Chisinau", region: "Chișinău Municipality"},
	{country: "Moldova", city: "Chisinau", region: "Chișinău Municipality"},
	{country: "Netherlands", city: "Lelystad", region: "Flevoland"},
	{country: "Netherlands", city: "Amsterdam", region: "North Holland"},
	{country: "Nigeria", city: "Lagos", region: "Lagos"},
	{country: "Nigeria", city: "Lagos", region: "Lagos"},
	{country: "Norway", city: "Oslo", region: "Oslo"},
	{country: "Norway", city: "Oslo", region: "Oslo"},
	{country: "Poland", city: "Włochy", region: "Mazovia"},
	{country: "Poland", city: "Włochy", region: "Mazovia"},
	{country: "Romania", city: "Bucharest", region: "București"},
	{country: "Romania", city: "Bucharest", region: "București"},
	{country: "Serbia", city: "Belgrade", region: "Central Serbia"},
	{country: "Serbia", city: "Belgrade", region: "Central Serbia"},
	{country: "Singapore", city: "Singapore", region: "Singapore"},
	{country: "Singapore", city: "Singapore", region: "Singapore"},
	{country: "Slovakia", city: "Bratislava", region: "Bratislava Region"},
	{country: "Slovakia", city: "Bratislava", region: "Bratislava Region"},
	{country: "South Africa", city: "Johannesburg", region: "Gauteng"},
	{country: "South Africa", city: "Johannesburg", region: "Gauteng"},
	{country: "Spain", city: "Madrid", region: "Madrid"},
	{country: "Spain", city: "Madrid", region: "Madrid"},
	{country: "Sweden", city: "Stockholm", region: "Stockholm"},
	{country: "Sweden", city: "Stockholm", region: "Stockholm"},
	{country: "Switzerland", city: "Zürich", region: "Zurich"},
	{country: "Switzerland", city: "Zürich", region: "Zurich"},
	{country: "Turkey", city: "Istanbul", region: "Istanbul"},
	{country: "Turkey", city: "Istanbul", region: "Istanbul"},
	{country: "United Arab Emirates", city: "Dubai", region: "Dubai"},
	{country: "United Arab Emirates", city: "Dubai", region: "Dubai"},
	{country: "United Kingdom", city: "London", region: "England"},
	{country: "United Kingdom", city: "London", region: "England"},
	{country: "United Kingdom", city: "London", region: "England"},
	{country: "United Kingdom", city: "Manchester", region: "England"},
	{country: "United Kingdom", city: "Manchester", region: "England"},
	{country: "United Kingdom", city: "Manchester", region: "England"},
	{country: "United States", city: "Phoenix", region: "Arizona"},
	{country: "United States", city: "Phoenix", region: "Arizona"},
	{country: "United States", city: "Phoenix", region: "Arizona"},
	{country: "United States", city: "Los Angeles", region: "California"},
	{country: "United States", city: "Los Angeles", region: "California"},
	{country: "United States", city: "Miami", region: "Florida"},
	{country: "United States", city: "Miami", region: "Florida"},
	{country: "United States", city: "Atlanta", region: "Georgia"},
	{country: "United States", city: "Atlanta", region: "Georgia"},
	{country: "United States", city: "Chicago", region: "Illinois"},
	{country: "United States", city: "Chicago", region: "Illinois"},
	{country: "United States", city: "Secaucus", region: "New Jersey"},
	{country: "United States", city: "Houston", region: "Texas"},
	{country: "United States", city: "Houston", region: "Texas"},
	{country: "United States", city: "Salt Lake City", region: "Utah"},
	{country: "United States", city: "Salt Lake City", region: "Utah"},
	{country: "United States", city: "Ashburn", region: "Virginia"},
	{country: "United States", city: "Ashburn", region: "Virginia"},
	{country: "United States", city: "Seattle", region: "Washington"},
	{country: "United States", city: "Seattle", region: "Washington"},
}

func getRegionFromCountryCity(country, city string) (region string) {
	for _, location := range locationsWithRegions {
		if comparePlaceNames(location.country, country) && comparePlaceNames(location.city, city) {
			return location.region
		}
	}
	return ""
}

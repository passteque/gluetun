package updater

import (
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

// locationWithRegion is a struct that represents a location with its country, city, and region,
// and is used to populate hardcoded locations with a region field set in older data (see [locationsWithRegions]).
// TODO v4: remove region field from purevpn.
type locationWithRegion struct {
	country string
	city    string
	region  string
}

var locationsWithRegions = []locationWithRegion{ //nolint:gochecknoglobals
	{country: "Afghanistan", city: "Kabul", region: "Kabul"},
	{country: "Albania", city: "Tirana", region: "Tirana"},
	{country: "Algeria", city: "Algiers", region: "Algiers"},
	{country: "Angola", city: "Benguela", region: "Benguela"},
	{country: "Argentina", city: "Buenos Aires", region: "Buenos Aires F.D."},
	{country: "Australia", city: "Brisbane", region: "Queensland"},
	{country: "Australia", city: "Melbourne", region: "Victoria"},
	{country: "Australia", city: "Sydney", region: "New South Wales"},
	{country: "Australia", city: "Perth", region: "Western Australia"},
	{country: "Austria", city: "Vienna", region: "Vienna"},
	{country: "Bahamas", city: "Freeport", region: "Grand Bahama"},
	{country: "Bahrain", city: "Manama", region: "Manama"},
	{country: "Bangladesh", city: "Dhaka", region: "Dhaka"},
	{country: "Belgium", city: "Zaventem", region: "Flanders"},
	{country: "Bolivia", city: "Sucre", region: "Chuquisaca"},
	{country: "Brazil", city: "São Paulo", region: "São Paulo"},
	{country: "Bulgaria", city: "Sofia", region: "Sofia-Capital"},
	{country: "Canada", city: "Montreal", region: "Quebec"},
	{country: "Canada", city: "Vancouver", region: "British Columbia"},
	{country: "Canada", city: "Toronto", region: "Ontario"},
	{country: "Chile", city: "Santiago", region: "Santiago Metropolitan"},
	{country: "China", city: "Beijing", region: "Beijing"},
	{country: "Czech Republic", city: "Prague", region: "Prague"},
	{country: "Denmark", city: "Copenhagen", region: "Capital Region"},
	{country: "Egypt", city: "Cairo", region: "Cairo"},
	{country: "Estonia", city: "Tallinn", region: "Harjumaa"},
	{country: "Finland", city: "Espoo", region: "Uusimaa"},
	{country: "Finland", city: "Helsinki", region: "Uusimaa"},
	{country: "France", city: "Paris", region: "Île-de-France"},
	{country: "Germany", city: "Frankfurt", region: "Hesse"},
	{country: "Germany", city: "Frankfurt am Main", region: "Hesse"},
	{country: "Greece", city: "Athens", region: "Attica"},
	{country: "Hong Kong", city: "Hong Kong", region: "Hong Kong"},
	{country: "Hong Kong", city: "Tung Chung", region: "Islands"},
	{country: "Hungary", city: "Budapest", region: "Budapest"},
	{country: "India", city: "Mumbai", region: "Maharashtra"},
	{country: "Ireland", city: "Dublin", region: "Leinster"},
	{country: "Italy", city: "Figino", region: "Lombardy"},
	{country: "Italy", city: "Milan", region: "Lombardy"},
	{country: "Japan", city: "Tokyo", region: "Tokyo"},
	{country: "Korea", city: "Seoul", region: "Seoul"},
	{country: "Latvia", city: "Riga", region: "Riga"},
	{country: "Lithuania", city: "Vilnius", region: "Vilnius"},
	{country: "Luxembourg", city: "Luxembourg", region: "Luxembourg"},
	{country: "Moldova", city: "Chisinau", region: "Chișinău Municipality"},
	{country: "Monaco", city: "Monaco", region: "Monaco"},
	{country: "Netherlands", city: "Lelystad", region: "Flevoland"},
	{country: "Netherlands", city: "Amsterdam", region: "North Holland"},
	{country: "Nigeria", city: "Lagos", region: "Lagos"},
	{country: "Norway", city: "Oslo", region: "Oslo"},
	{country: "Oman", city: "Salalah", region: "Dhofar"},
	{country: "Panama", city: "Panama City", region: "Panama"},
	{country: "Philippines", city: "Manila", region: "Metro Manila"},
	{country: "Poland", city: "Warsaw", region: "Mazovia"},
	{country: "Poland", city: "Włochy", region: "Mazovia"},
	{country: "Portugal", city: "Lisbon", region: "Lisbon"},
	{country: "Romania", city: "Bucharest", region: "București"},
	{country: "Russian Federation", city: "Moscow", region: "Moscow"},
	{country: "Serbia", city: "Belgrade", region: "Central Serbia"},
	{country: "Singapore", city: "Singapore", region: "Singapore"},
	{country: "Slovakia", city: "Bratislava", region: "Bratislava Region"},
	{country: "South Africa", city: "Johannesburg", region: "Gauteng"},
	{country: "Spain", city: "Madrid", region: "Madrid"},
	{country: "Sweden", city: "Stockholm", region: "Stockholm"},
	{country: "Switzerland", city: "Zürich", region: "Zurich"},
	{country: "Turkey", city: "Istanbul", region: "Istanbul"},
	{country: "United Arab Emirates", city: "Dubai", region: "Dubai"},
	{country: "United Kingdom", city: "London", region: "England"},
	{country: "United Kingdom", city: "Manchester", region: "England"},
	{country: "United States", city: "New York", region: "New York"},
	{country: "United States", city: "Newark", region: "New Jersey"},
	{country: "United States", city: "Phoenix", region: "Arizona"},
	{country: "United States", city: "Los Angeles", region: "California"},
	{country: "United States", city: "Miami", region: "Florida"},
	{country: "United States", city: "Atlanta", region: "Georgia"},
	{country: "United States", city: "Chicago", region: "Illinois"},
	{country: "United States", city: "San Francisco", region: "California"},
	{country: "United States", city: "Secaucus", region: "New Jersey"},
	{country: "United States", city: "Houston", region: "Texas"},
	{country: "United States", city: "Salt Lake City", region: "Utah"},
	{country: "United States", city: "Ashburn", region: "Virginia"},
	{country: "United States", city: "Seattle", region: "Washington"},
	{country: "Vietnam", city: "Hanoi", region: "Hanoi"},
}

func getRegionFromCountryCity(country, city string) (region string) {
	for _, location := range locationsWithRegions {
		if comparePlaceNames(location.country, country) && comparePlaceNames(location.city, city) {
			return location.region
		}
	}
	return ""
}

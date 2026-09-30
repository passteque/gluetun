package updater

import (
	"fmt"
	"strings"

	"github.com/qdm12/gluetun/internal/models"
)

// generateCandidateHostnames generates multiple hostname candidates for a given location
// by trying different slug variations, number suffixes, and country aliases.
func generateCandidateHostnames(server models.Server) (hostnames []string, err error) {
	country := strings.ToLower(server.Country)
	city := strings.ToLower(server.City)

	if strings.Contains(country, " (via ") {
		destinationEndIndex := strings.Index(country, " (via ")
		destination := strings.TrimSpace(country[:destinationEndIndex])
		destination = strings.ReplaceAll(destination, " ", "")

		sourceEndIndex := strings.Index(country[destinationEndIndex:], ")")
		if sourceEndIndex == -1 {
			return nil, fmt.Errorf("invalid location format, missing closing parenthesis for source: %q", country)
		}
		source := strings.TrimSpace(country[destinationEndIndex+len(" (via ") : destinationEndIndex+sourceEndIndex])
		source = strings.ReplaceAll(source, " ", "")

		sourceAliases := countryNameToAliases(source)
		sources := make([]string, 0, 1+len(sourceAliases))
		sources = append(sources, source)
		sources = append(sources, sourceAliases...)
		destinationAliases := countryNameToAliases(destination)
		destinations := make([]string, 0, 1+len(destinationAliases))
		destinations = append(destinations, destination)
		destinations = append(destinations, destinationAliases...)

		slugs := make([]string, 0, (1+len(sourceAliases))*(1+len(destinationAliases)))
		for _, destination := range destinations {
			for _, source := range sources {
				slugs = append(slugs, destination+"-"+source)
			}
		}

		if city != "" {
			return nil, fmt.Errorf("city %q should be empty for multi-hop country: %s", city, country)
		}

		return makeNumberedCandidates(slugs, server.Number), nil
	}

	countrySlug := strings.ReplaceAll(strings.TrimSpace(country), " ", "")
	countrySlugAliases := countryNameToAliases(countrySlug)
	countrySlugs := make([]string, 0, 1+len(countrySlugAliases))
	countrySlugs = append(countrySlugs, countrySlug)
	countrySlugs = append(countrySlugs, countrySlugAliases...)

	var citySlugs []string
	if city != "" {
		if strings.Contains(city, " ") {
			citySlugs = append(citySlugs, strings.ReplaceAll(city, " ", ""))
			citySlugs = append(citySlugs, strings.ReplaceAll(city, " ", "-"))
		} else {
			citySlugs = append(citySlugs, city)
		}
	}

	var slugs []string
	if len(citySlugs) == 0 {
		slugs = countrySlugs
	} else {
		slugs = make([]string, 0, len(countrySlugs)*len(citySlugs))
		for _, countrySlug := range countrySlugs {
			for _, citySlug := range citySlugs {
				slugs = append(slugs, countrySlug+"-"+citySlug)
			}
		}
	}

	return makeNumberedCandidates(slugs, server.Number), nil
}

func makeNumberedCandidates(baseSlugs []string, serverNumber uint16) (candidates []string) {
	numbersToTry := []uint16{1, 2, 3, 4, 5}
	if serverNumber > 0 {
		numbersToTry = []uint16{serverNumber}
	}
	const candidateVariationsPerNumber = 2                                           // slugN and slug-N
	candidateVariationsPerBase := 1 + len(numbersToTry)*candidateVariationsPerNumber // base + (slugN and slug-N for each number)
	candidates = make([]string, 0, len(baseSlugs)*candidateVariationsPerBase)
	for _, base := range baseSlugs {
		candidates = append(candidates, base+hostnameSuffix)
		for _, number := range numbersToTry {
			candidates = append(candidates,
				base+fmt.Sprintf("%d-ca-version-2.expressnetw.com", number),
				base+fmt.Sprintf("-%d-ca-version-2.expressnetw.com", number))
		}
	}
	return candidates
}

// hostnameSuffix is appended to all ExpressVPN hostnames.
const hostnameSuffix = "-ca-version-2.expressnetw.com"

// countryNameToAliases maps common country names to alternative names used in hostnames.
func countryNameToAliases(country string) (aliases []string) {
	switch country {
	case "usa":
		return []string{"us"}
	case "uk":
		return []string{"gb"}
	case "netherlands":
		return []string{"nl"}
	case "switzerland":
		return []string{"ch"}
	case "japan":
		return []string{"jp"}
	case "sweden":
		return []string{"se"}
	case "norway":
		return []string{"no"}
	case "denmark":
		return []string{"dk"}
	case "finland":
		return []string{"fi"}
	case "portugal":
		return []string{"pt"}
	case "spain":
		return []string{"es"}
	case "germany":
		return []string{"de"}
	case "italy":
		return []string{"it"}
	case "australia":
		return []string{"au"}
	case "singapore":
		return []string{"sg"}
	case "taiwan":
		return []string{"tw"}
	case "southkorea":
		return []string{"kr"}
	case "northmacedonia":
		return []string{"macedonia"}
	default:
		return nil
	}
}

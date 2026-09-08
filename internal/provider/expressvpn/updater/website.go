package updater

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	htmlutils "github.com/qdm12/gluetun/internal/updater/html"
	"golang.org/x/net/html"
)

func fetchServersFromWebsite(ctx context.Context, client *http.Client) (
	servers []models.Server, warnings []string, err error,
) {
	const url = "https://www.expressvpn.com/vpn-server"
	rootNode, err := htmlutils.Fetch(ctx, client, url)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching HTML code: %w", err)
	}

	servers, warnings = parseServerListTable(rootNode)

	return servers, warnings, nil
}

func parseServerListTable(rootNode *html.Node) (
	servers []models.Server, warnings []string,
) {
	// Collect all tr nodes from all tbody elements using recursive walk
	var allRows []*html.Node
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Data == "tr" {
			allRows = append(allRows, n)
			return
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(rootNode)

	seenLocations := make(map[string]struct{})
	for _, trNode := range allRows {
		serverLocation := strings.TrimSpace(htmlutils.Attribute(trNode, "data-server-location"))
		if serverLocation == "" {
			continue
		}

		country, city, number, err := parseLocation(serverLocation)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("parsing location: %s", err))
			continue
		}
		server := models.Server{
			VPN:     vpn.OpenVPN,
			TCP:     true,
			UDP:     true,
			Country: country,
			City:    city,
			Number:  number,
		}

		locationKey := fmt.Sprintf("%s-%s-%d", country, city, number)
		if _, ok := seenLocations[locationKey]; ok {
			continue
		}
		seenLocations[locationKey] = struct{}{}
		servers = append(servers, server)
	}

	return servers, warnings
}

func parseLocation(location string) (country, city string, number uint16, err error) {
	// Location formats:
	// - "Argentina" -> country="Argentina", city="", number=0
	// - "Australia - Adelaide" -> country="Australia", city="Adelaide", number=0
	// - "Canada - Toronto" -> country="Canada", city="Toronto", number=0
	parts := strings.Split(location, " - ")
	country = strings.TrimSpace(parts[0])
	switch len(parts) {
	case 1: // country only
		if strings.Contains(country, " [") {
			// This can be "country [city]"
			parts := strings.SplitN(country, " [", 2)
			country = strings.TrimSpace(parts[0])
			city = strings.TrimSuffix(strings.TrimSpace(parts[1]), "]")
		}
	case 2: // country and city
		city = strings.TrimSpace(parts[1])
	case 3: // country, city, and number
		city = strings.TrimSpace(parts[1])
		fmt.Sscanf(strings.TrimSpace(parts[2]), "%d", &number)
	default:
		return "", "", 0, fmt.Errorf("invalid location format: %q", location)
	}

	// Retro-compatibility transforms
	switch strings.ToLower(country) {
	case "united states":
		country = "USA"
	case "united kingdom":
		country = "UK"
	}

	return country, city, number, nil
}

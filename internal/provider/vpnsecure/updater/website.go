package updater

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/common"
	htmlutils "github.com/qdm12/gluetun/internal/updater/html"
	"golang.org/x/net/html"
)

func fetchServers(ctx context.Context, client *http.Client,
	warner common.Warner,
) (servers []models.Server, err error) {
	const url = "https://www.vpnsecure.me/locations/"
	rootNode, err := htmlutils.Fetch(ctx, client, url)
	if err != nil {
		return nil, fmt.Errorf("fetching HTML code: %w", err)
	}

	servers, warnings, err := parseHTML(rootNode)
	for _, warning := range warnings {
		warner.Warn(warning)
	}
	if err != nil {
		return nil, fmt.Errorf("parsing HTML code: %w", err)
	}

	return servers, nil
}

const divString = "div"

func parseHTML(rootNode *html.Node) (servers []models.Server,
	warnings []string, err error,
) {
	// Find div container for all servers, searching with BFS.
	serversDiv := htmlutils.BFS(rootNode, htmlutils.MatchID("servers"))
	if serversDiv == nil {
		return nil, nil, htmlutils.WrapError(errors.New("HTML servers container div not found"), rootNode)
	}

	for countryNode := serversDiv.FirstChild; countryNode != nil; countryNode = countryNode.NextSibling {
		if countryNode.Data != divString ||
			!htmlutils.HasClassStrings(countryNode, "box", "dark-gray") {
			continue
		}

		country := findCountry(countryNode)
		if country == "" {
			warnings = append(warnings, htmlutils.WrapWarning("country not found", countryNode))
			continue
		}

		// Find all server tables within this country container
		for serverNode := countryNode.FirstChild; serverNode != nil; serverNode = serverNode.NextSibling {
			if serverNode.Data != divString {
				continue
			}
			if !htmlutils.HasClassStrings(serverNode, "box", "white") {
				continue
			}

			server, warning := parseServerNode(serverNode, country)
			if warning != "" {
				warnings = append(warnings, warning)
				continue
			}
			servers = append(servers, server)
		}
	}

	return servers, warnings, nil
}

func parseServerNode(node *html.Node, country string) (
	server models.Server, warning string,
) {
	// Find the table within this server box
	tableNode := htmlutils.DirectChild(node, func(n *html.Node) bool {
		return n != nil && n.Data == "table"
	})
	if tableNode == nil {
		return server, htmlutils.WrapWarning("server table not found", node)
	}

	// Check status from green-circle in thead
	isUp := hasGreenCircle(tableNode)
	if !isUp {
		warning := "skipping server which is not up"
		return server, htmlutils.WrapWarning(warning, tableNode)
	}

	// Extract city from thead
	city := findCity(tableNode)
	if city == "" {
		return server, htmlutils.WrapWarning("city not found", tableNode)
	}

	// Extract server identifier (e.g., "AU #01") from thead
	serverID := findServerID(tableNode)
	if serverID == "" {
		return server, htmlutils.WrapWarning("server ID not found", tableNode)
	}

	hostname, err := buildHostname(serverID)
	if err != nil {
		return server, htmlutils.WrapWarning(fmt.Sprintf("invalid server ID %q: %v", serverID, err), tableNode)
	}

	// Check for Dedicated IP feature (maps to Premium)
	premium := hasFeature(tableNode, "Dedicated IP")

	return models.Server{
		Country:  country,
		City:     city,
		Hostname: hostname,
		Premium:  premium,
	}, ""
}

var serverIDPattern = regexp.MustCompile(`^([A-Z]{2})\s*#\s*(\d+)$`)

func buildHostname(serverID string) (string, error) {
	const expectedSubmatches = 3
	matches := serverIDPattern.FindStringSubmatch(serverID)
	if len(matches) != expectedSubmatches {
		return "", errors.New("unexpected format")
	}
	countryCode := strings.ToLower(matches[1])
	serverNum := strings.TrimLeft(matches[2], "0")
	return fmt.Sprintf("%s%s.isponeder.com", countryCode, serverNum), nil
}

func findCountry(countryNode *html.Node) (country string) {
	h3Node := htmlutils.DirectChild(countryNode, func(n *html.Node) bool {
		return n != nil && n.Data == "h3"
	})
	if h3Node == nil {
		return ""
	}

	// Extract text content from h3, trimming the flag emoji and whitespace
	var sb strings.Builder
	for child := h3Node.FirstChild; child != nil; child = child.NextSibling {
		if child.Type == html.TextNode {
			sb.WriteString(child.Data)
		}
	}
	country = strings.TrimSpace(sb.String())
	// Strip leading emoji (flag) - flags are typically composed emoji characters
	for len(country) > 0 {
		r, size := utf8.DecodeRuneInString(country)
		if !isEmojiRune(r) {
			break
		}
		country = country[size:]
	}
	country = strings.TrimSpace(country)
	return country
}

func findCity(tableNode *html.Node) (city string) {
	const minThCount = 2
	theadNode := htmlutils.DirectChild(tableNode, func(n *html.Node) bool {
		return n != nil && n.Data == "thead"
	})
	if theadNode == nil {
		return ""
	}

	// Find the second <th> which contains the city name
	thNodes := htmlutils.BFS(theadNode, func(n *html.Node) bool {
		return n != nil && n.Data == "th"
	})
	if thNodes == nil {
		return ""
	}

	// Collect th nodes in order
	var ths []*html.Node
	for node := thNodes; node != nil; node = node.NextSibling {
		if node.Data == "th" {
			ths = append(ths, node)
		}
	}
	if len(ths) < minThCount {
		return ""
	}

	// Second th contains the city
	return strings.TrimSpace(getTextContent(ths[1]))
}

func findServerID(tableNode *html.Node) (serverID string) {
	theadNode := htmlutils.DirectChild(tableNode, func(n *html.Node) bool {
		return n != nil && n.Data == "thead"
	})
	if theadNode == nil {
		return ""
	}

	// Find the right-aligned th which contains the server ID
	for node := htmlutils.BFS(theadNode, func(n *html.Node) bool {
		return n != nil && n.Data == "th"
	}); node != nil; node = node.NextSibling {
		if node.Data == "th" && htmlutils.HasClassStrings(node, "right") {
			return strings.TrimSpace(getTextContent(node))
		}
	}

	return ""
}

func hasGreenCircle(tableNode *html.Node) bool {
	return htmlutils.BFS(tableNode, func(n *html.Node) bool {
		return n != nil && n.Data == "div" &&
			htmlutils.HasClassStrings(n, "green-circle")
	}) != nil
}

func hasFeature(tableNode *html.Node, featureName string) bool {
	tbodyNode := htmlutils.DirectChild(tableNode, func(n *html.Node) bool {
		return n != nil && n.Data == "tbody"
	})
	if tbodyNode == nil {
		return false
	}

	for trNode := tbodyNode.FirstChild; trNode != nil; trNode = trNode.NextSibling {
		if trNode.Data != "tr" {
			continue
		}

		// Collect td cells in this row
		var tds []*html.Node
		for tdNode := trNode.FirstChild; tdNode != nil; tdNode = tdNode.NextSibling {
			if tdNode.Data == "td" {
				tds = append(tds, tdNode)
			}
		}
		if len(tds) == 0 {
			continue
		}

		feature := strings.TrimSpace(getTextContent(tds[0]))
		if feature != featureName {
			continue
		}

		// If only one td with colspan spanning columns, feature exists
		if len(tds) == 1 && htmlutils.Attribute(tds[0], "colspan") != "" {
			return true
		}

		// Otherwise check for pink-check icon in subsequent td cells
		for _, td := range tds[1:] {
			if htmlutils.BFS(td, func(n *html.Node) bool {
				return n != nil && n.Data == "img" &&
					strings.Contains(htmlutils.Attribute(n, "src"), "pink-check")
			}) != nil {
				return true
			}
		}
	}

	return false
}

func getTextContent(node *html.Node) string {
	var sb strings.Builder
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if child.Type == html.TextNode {
			sb.WriteString(child.Data)
		}
	}
	return sb.String()
}

func isEmojiRune(r rune) bool {
	for _, rangeStart := range []struct{ lo, hi rune }{
		// Emoticons
		{0x1F600, 0x1F64F},
		// Misc Symbols and Pictographs
		{0x1F300, 0x1F5FF},
		// Transport and Map Symbols
		{0x1F680, 0x1F6FF},
		// Flags (regional indicator symbols + flag emojis)
		{0x1F1E0, 0x1F1FF},
		{0x1F100, 0x1F10A},
		// Supplemental Symbols
		{0x1F900, 0x1F9FF},
	} {
		if r >= rangeStart.lo && r <= rangeStart.hi {
			return true
		}
	}
	// Catch-all for non-ASCII emoji using Unicode category
	if r > 0x7E && unicode.In(r, unicode.So) {
		return true
	}
	return false
}

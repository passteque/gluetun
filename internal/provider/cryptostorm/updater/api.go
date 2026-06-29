package updater

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	htmlutils "github.com/qdm12/gluetun/internal/updater/html"
	"golang.org/x/net/html"
)

// nodeData represents one entry parsed from the Cryptostorm wireguard page.
type nodeData struct {
	Location string // e.g. "Canada - Montreal", "Austria", "US - Texas - Dallas"
	Hostname string // e.g. "austria.cstorm.is"
	WgPubKey string
}

// fetchNodes retrieves and parses the Cryptostorm node list from their
// wireguard page at https://cryptostorm.is/wireguard.
func fetchNodes(ctx context.Context, client *http.Client) (
	nodes []nodeData, warnings []string, err error) {
	const url = "https://cryptostorm.is/wireguard"

	rootNode, err := htmlutils.Fetch(ctx, client, url)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching HTML: %w", err)
	}

	nodes, warnings, err = parseHTML(rootNode)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing HTML: %w", err)
	}
	return nodes, warnings, nil
}

func parseHTML(rootNode *html.Node) (nodes []nodeData,
	warnings []string, err error) {
	tableNode := htmlutils.BFS(rootNode, htmlutils.MatchData("table"))
	if tableNode == nil {
		return nil, nil, fmt.Errorf("HTML server table not found")
	}

	// html.Parse inserts <tbody> per the HTML5 spec, so <tr> elements
	// are not direct children of <table>.
	tbody := htmlutils.DirectChild(tableNode, htmlutils.MatchData("tbody"))
	rowParent := tableNode
	if tbody != nil {
		rowParent = tbody
	}
	rows := htmlutils.DirectChildren(rowParent, htmlutils.MatchData("tr"))
	nodes = make([]nodeData, 0, len(rows)-1)
	for _, row := range rows[1:] { // skip header row
		cells := htmlutils.DirectChildren(row, htmlutils.MatchData("td"))
		const expectedCells = 3
		if len(cells) != expectedCells {
			warnings = append(warnings,
				htmlutils.WrapWarning(fmt.Sprintf("expected %d cells but got %d",
					expectedCells, len(cells)), row))
			continue
		}

		location := strings.TrimSpace(textContent(cells[0]))
		// Remove non-breaking spaces left over from &nbsp; entities.
		location = strings.ReplaceAll(location, "\u00a0", "")
		location = strings.TrimSpace(location)
		hostname := strings.TrimSpace(textContent(cells[1]))
		wgPubKey := strings.TrimSpace(textContent(cells[2]))

		switch {
		case location == "":
			warnings = append(warnings,
				htmlutils.WrapWarning("empty location", row))
			continue
		case hostname == "":
			warnings = append(warnings,
				htmlutils.WrapWarning("empty hostname", row))
			continue
		}

		nodes = append(nodes, nodeData{
			Location: location,
			Hostname: hostname,
			WgPubKey: wgPubKey,
		})
	}

	return nodes, warnings, nil
}

// textContent returns the concatenated text content of a node and
// all its descendants, similar to the DOM's textContent property.
func textContent(node *html.Node) string {
	if node == nil {
		return ""
	}
	if node.Type == html.TextNode {
		return node.Data
	}
	var sb strings.Builder
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		sb.WriteString(textContent(child))
	}
	return sb.String()
}

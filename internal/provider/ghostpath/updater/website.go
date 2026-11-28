package updater

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/common"
	htmlutils "github.com/qdm12/gluetun/internal/updater/html"
	"golang.org/x/net/html"
)

func fetchServers(ctx context.Context, client *http.Client,
	warner common.Warner,
) (servers []models.Server, err error) {
	const url = "https://ghostpath.com/servers"
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

var errNoServerRow = errors.New("no server row found")

// parseHTML parses the table rows of the servers page, each row having
// the cells: country, city, hostname, protocols and configuration file links.
func parseHTML(rootNode *html.Node) (servers []models.Server,
	warnings []string, err error,
) {
	rows := findAll(rootNode, "tr")
	for _, row := range rows {
		cells := htmlutils.DirectChildren(row, htmlutils.MatchData("td"))
		const expectedCells = 4
		if len(cells) < expectedCells {
			continue // header row or unrelated table
		}

		hostname := textContent(cells[2])
		if !strings.HasSuffix(hostname, ".gpvpn.com") {
			warnings = append(warnings, htmlutils.WrapWarning(
				"unexpected hostname "+hostname, row))
			continue
		}

		if !strings.Contains(textContent(cells[3]), "OpenVPN") {
			continue
		}

		servers = append(servers, models.Server{
			Country:  textContent(cells[0]),
			City:     textContent(cells[1]),
			Hostname: hostname,
		})
	}

	if len(servers) == 0 {
		return nil, warnings, htmlutils.WrapError(errNoServerRow, rootNode)
	}

	return servers, warnings, nil
}

func findAll(node *html.Node, data string) (found []*html.Node) {
	if htmlutils.MatchData(data)(node) {
		found = append(found, node)
	}
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		found = append(found, findAll(child, data)...)
	}
	return found
}

func textContent(node *html.Node) (text string) {
	var builder strings.Builder
	var walk func(current *html.Node)
	walk = func(current *html.Node) {
		if current.Type == html.TextNode {
			builder.WriteString(current.Data)
		}
		for child := current.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(node)
	return strings.TrimSpace(builder.String())
}

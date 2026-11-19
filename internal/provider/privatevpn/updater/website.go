package updater

import (
	"context"
	"errors"
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
	const url = "https://help.privatevpn.com/en/articles/302378-privatevpn-server-list"
	rootNode, err := htmlutils.Fetch(ctx, client, url)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching HTML code: %w", err)
	}

	servers, warnings, err = parseServerListTable(rootNode)
	if err != nil {
		return nil, warnings, fmt.Errorf("parsing HTML code: %w", err)
	}

	return servers, warnings, nil
}

func parseServerListTable(rootNode *html.Node) (
	servers []models.Server, warnings []string, err error,
) {
	// Find the article_body div which contains the server list table
	// This avoids picking up the footer contact table which also exists on the page
	articleBodyNode := htmlutils.BFS(rootNode, func(node *html.Node) bool {
		return htmlutils.HasClassStrings(node, "article_body")
	})
	if articleBodyNode == nil {
		return nil, nil, htmlutils.WrapError(errors.New("article body not found"), rootNode)
	}

	// Find the table within the article body
	tableNode := htmlutils.BFS(articleBodyNode, htmlutils.MatchData("table"))
	if tableNode == nil {
		return nil, nil, htmlutils.WrapError(errors.New("server list table not found in article body"), articleBodyNode)
	}

	tbodyNode := htmlutils.DirectChild(tableNode, htmlutils.MatchData("tbody"))
	if tbodyNode == nil {
		return nil, nil, htmlutils.WrapError(errors.New("table body not found"), tableNode)
	}

	// Iterate through each row in the table body
	skipHeader := true
	for trNode := tbodyNode.FirstChild; trNode != nil; trNode = trNode.NextSibling {
		if trNode.Data != "tr" {
			continue
		}

		if skipHeader {
			skipHeader = false
			continue
		}

		server, warning := parseServerRow(trNode)
		if warning != "" {
			warnings = append(warnings, warning)
			continue
		}
		servers = append(servers, server)
	}

	return servers, warnings, nil
}

func parseServerRow(trNode *html.Node) (server models.Server, warning string) {
	// Get all td cells in this row
	var tds []*html.Node
	for tdNode := trNode.FirstChild; tdNode != nil; tdNode = tdNode.NextSibling {
		if tdNode.Data == "td" {
			tds = append(tds, tdNode)
		}
	}

	const expectedCellCount = 2
	if len(tds) != expectedCellCount {
		return models.Server{}, htmlutils.WrapWarning("expected 2 cells in row", trNode)
	}

	// First cell: Location (format: "Country - City" or just "Country")
	location := extractTextFromCell(tds[0])
	if location == "" {
		return models.Server{}, htmlutils.WrapWarning("empty location cell", trNode)
	}

	// Second cell: Server Address (hostname ending in .pvdata.host)
	hostname := extractTextFromCell(tds[1])
	if hostname == "" {
		return models.Server{}, htmlutils.WrapWarning("empty server address cell", trNode)
	}
	hostname = strings.TrimSpace(hostname)

	country, city := parseLocation(location)

	return models.Server{
		VPN:      vpn.OpenVPN,
		TCP:      true, // port 443
		UDP:      true, // port 1194
		Country:  country,
		City:     city,
		Hostname: hostname,
	}, ""
}

func parseLocation(location string) (country, city string) {
	const separator = " - "
	parts := strings.SplitN(location, separator, 2) //nolint:mnd
	country = strings.TrimSpace(parts[0])

	if len(parts) > 1 {
		city = strings.TrimSpace(parts[1])
	}

	return country, city
}

func extractTextFromCell(tdNode *html.Node) string {
	var sb strings.Builder
	extractText(tdNode, &sb)
	return strings.TrimSpace(sb.String())
}

func extractText(node *html.Node, sb *strings.Builder) {
	if node.Type == html.TextNode {
		sb.WriteString(node.Data)
	}
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		extractText(child, sb)
	}
}

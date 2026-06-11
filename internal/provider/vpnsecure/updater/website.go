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
	const url = "https://www.vpnsecure.me/vpn-locations/"
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
	serversDiv := findServersDiv(rootNode)
	if serversDiv == nil {
		return nil, nil, htmlutils.WrapError(errors.New("HTML servers container div not found"), rootNode)
	}

	for countryNode := serversDiv.FirstChild; countryNode != nil; countryNode = countryNode.NextSibling {
		if countryNode.Data != divString {
			// empty line(s) and tab(s)
			continue
		}

		country := findCountry(countryNode)
		if country == "" {
			warnings = append(warnings, htmlutils.WrapWarning("country not found", countryNode))
			continue
		}

		grid := htmlutils.BFS(countryNode, matchGridDiv)
		if grid == nil {
			warnings = append(warnings, htmlutils.WrapWarning("grid div not found", countryNode))
			continue
		}

		gridItems := htmlutils.DirectChildren(grid, matchGridItem)
		if len(gridItems) == 0 {
			warnings = append(warnings, htmlutils.WrapWarning("no grid item found", grid))
			continue
		}

		for _, gridItem := range gridItems {
			server, warning := parseHTMLGridItem(gridItem)
			if warning != "" {
				warnings = append(warnings, warning)
				continue
			}

			server.Country = country
			servers = append(servers, server)
		}
	}

	return servers, warnings, nil
}

func parseHTMLGridItem(gridItem *html.Node) (
	server models.Server, warning string,
) {
	gridItemDT := htmlutils.DirectChild(gridItem, matchDT)
	if gridItemDT == nil {
		return server, htmlutils.WrapWarning("grid item <dt> not found", gridItem)
	}

	host := findHost(gridItemDT)
	host = naToEmpty(host)
	if host == "" {
		return server, htmlutils.WrapWarning("host not found", gridItemDT)
	}

	status := findStatus(gridItemDT)
	if !strings.EqualFold(status, "up") {
		warning := fmt.Sprintf("skipping server with host %s which has status %q", host, status)
		warning = htmlutils.WrapWarning(warning, gridItemDT)
		return server, warning
	}

	gridItemDD := htmlutils.DirectChild(gridItem, matchDD)
	if gridItemDD == nil {
		return server, htmlutils.WrapWarning("grid item dd not found", gridItem)
	}

	region := findSpanStrong(gridItemDD, "Region:")
	if region == "" {
		warning := fmt.Sprintf("region for host %s not found", host)
		return server, htmlutils.WrapWarning(warning, gridItemDD)
	}
	region = naToEmpty(region)

	city := findSpanStrong(gridItemDD, "City:")
	if city == "" {
		warning := fmt.Sprintf("region for host %s not found", host)
		return server, htmlutils.WrapWarning(warning, gridItemDD)
	}
	city = naToEmpty(city)

	premiumString := findSpanStrong(gridItemDD, "Premium:")
	premiumString = naToEmpty(premiumString)
	if premiumString == "" {
		warning := fmt.Sprintf("premium for host %s not found", host)
		return server, htmlutils.WrapWarning(warning, gridItemDD)
	}

	return models.Server{
		Region:   region,
		City:     city,
		Hostname: host + ".isponeder.com",
		Premium:  strings.EqualFold(premiumString, "yes"),
	}, ""
}

func naToEmpty(current string) (output string) {
	if current == "N / A" {
		return ""
	}
	return current
}

func findCountry(countryNode *html.Node) (country string) {
	for node := countryNode.FirstChild; node != nil; node = node.NextSibling {
		if node.Data != "a" {
			continue
		}
		for subNode := node.FirstChild; subNode != nil; subNode = subNode.NextSibling {
			if subNode.Data != "h4" {
				continue
			}
			return subNode.FirstChild.Data
		}
	}
	return ""
}

func findServersDiv(rootNode *html.Node) (serversDiv *html.Node) {
	locationsDiv := htmlutils.BFS(rootNode, matchLocationsListDiv)
	if locationsDiv == nil {
		return nil
	}

	return htmlutils.BFS(locationsDiv, matchServersDiv)
}

func findHost(gridItemDT *html.Node) (host string) {
	hostNode := htmlutils.DirectChild(gridItemDT, matchText)
	return strings.TrimSpace(hostNode.Data)
}

func matchText(node *html.Node) (match bool) {
	if node.Type != html.TextNode {
		return false
	}
	data := strings.TrimSpace(node.Data)
	return data != ""
}

func findStatus(gridItemDT *html.Node) (status string) {
	statusNode := htmlutils.DirectChild(gridItemDT, matchStatusSpan)
	return strings.TrimSpace(statusNode.FirstChild.Data)
}

func matchServersDiv(node *html.Node) (match bool) {
	return node != nil && node.Data == divString &&
		htmlutils.HasClassStrings(node, "blk__i")
}

func matchLocationsListDiv(node *html.Node) (match bool) {
	return node != nil && node.Data == divString &&
		htmlutils.HasClassStrings(node, "locations-list")
}

func matchGridDiv(node *html.Node) (match bool) {
	return node != nil && node.Data == divString &&
		htmlutils.HasClassStrings(node, "grid--locations")
}

func matchGridItem(node *html.Node) (match bool) {
	return node != nil && node.Data == "dl" &&
		htmlutils.HasClassStrings(node, "grid__i")
}

func matchDT(node *html.Node) (match bool) {
	return node != nil && node.Data == "dt"
}

func matchDD(node *html.Node) (match bool) {
	return node != nil && node.Data == "dd"
}

func matchStatusSpan(node *html.Node) (match bool) {
	return node.Data == "span" && htmlutils.HasClassStrings(node, "status")
}

func findSpanStrong(gridItemDD *html.Node, spanData string) (
	strongValue string,
) {
	spanFound := false
	for child := gridItemDD.FirstChild; child != nil; child = child.NextSibling {
		if !htmlutils.MatchData("div")(child) {
			continue
		}

		for subchild := child.FirstChild; subchild != nil; subchild = subchild.NextSibling {
			if htmlutils.MatchData("span")(subchild) && subchild.FirstChild.Data == spanData {
				spanFound = true
				break
			}
		}

		if !spanFound {
			continue
		}

		for subchild := child.FirstChild; subchild != nil; subchild = subchild.NextSibling {
			if htmlutils.MatchData("strong")(subchild) {
				return subchild.FirstChild.Data
			}
		}
	}

	return ""
}

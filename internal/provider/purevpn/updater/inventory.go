package updater

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

const (
	inventoryEndpointsAsarPath = "node_modules/atom-sdk/node_modules/utils/lib/constants/end-points.js"
	inventoryOfflineAsarPath   = "node_modules/atom-sdk/node_modules/inventory/lib/offline-data/inventory-data.js"
)

var (
	baseURLBPCRegex      = regexp.MustCompile(`BASE_URL_BPC"\s*,\s*"([^"]+)"`)
	inventoryPathRegex   = regexp.MustCompile(`"/\{resellerUid\}[^"]*app\.json"`)
	resellerUIDRegexJSON = regexp.MustCompile(`Uid"\s*:\s*"([^"]+)"`)
	resellerUIDRegexJS   = regexp.MustCompile(`Uid\s*:\s*"([^"]+)"`)
)

func parseInventoryURLTemplate(endpointsJS []byte) (template string, err error) {
	raw := string(endpointsJS)

	baseMatch := baseURLBPCRegex.FindStringSubmatch(raw)
	if len(baseMatch) != 2 {
		return "", fmt.Errorf("BASE_URL_BPC not found in endpoints file")
	}
	baseURL := strings.TrimSpace(baseMatch[1])
	if baseURL == "" {
		return "", fmt.Errorf("BASE_URL_BPC is empty")
	}

	pathMatch := inventoryPathRegex.FindString(raw)
	if pathMatch == "" {
		return "", fmt.Errorf("inventory path not found in endpoints file")
	}
	// Strip surrounding quotes from the JS string literal.
	path := strings.Trim(pathMatch, `"`)
	return strings.TrimRight(baseURL, "/") + path, nil
}

func parseResellerUIDFromInventoryOffline(offlineInventoryJS []byte) (resellerUID string, err error) {
	raw := string(offlineInventoryJS)

	match := resellerUIDRegexJSON.FindStringSubmatch(raw)
	if len(match) != 2 {
		match = resellerUIDRegexJS.FindStringSubmatch(raw)
	}
	if len(match) != 2 {
		return "", fmt.Errorf("reseller Uid not found in inventory offline data")
	}
	resellerUID = strings.TrimSpace(match[1])
	if resellerUID == "" {
		return "", fmt.Errorf("reseller Uid is empty")
	}
	return resellerUID, nil
}

func buildInventoryURL(template, resellerUID string) (inventoryURL string, err error) {
	if template == "" {
		return "", fmt.Errorf("inventory URL template is empty")
	}
	if resellerUID == "" {
		return "", fmt.Errorf("reseller UID is empty")
	}
	if !strings.Contains(template, "{resellerUid}") {
		return "", fmt.Errorf("inventory URL template does not contain {resellerUid}")
	}
	return strings.Replace(template, "{resellerUid}", resellerUID, 1), nil
}

type inventoryResponse struct {
	Body inventoryBody `json:"body"`
}

type inventoryBody struct {
	Countries   []inventoryCountry    `json:"countries"`
	DNS         []inventoryDNS        `json:"dns"`
	DataCenters []inventoryDataCenter `json:"data_centers"`
}

type inventoryCountry struct {
	DataCenters []inventoryDataCenterRef `json:"data_centers"`
	Protocols   []inventoryProtocol      `json:"protocols"`
	Features    []string                 `json:"features"`
}

type inventoryDataCenterRef struct {
	ID int `json:"id"`
}

type inventoryProtocol struct {
	Protocol string                 `json:"protocol"`
	DNS      []inventoryProtocolDNS `json:"dns"`
}

type inventoryProtocolDNS struct {
	DNSID      int `json:"dns_id"`
	PortNumber int `json:"port_number"`
}

type inventoryDNS struct {
	ID                   int      `json:"id"`
	Hostname             string   `json:"hostname"`
	ConfigurationVersion string   `json:"configuration_version"`
	Tags                 []string `json:"tags"`
}

type inventoryDataCenter struct {
	ID int    `json:"id"`
	IP string `json:"ip"`
}

func parseInventoryJSON(content []byte) (hts hostToServer, hostToFallbackIPs map[string][]netip.Addr, err error) {
	var response inventoryResponse
	if err := json.Unmarshal(content, &response); err != nil {
		return nil, nil, fmt.Errorf("unmarshalling inventory JSON: %w", err)
	}

	if len(response.Body.Countries) == 0 {
		return nil, nil, fmt.Errorf("no countries found in inventory JSON")
	}

	dnsIDToHostname := make(map[int]string, len(response.Body.DNS))
	dnsIDToP2PTagged := make(map[int]bool, len(response.Body.DNS))
	for _, dnsEntry := range response.Body.DNS {
		if dnsEntry.ID == 0 || dnsEntry.Hostname == "" {
			continue
		}
		dnsIDToHostname[dnsEntry.ID] = strings.TrimSpace(dnsEntry.Hostname)
		dnsIDToP2PTagged[dnsEntry.ID] = hasP2PTag(dnsEntry.Tags)
	}

	dataCenterIDToIP := make(map[int]netip.Addr, len(response.Body.DataCenters))
	for _, dataCenter := range response.Body.DataCenters {
		if dataCenter.ID == 0 || dataCenter.IP == "" {
			continue
		}
		ip, parseErr := netip.ParseAddr(strings.TrimSpace(dataCenter.IP))
		if parseErr != nil {
			continue
		}
		dataCenterIDToIP[dataCenter.ID] = ip
	}

	hts = make(hostToServer)
	hostToFallbackIPs = make(map[string][]netip.Addr)
	blocksFound := 0

	for _, country := range response.Body.Countries {
		countryP2PTagged := hasP2PTag(country.Features)
		countryDataCenterIPs := make([]netip.Addr, 0, len(country.DataCenters))
		for _, dataCenterRef := range country.DataCenters {
			ip, ok := dataCenterIDToIP[dataCenterRef.ID]
			if !ok {
				continue
			}
			countryDataCenterIPs = appendIPIfMissing(countryDataCenterIPs, ip)
		}

		for _, protocol := range country.Protocols {
			protocolName := strings.ToUpper(protocol.Protocol)
			tcp := protocolName == "TCP"
			udp := protocolName == "UDP"
			if !tcp && !udp {
				continue
			}
			blocksFound++

			for _, dns := range protocol.DNS {
				hostname := strings.TrimSpace(dnsIDToHostname[dns.DNSID])
				if hostname == "" {
					continue
				}

				port := uint16(0)
				if dns.PortNumber > 0 && dns.PortNumber <= 65535 {
					port = uint16(dns.PortNumber)
				}
				p2pTagged := countryP2PTagged || dnsIDToP2PTagged[dns.DNSID]
				hts.add(hostname, tcp, udp, port, p2pTagged)

				for _, ip := range countryDataCenterIPs {
					hostToFallbackIPs[hostname] = appendIPIfMissing(hostToFallbackIPs[hostname], ip)
				}
			}
		}
	}

	if blocksFound == 0 {
		return nil, nil, fmt.Errorf("no TCP/UDP protocol blocks found in inventory JSON")
	}
	if len(hts) == 0 {
		return nil, nil, fmt.Errorf("no OpenVPN TCP/UDP DNS hosts found in inventory JSON")
	}

	return hts, hostToFallbackIPs, nil
}

func parseInventoryConfigurationVersions(content []byte) (versions []string, err error) {
	var response inventoryResponse
	if err := json.Unmarshal(content, &response); err != nil {
		return nil, fmt.Errorf("unmarshalling inventory JSON: %w", err)
	}

	set := make(map[string]struct{})
	for _, dnsEntry := range response.Body.DNS {
		version := strings.TrimSpace(dnsEntry.ConfigurationVersion)
		if version == "" {
			continue
		}
		if _, exists := set[version]; exists {
			continue
		}
		set[version] = struct{}{}
		versions = append(versions, version)
	}

	return versions, nil
}

func hasP2PTag(tags []string) (p2p bool) {
	separatorNormalizer := strings.NewReplacer("-", "_", " ", "_")
	for _, tag := range tags {
		normalized := strings.ToLower(strings.TrimSpace(tag))
		if normalized == "" {
			continue
		}
		normalized = separatorNormalizer.Replace(normalized)
		for _, token := range strings.Split(normalized, "_") {
			if token == "p2p" {
				return true
			}
		}
	}
	return false
}

func extractFirstFileFromAsar(asarContent []byte, paths ...string) (content []byte, usedPath string, err error) {
	if len(paths) == 0 {
		return nil, "", fmt.Errorf("no asar paths provided")
	}

	var lastErr error
	for _, path := range paths {
		content, err = extractFileFromAsar(asarContent, path)
		if err == nil {
			return content, path, nil
		}
		lastErr = err
	}

	return nil, "", fmt.Errorf("extracting from app.asar failed for paths %q: %w", paths, lastErr)
}

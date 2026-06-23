package updater

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/qdm12/gluetun/internal/constants"
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
	if len(baseMatch) != 2 { //nolint:mnd
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
	if len(match) != 2 { //nolint:mnd
		match = resellerUIDRegexJS.FindStringSubmatch(raw)
	}
	if len(match) != 2 { //nolint:mnd
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
	Body struct {
		Countries []struct {
			DataCenters []struct {
				ID uint `json:"id"`
			} `json:"data_centers"`
			Protocols []struct {
				Protocol string `json:"protocol"`
				DNS      []struct {
					DNSID      uint   `json:"dns_id"`
					PortNumber uint16 `json:"port_number"`
				} `json:"dns"`
			} `json:"protocols"`
			Features []string `json:"features"`
		} `json:"countries"`
		DNS []struct {
			ID                   uint     `json:"id"`
			Hostname             string   `json:"hostname"`
			ConfigurationVersion string   `json:"configuration_version"`
			Tags                 []string `json:"tags"`
		} `json:"dns"`
		DataCenters []struct {
			ID uint       `json:"id"`
			IP netip.Addr `json:"ip"`
		} `json:"data_centers"`
	} `json:"body"`
}

type dnsData struct {
	hostname string
	p2p      bool
}

func parseInventoryJSON(reader io.Reader) (hts hostToServer, err error) {
	var response inventoryResponse
	decoder := json.NewDecoder(reader)
	err = decoder.Decode(&response)
	if err != nil {
		return nil, fmt.Errorf("decoding inventory JSON: %w", err)
	} else if len(response.Body.Countries) == 0 {
		return nil, errors.New("no countries found in inventory JSON")
	}

	dnsIDToData := getDNSIDToData(response)
	dataCenterIDToIP := getDataCenterIDToIP(response)

	hts = make(hostToServer)
	for _, country := range response.Body.Countries {
		countryP2PTagged := hasP2PTag(country.Features)
		countryDataCenterIPs := make([]netip.Addr, 0, len(country.DataCenters))
		for _, dataCenterRef := range country.DataCenters {
			ip, ok := dataCenterIDToIP[dataCenterRef.ID]
			if !ok {
				continue
			}
			countryDataCenterIPs = appendIfMissing(countryDataCenterIPs, ip)
		}

		for _, protocol := range country.Protocols {
			tcp := strings.EqualFold(protocol.Protocol, constants.TCP)
			udp := strings.EqualFold(protocol.Protocol, constants.UDP)
			if !tcp && !udp {
				continue
			}

			for _, dns := range protocol.DNS {
				data, ok := dnsIDToData[dns.DNSID]
				if !ok {
					continue
				}

				var tcpPorts, udpPorts []uint16
				if tcp {
					tcpPorts = []uint16{dns.PortNumber} // always 80
				}
				if udp {
					udpPorts = []uint16{dns.PortNumber}
				}
				p2pTagged := countryP2PTagged || data.p2p
				hts.add(data.hostname, countryDataCenterIPs, tcp, udp, tcpPorts, udpPorts, p2pTagged)
			}
		}
	}

	return hts, nil
}

func getDNSIDToData(response inventoryResponse) (dnsIDToData map[uint]dnsData) {
	dnsIDToData = make(map[uint]dnsData, len(response.Body.DNS))
	for _, dnsEntry := range response.Body.DNS {
		if dnsEntry.ID == 0 || dnsEntry.Hostname == "" {
			continue
		}
		dnsIDToData[dnsEntry.ID] = dnsData{
			hostname: strings.TrimSpace(dnsEntry.Hostname),
			p2p:      hasP2PTag(dnsEntry.Tags),
		}
	}
	return dnsIDToData
}

func getDataCenterIDToIP(response inventoryResponse) (dataCenterIDToIP map[uint]netip.Addr) {
	dataCenterIDToIP = make(map[uint]netip.Addr, len(response.Body.DataCenters))
	for _, dataCenter := range response.Body.DataCenters {
		if dataCenter.ID == 0 || !dataCenter.IP.IsValid() {
			continue
		}
		dataCenterIDToIP[dataCenter.ID] = dataCenter.IP
	}
	return dataCenterIDToIP
}

func hasP2PTag(tags []string) (p2p bool) {
	separatorNormalizer := strings.NewReplacer("-", "_", " ", "_")
	for _, tag := range tags {
		normalized := strings.ToLower(strings.TrimSpace(tag))
		normalized = separatorNormalizer.Replace(normalized)
		if slices.Contains(strings.Split(normalized, "_"), "p2p") {
			return true
		}
	}
	return false
}

func extractFirstFileFromAsar(asarContent []byte, paths ...string) (content []byte, usedPath string, err error) {
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

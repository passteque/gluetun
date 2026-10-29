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
		return "", errors.New("BASE_URL_BPC not found in endpoints file")
	}
	baseURL := strings.TrimSpace(baseMatch[1])
	if baseURL == "" {
		return "", errors.New("BASE_URL_BPC is empty")
	}

	pathMatch := inventoryPathRegex.FindString(raw)
	if pathMatch == "" {
		return "", errors.New("inventory path not found in endpoints file")
	}
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
		return "", errors.New("reseller Uid not found in inventory offline data")
	}
	resellerUID = strings.TrimSpace(match[1])
	if resellerUID == "" {
		return "", errors.New("reseller Uid is empty")
	}
	return resellerUID, nil
}

func buildInventoryURL(template, resellerUID string) (inventoryURL string, err error) {
	if template == "" {
		return "", errors.New("inventory URL template is empty")
	}
	if resellerUID == "" {
		return "", errors.New("reseller UID is empty")
	}
	if !strings.Contains(template, "{resellerUid}") {
		return "", errors.New("inventory URL template does not contain {resellerUid}")
	}
	return strings.Replace(template, "{resellerUid}", resellerUID, 1), nil
}

type inventoryResponse struct {
	Body inventoryBody `json:"body"`
}

type inventoryBody struct {
	Countries   []inventoryCountry    `json:"countries"`
	Cities      []inventoryCity       `json:"cities"`
	DNS         []inventoryDNS        `json:"dns"`
	DataCenters []inventoryDataCenter `json:"data_centers"`
}

// inventoryCity is a city with data centers and features hosting servers referenced by DNS entry ID.
type inventoryCity struct {
	Name        string `json:"name"`
	DataCenters []struct {
		ID uint `json:"id"`
	} `json:"data_centers"`
	Protocols []inventoryProtocol `json:"protocols"`
	Features  []string            `json:"features"`
}

type inventoryCountry struct {
	DataCenters []struct {
		ID uint `json:"id"`
	} `json:"data_centers"`
	Protocols []inventoryProtocol `json:"protocols"`
	// Features are the network features available in the country, for
	// example `p2p`, `PF`, `QR` or `OVPN_OBF`.
	Features []string `json:"features"`
}

type inventoryProtocol struct {
	Protocol string `json:"protocol"`
	DNS      []struct {
		DNSID      uint   `json:"dns_id"`
		PortNumber uint16 `json:"port_number"`
	} `json:"dns"`
}

type inventoryDNS struct {
	ID       uint   `json:"id"`
	Hostname string `json:"hostname"`
}

type inventoryDataCenter struct {
	ID uint       `json:"id"`
	IP netip.Addr `json:"ip"`
}

func parseInventoryJSON(reader io.Reader) (hts hostToServer, err error) {
	var response inventoryResponse
	decoder := json.NewDecoder(reader)
	err = decoder.Decode(&response)
	if err != nil {
		return nil, fmt.Errorf("decoding inventory JSON: %w", err)
	}
	if len(response.Body.Countries) == 0 {
		return nil, errors.New("no countries found in inventory JSON")
	}

	dnsIDToHostname := getDNSIDToHostname(response.Body.DNS)
	dataCenterIDToIP := getDataCenterIDToIP(response.Body.DataCenters)

	hts = make(hostToServer)
	for _, country := range response.Body.Countries {
		// Each hostname of the country is served by all its data centers.
		dataCenterIPs := make([]netip.Addr, 0, len(country.DataCenters))
		for _, dataCenterRef := range country.DataCenters {
			ip, ok := dataCenterIDToIP[dataCenterRef.ID]
			if !ok || slices.Contains(dataCenterIPs, ip) {
				continue
			}
			dataCenterIPs = append(dataCenterIPs, ip)
		}

		p2p := hasP2PFeature(country.Features)
		for _, protocol := range country.Protocols {
			hts.addProtocolServers(protocol, dnsIDToHostname, dataCenterIPs, p2p, "")
		}
	}

	for _, city := range response.Body.Cities {
		dataCenterIPs := make([]netip.Addr, 0, len(city.DataCenters))
		for _, dataCenterRef := range city.DataCenters {
			ip, ok := dataCenterIDToIP[dataCenterRef.ID]
			if !ok || slices.Contains(dataCenterIPs, ip) {
				continue
			}
			dataCenterIPs = append(dataCenterIPs, ip)
		}

		p2p := hasP2PFeature(city.Features)
		for _, protocol := range city.Protocols {
			hts.addProtocolServers(protocol, dnsIDToHostname, dataCenterIPs, p2p, city.Name)
		}
	}

	return hts, nil
}

// addProtocolServers adds a server for each hostname of the protocol, served
// on the port of the protocol. Only TCP and UDP are handled since only
// OpenVPN is supported by this updater.
func (hts hostToServer) addProtocolServers(protocol inventoryProtocol,
	dnsIDToHostname map[uint]string, dataCenterIPs []netip.Addr, p2p bool, cityName string,
) {
	tcp := strings.EqualFold(protocol.Protocol, constants.TCP)
	udp := strings.EqualFold(protocol.Protocol, constants.UDP)
	if !tcp && !udp {
		return
	}

	for _, dns := range protocol.DNS {
		hostname, ok := dnsIDToHostname[dns.DNSID]
		if !ok || hostname == "" {
			continue
		}

		var tcpPorts, udpPorts []uint16
		if tcp {
			tcpPorts = []uint16{dns.PortNumber} // always 80
		}
		if udp {
			udpPorts = []uint16{dns.PortNumber} // 53, 5565 or 15021
		}
		hts.add(hostname, dataCenterIPs, tcp, udp, tcpPorts, udpPorts, p2p)
		if cityName != "" {
			server := hts[hostname]
			if server.City == "" {
				server.City = cityName
				hts[hostname] = server
			}
		}
	}
}

func getDNSIDToHostname(dnsEntries []inventoryDNS) (dnsIDToHostname map[uint]string) {
	dnsIDToHostname = make(map[uint]string, len(dnsEntries))
	for _, dnsEntry := range dnsEntries {
		if dnsEntry.ID == 0 || dnsEntry.Hostname == "" {
			continue
		}
		dnsIDToHostname[dnsEntry.ID] = strings.TrimSpace(dnsEntry.Hostname)
	}
	return dnsIDToHostname
}

func getDataCenterIDToIP(dataCenters []inventoryDataCenter) (dataCenterIDToIP map[uint]netip.Addr) {
	dataCenterIDToIP = make(map[uint]netip.Addr, len(dataCenters))
	for _, dataCenter := range dataCenters {
		if dataCenter.ID == 0 || !dataCenter.IP.IsValid() {
			continue
		}
		dataCenterIDToIP[dataCenter.ID] = dataCenter.IP
	}
	return dataCenterIDToIP
}

func hasP2PFeature(features []string) (p2p bool) {
	return slices.ContainsFunc(features, func(feature string) bool {
		return strings.EqualFold(strings.TrimSpace(feature), "p2p")
	})
}

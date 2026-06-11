package updater

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

const localDataAsarPath = "node_modules/atom-sdk/lib/offline-data/local-data.js"

var (
	hostNeedle = `name:"`
	portNeedle = `port_number:`
	idPattern  = regexp.MustCompile(`id:\s*"?([0-9]+)"?`)
)

func parseLocalData(content []byte) (hostToServer, error) {
	raw := string(content)
	hts := make(hostToServer)
	const protocolNeedle = `protocol:"`
	blocksFound := 0
	for index := 0; index < len(raw); {
		start := strings.Index(raw[index:], protocolNeedle)
		if start == -1 {
			break
		}
		start += index
		protocolStart := start + len(protocolNeedle)
		protocolEnd := strings.IndexByte(raw[protocolStart:], '"')
		if protocolEnd == -1 {
			break
		}
		protocolEnd += protocolStart
		protocol := strings.ToUpper(raw[protocolStart:protocolEnd])
		tcp := protocol == "TCP"
		udp := protocol == "UDP"
		index = protocolEnd + 1
		if !tcp && !udp {
			continue
		}
		blocksFound++

		dnsMarker := strings.Index(raw[index:], `dns:[`)
		if dnsMarker == -1 {
			continue
		}
		dnsMarker += index
		arrayStart := dnsMarker + len(`dns:`)
		dnsArray, arrayEnd, err := extractBracketContent(raw, arrayStart, '[', ']')
		if err != nil {
			continue
		}
		index = arrayEnd + 1

		for _, entry := range splitObjectEntries(dnsArray) {
			host, port, ok := parseHostPortFromDNSEntry(entry)
			if !ok {
				continue
			}
			hts.add(host, tcp, udp, port, false)
		}
	}

	if blocksFound == 0 {
		return nil, fmt.Errorf("no TCP/UDP protocol blocks found in local-data payload")
	}
	if len(hts) == 0 {
		return nil, fmt.Errorf("no OpenVPN TCP/UDP DNS hosts found in local-data payload")
	}

	return hts, nil
}

func extractBracketContent(s string, openIndex int, open, close byte) (content string, closeIndex int, err error) {
	if openIndex < 0 || openIndex >= len(s) || s[openIndex] != open {
		return "", -1, fmt.Errorf("opening bracket not found at index %d", openIndex)
	}
	depth := 0
	for i := openIndex; i < len(s); i++ {
		switch s[i] {
		case open:
			depth++
		case close:
			depth--
			if depth == 0 {
				return s[openIndex+1 : i], i, nil
			}
		}
	}
	return "", -1, fmt.Errorf("closing bracket not found for index %d", openIndex)
}

func splitObjectEntries(s string) (entries []string) {
	entryStart := -1
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '{':
			if depth == 0 {
				entryStart = i
			}
			depth++
		case '}':
			if depth == 0 {
				continue
			}
			depth--
			if depth == 0 && entryStart >= 0 {
				entries = append(entries, s[entryStart:i+1])
				entryStart = -1
			}
		}
	}
	return entries
}

func parseHostPortFromDNSEntry(entry string) (host string, port uint16, ok bool) {
	hostStart := strings.Index(entry, hostNeedle)
	if hostStart == -1 {
		return "", 0, false
	}
	hostStart += len(hostNeedle)
	hostEnd := strings.IndexByte(entry[hostStart:], '"')
	if hostEnd == -1 {
		return "", 0, false
	}
	hostEnd += hostStart
	host = strings.TrimSpace(entry[hostStart:hostEnd])
	if host == "" {
		return "", 0, false
	}

	portStart := strings.Index(entry, portNeedle)
	if portStart == -1 {
		return "", 0, false
	}
	portStart += len(portNeedle)
	portEnd := portStart
	for ; portEnd < len(entry) && entry[portEnd] >= '0' && entry[portEnd] <= '9'; portEnd++ {
	}
	if portEnd == portStart {
		return "", 0, false
	}
	port64, err := strconv.ParseUint(entry[portStart:portEnd], 10, 16)
	if err != nil || port64 == 0 {
		return "", 0, false
	}
	return host, uint16(port64), true
}

func parseLocalDataFallbackIPs(content []byte) (hostToFallbackIPs map[string][]netip.Addr) {
	raw := string(content)

	dataCenterIDToIP := parseDataCenterIDToPingIP(raw)
	if len(dataCenterIDToIP) == 0 {
		return nil
	}

	countriesArray, _, err := extractArrayByKey(raw, "countries:")
	if err != nil {
		return nil
	}

	hostToFallbackIPs = make(map[string][]netip.Addr)
	for _, countryEntry := range splitObjectEntries(countriesArray) {
		dataCenterIDs := parseCountryDataCenterIDs(countryEntry)
		if len(dataCenterIDs) == 0 {
			continue
		}

		hosts := parseTCPUDPHostsFromChunk(countryEntry)
		if len(hosts) == 0 {
			continue
		}

		for _, host := range hosts {
			for _, dataCenterID := range dataCenterIDs {
				ip, ok := dataCenterIDToIP[dataCenterID]
				if !ok {
					continue
				}
				hostToFallbackIPs[host] = appendIPIfMissing(hostToFallbackIPs[host], ip)
			}
		}
	}

	return hostToFallbackIPs
}

func parseDataCenterIDToPingIP(raw string) map[int]netip.Addr {
	dataCentersArray, _, err := extractArrayByKey(raw, "data_centers:")
	if err != nil {
		return nil
	}

	dataCenterIDToIP := make(map[int]netip.Addr)
	for _, dataCenterEntry := range splitObjectEntries(dataCentersArray) {
		id := parseID(dataCenterEntry)
		if id == 0 {
			continue
		}
		pingIP, ok := parseQuotedValue(dataCenterEntry, "ping_ip_address:")
		if !ok || pingIP == "" {
			continue
		}
		ip, err := netip.ParseAddr(pingIP)
		if err != nil {
			continue
		}
		dataCenterIDToIP[id] = ip
	}
	return dataCenterIDToIP
}

func parseCountryDataCenterIDs(countryEntry string) (ids []int) {
	dataCentersArray, _, err := extractArrayByKey(countryEntry, "data_centers:")
	if err != nil {
		return nil
	}
	for _, dataCenterEntry := range splitObjectEntries(dataCentersArray) {
		id := parseID(dataCenterEntry)
		if id == 0 {
			continue
		}
		ids = appendIntIfMissing(ids, id)
	}
	return ids
}

func parseTCPUDPHostsFromChunk(chunk string) (hosts []string) {
	const protocolNeedle = `protocol:"`
	for index := 0; index < len(chunk); {
		start := strings.Index(chunk[index:], protocolNeedle)
		if start == -1 {
			break
		}
		start += index
		protocolStart := start + len(protocolNeedle)
		protocolEnd := strings.IndexByte(chunk[protocolStart:], '"')
		if protocolEnd == -1 {
			break
		}
		protocolEnd += protocolStart
		protocol := strings.ToUpper(chunk[protocolStart:protocolEnd])
		index = protocolEnd + 1
		if protocol != "TCP" && protocol != "UDP" {
			continue
		}

		dnsArray, arrayEnd, err := extractArrayByKey(chunk[index:], "dns:")
		if err != nil {
			continue
		}
		index += arrayEnd + 1

		for _, entry := range splitObjectEntries(dnsArray) {
			host, _, ok := parseHostPortFromDNSEntry(entry)
			if !ok {
				continue
			}
			hosts = appendStringIfMissing(hosts, host)
		}
	}
	return hosts
}

func extractArrayByKey(s, key string) (content string, endIndex int, err error) {
	keyIndex := strings.Index(s, key)
	if keyIndex == -1 {
		return "", -1, fmt.Errorf("key %q not found", key)
	}
	openIndex := strings.IndexByte(s[keyIndex:], '[')
	if openIndex == -1 {
		return "", -1, fmt.Errorf("array opening bracket not found for key %q", key)
	}
	openIndex += keyIndex
	content, closeIndex, err := extractBracketContent(s, openIndex, '[', ']')
	if err != nil {
		return "", -1, err
	}
	return content, closeIndex, nil
}

func parseQuotedValue(s, key string) (value string, ok bool) {
	keyIndex := strings.Index(s, key)
	if keyIndex == -1 {
		return "", false
	}
	start := strings.IndexByte(s[keyIndex:], '"')
	if start == -1 {
		return "", false
	}
	start += keyIndex + 1
	end := strings.IndexByte(s[start:], '"')
	if end == -1 {
		return "", false
	}
	end += start
	return strings.TrimSpace(s[start:end]), true
}

func parseID(s string) (id int) {
	match := idPattern.FindStringSubmatch(s)
	if len(match) < 2 {
		return 0
	}
	id, _ = strconv.Atoi(match[1])
	return id
}

func appendStringIfMissing(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func appendIntIfMissing(values []int, value int) []int {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func appendIPIfMissing(values []netip.Addr, value netip.Addr) []netip.Addr {
	for _, existing := range values {
		if existing.Compare(value) == 0 {
			return values
		}
	}
	return append(values, value)
}

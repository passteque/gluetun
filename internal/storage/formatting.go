package storage

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/vpn"
)

func commaJoin(slice []string) string {
	return strings.Join(slice, ", ")
}

func noServerFoundError(selection settings.ServerSelection) (err error) {
	var messageParts []string

	messageParts = append(messageParts, "VPN "+selection.VPN)

	protocol := constants.UDP
	if selection.OpenVPN.Protocol == constants.TCP {
		protocol = constants.TCP
	}
	messageParts = append(messageParts, "protocol "+protocol)

	switch len(selection.Countries) {
	case 0:
	case 1:
		part := "country " + selection.Countries[0]
		messageParts = append(messageParts, part)
	default:
		part := "countries " + commaJoin(selection.Countries)
		messageParts = append(messageParts, part)
	}

	switch len(selection.Categories) {
	case 0:
	case 1:
		part := "category " + selection.Categories[0]
		messageParts = append(messageParts, part)
	default:
		part := "categories " + commaJoin(selection.Categories)
		messageParts = append(messageParts, part)
	}

	switch len(selection.Regions) {
	case 0:
	case 1:
		part := "region " + selection.Regions[0]
		messageParts = append(messageParts, part)
	default:
		part := "regions " + commaJoin(selection.Regions)
		messageParts = append(messageParts, part)
	}

	switch len(selection.Cities) {
	case 0:
	case 1:
		part := "city " + selection.Cities[0]
		messageParts = append(messageParts, part)
	default:
		part := "cities " + commaJoin(selection.Cities)
		messageParts = append(messageParts, part)
	}

	if *selection.OwnedOnly {
		messageParts = append(messageParts, "owned servers only")
	}

	switch len(selection.ISPs) {
	case 0:
	case 1:
		part := "ISP " + selection.ISPs[0]
		messageParts = append(messageParts, part)
	default:
		part := "ISPs " + commaJoin(selection.ISPs)
		messageParts = append(messageParts, part)
	}

	switch len(selection.Hostnames) {
	case 0:
	case 1:
		part := "hostname " + selection.Hostnames[0]
		messageParts = append(messageParts, part)
	default:
		part := "hostnames " + commaJoin(selection.Hostnames)
		messageParts = append(messageParts, part)
	}

	switch len(selection.Names) {
	case 0:
	case 1:
		part := "name " + selection.Names[0]
		messageParts = append(messageParts, part)
	default:
		part := "names " + commaJoin(selection.Names)
		messageParts = append(messageParts, part)
	}

	switch len(selection.Numbers) {
	case 0:
	case 1:
		part := "server number " + strconv.Itoa(int(selection.Numbers[0]))
		messageParts = append(messageParts, part)
	default:
		serverNumbers := make([]string, len(selection.Numbers))
		for i := range selection.Numbers {
			serverNumbers[i] = strconv.Itoa(int(selection.Numbers[i]))
		}
		part := "server numbers " + commaJoin(serverNumbers)
		messageParts = append(messageParts, part)
	}

	if *selection.OpenVPN.PIAEncPreset != "" {
		part := "encryption preset " + *selection.OpenVPN.PIAEncPreset
		messageParts = append(messageParts, part)
	}

	if *selection.FreeOnly {
		messageParts = append(messageParts, "free tier only")
	}

	if *selection.PremiumOnly {
		messageParts = append(messageParts, "premium tier only")
	}

	if *selection.StreamOnly {
		messageParts = append(messageParts, "stream only")
	}

	if *selection.MultiHopOnly {
		messageParts = append(messageParts, "multihop only")
	}

	if *selection.PortForwardOnly {
		messageParts = append(messageParts, "port forwarding only")
	}

	if *selection.SecureCoreOnly {
		messageParts = append(messageParts, "secure core only")
	}

	if *selection.TorOnly {
		messageParts = append(messageParts, "tor only")
	}

	targetIP := selection.OpenVPN.EndpointIP
	if selection.VPN == vpn.Wireguard {
		targetIP = selection.Wireguard.EndpointIP
	}
	if targetIP.IsValid() {
		messageParts = append(messageParts,
			"target ip address "+targetIP.String())
	}

	message := "for " + strings.Join(messageParts, "; ")

	return fmt.Errorf("no server found: %s", message)
}

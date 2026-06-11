package models

import (
	"fmt"
	"strings"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/constants/vpn"
)

func boolToMarkdown(b bool) string {
	if b {
		return "✅"
	}
	return "❌"
}

func markdownTableHeading(legendFields ...string) (markdown string) {
	return "| " + strings.Join(legendFields, " | ") + " |\n" +
		"|" + strings.Repeat(" --- |", len(legendFields))
}

const (
	categoriesHeader  = "Categories"
	cityHeader        = "City"
	countryHeader     = "Country"
	freeHeader        = "Free"
	hostnameHeader    = "Hostname"
	ispHeader         = "ISP"
	multiHopHeader    = "MultiHop"
	nameHeader        = "Name"
	numberHeader      = "Number"
	ownedHeader       = "Owned"
	portForwardHeader = "Port forwarding"
	premiumHeader     = "Premium"
	regionHeader      = "Region"
	secureHeader      = "Secure"
	streamHeader      = "Stream"
	tcpHeader         = "TCP"
	torHeader         = "Tor"
	udpHeader         = "UDP"
	vpnHeader         = "VPN"
)

func (s *Server) ToMarkdown(headers ...string) (markdown string) {
	if len(headers) == 0 {
		return ""
	}

	fields := make([]string, len(headers))
	for i, header := range headers {
		switch header {
		case cityHeader:
			fields[i] = s.City
		case countryHeader:
			fields[i] = s.Country
		case categoriesHeader:
			fields[i] = strings.Join(s.Categories, ", ")
		case freeHeader:
			fields[i] = boolToMarkdown(s.Free)
		case hostnameHeader:
			fields[i] = fmt.Sprintf("`%s`", s.Hostname)
		case ispHeader:
			fields[i] = s.ISP
		case multiHopHeader:
			fields[i] = boolToMarkdown(s.MultiHop)
		case nameHeader:
			fields[i] = s.ServerName
		case numberHeader:
			fields[i] = fmt.Sprint(s.Number)
		case ownedHeader:
			fields[i] = boolToMarkdown(s.Owned)
		case portForwardHeader:
			fields[i] = boolToMarkdown(s.PortForward)
		case premiumHeader:
			fields[i] = boolToMarkdown(s.Premium)
		case regionHeader:
			fields[i] = s.Region
		case streamHeader:
			fields[i] = boolToMarkdown(s.Stream)
		case tcpHeader:
			fields[i] = boolToMarkdown(s.TCP)
		case udpHeader:
			fields[i] = boolToMarkdown(s.UDP || s.VPN == vpn.Wireguard)
		case vpnHeader:
			fields[i] = s.VPN
		}
	}

	return "| " + strings.Join(fields, " | ") + " |"
}

func (s *Servers) toMarkdown(vpnProvider string) (formatted string, err error) {
	headers, err := getMarkdownHeaders(vpnProvider)
	if err != nil {
		return "", fmt.Errorf("getting markdown headers: %w", err)
	}

	legend := markdownTableHeading(headers...)

	entries := make([]string, len(s.Servers))
	for i, server := range s.Servers {
		entries[i] = server.ToMarkdown(headers...)
	}

	formatted = legend + "\n" +
		strings.Join(entries, "\n") + "\n"
	return formatted, nil
}

func getMarkdownHeaders(vpnProvider string) (headers []string, err error) {
	switch vpnProvider {
	case providers.Airvpn:
		return []string{
			regionHeader, countryHeader, cityHeader, vpnHeader,
			udpHeader, tcpHeader, hostnameHeader, nameHeader,
		}, nil
	case providers.Cyberghost:
		return []string{countryHeader, hostnameHeader, tcpHeader, udpHeader}, nil
	case providers.Expressvpn:
		return []string{countryHeader, cityHeader, hostnameHeader, tcpHeader, udpHeader}, nil
	case providers.Fastestvpn:
		return []string{countryHeader, hostnameHeader, vpnHeader, tcpHeader, udpHeader}, nil
	case providers.Giganews:
		return []string{regionHeader, hostnameHeader, tcpHeader, udpHeader}, nil
	case providers.HideMyAss:
		return []string{countryHeader, regionHeader, cityHeader, hostnameHeader, tcpHeader, udpHeader}, nil
	case providers.Ipvanish:
		return []string{countryHeader, cityHeader, hostnameHeader, tcpHeader, udpHeader}, nil
	case providers.Ivpn:
		return []string{countryHeader, cityHeader, ispHeader, hostnameHeader, vpnHeader, tcpHeader, udpHeader}, nil
	case providers.Mullvad:
		return []string{countryHeader, cityHeader, ispHeader, ownedHeader, hostnameHeader, vpnHeader}, nil
	case providers.Nordvpn:
		return []string{countryHeader, regionHeader, cityHeader, hostnameHeader, vpnHeader, categoriesHeader}, nil
	case providers.Perfectprivacy:
		return []string{cityHeader, tcpHeader, udpHeader}, nil
	case providers.Privado:
		return []string{countryHeader, regionHeader, cityHeader, hostnameHeader}, nil
	case providers.PrivateInternetAccess:
		return []string{regionHeader, hostnameHeader, nameHeader, tcpHeader, udpHeader, portForwardHeader}, nil
	case providers.Privatevpn:
		return []string{countryHeader, cityHeader, hostnameHeader}, nil
	case providers.Protonvpn:
		return []string{
			countryHeader, regionHeader, cityHeader, hostnameHeader, vpnHeader,
			freeHeader, portForwardHeader, secureHeader, torHeader,
		}, nil
	case providers.Purevpn:
		return []string{countryHeader, regionHeader, cityHeader, hostnameHeader, tcpHeader, udpHeader}, nil
	case providers.SlickVPN:
		return []string{regionHeader, countryHeader, cityHeader, hostnameHeader}, nil
	case providers.Surfshark:
		return []string{
			regionHeader, countryHeader, cityHeader, hostnameHeader,
			vpnHeader, multiHopHeader, tcpHeader, udpHeader,
		}, nil
	case providers.Torguard:
		return []string{countryHeader, cityHeader, hostnameHeader, tcpHeader, udpHeader}, nil
	case providers.VPNSecure:
		return []string{regionHeader, cityHeader, hostnameHeader, premiumHeader}, nil
	case providers.VPNUnlimited:
		return []string{countryHeader, cityHeader, hostnameHeader, freeHeader, streamHeader, tcpHeader, udpHeader}, nil
	case providers.Vyprvpn:
		return []string{regionHeader, hostnameHeader, tcpHeader, udpHeader}, nil
	case providers.Windscribe:
		return []string{regionHeader, cityHeader, hostnameHeader, vpnHeader}, nil
	default:
		return nil, fmt.Errorf("markdown headers not defined: for %s", vpnProvider)
	}
}

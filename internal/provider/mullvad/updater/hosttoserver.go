package updater

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
)

type hostToServer map[string]models.Server

func (hts hostToServer) add(data serverData) (err error) {
	if !data.Active {
		return nil
	}

	if data.IPv4 == "" && data.IPv6 == "" {
		return errors.New("no IP address for VPN server")
	}

	server, ok := hts[data.Hostname]
	if ok { // API returns a server per hostname at most
		return nil
	}

	switch data.Type {
	case "wireguard":
		server.VPN = vpn.Wireguard
	case "bridge":
		// ignore bridge servers
		return nil
	default:
		return fmt.Errorf("VPN type not supported: %s", data.Type)
	}

	if data.IPv4 != "" {
		ipv4, err := netip.ParseAddr(data.IPv4)
		if err != nil {
			return fmt.Errorf("parsing IPv4 address: %w", err)
		} else if !ipv4.Is4() {
			return fmt.Errorf("IP address is not IPv4: %s", data.IPv4)
		}
		server.IPs = append(server.IPs, ipv4)
	}

	if data.IPv6 != "" {
		ipv6, err := netip.ParseAddr(data.IPv6)
		if err != nil {
			return fmt.Errorf("parsing IPv6 address: %w", err)
		} else if !ipv6.Is6() {
			return fmt.Errorf("IP address is not IPv6: %s", data.IPv6)
		}
		server.IPs = append(server.IPs, ipv6)
	}

	server.Country = data.Country
	server.City = strings.ReplaceAll(data.City, ",", "")
	server.Hostname = data.Hostname
	server.ISP = data.Provider
	server.Owned = data.Owned
	server.WgPubKey = data.PubKey

	hts[data.Hostname] = server

	return nil
}

func (hts hostToServer) toServersSlice() (servers []models.Server) {
	servers = make([]models.Server, 0, len(hts))
	for _, server := range hts {
		server.IPs = uniqueSortedIPs(server.IPs)
		servers = append(servers, server)
	}
	return servers
}

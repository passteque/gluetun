package updater

import (
	"net/netip"

	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
)

type ipToServers map[string][2]models.Server // first server is OpenVPN, second is Wireguard.

type features struct {
	secureCore bool
	tor        bool
	p2p        bool
	stream     bool
}

func (its ipToServers) add(country, region, city, name, hostname, wgPubKey string,
	free bool, ipv4, ipv6 netip.Addr, features features,
) {
	var key string
	const ipFamilies = 2
	ips := make([]netip.Addr, 0, ipFamilies)
	if ipv4.IsValid() {
		ips = append(ips, ipv4)
		key = ipv4.String()
	}
	if ipv6.IsValid() {
		ips = append(ips, ipv6)
		if key == "" {
			key = ipv6.String()
		}
	}
	servers, ok := its[key]
	if ok {
		return
	}

	baseServer := models.Server{
		Country:     country,
		Region:      region,
		City:        city,
		ServerName:  name,
		Hostname:    hostname,
		Free:        free,
		SecureCore:  features.secureCore,
		Tor:         features.tor,
		PortForward: features.p2p,
		Stream:      features.stream,
		IPs:         ips,
	}
	openvpnServer := baseServer
	openvpnServer.VPN = vpn.OpenVPN
	openvpnServer.UDP = true
	openvpnServer.TCP = true
	servers[0] = openvpnServer
	wireguardServer := baseServer
	wireguardServer.VPN = vpn.Wireguard
	wireguardServer.WgPubKey = wgPubKey
	servers[1] = wireguardServer
	its[key] = servers
}

func (its ipToServers) toServersSlice() (serversSlice []models.Server) {
	const vpnProtocols = 2
	serversSlice = make([]models.Server, 0, vpnProtocols*len(its))
	for _, servers := range its {
		serversSlice = append(serversSlice, servers[0], servers[1])
	}
	return serversSlice
}

func (its ipToServers) numberOfServers() int {
	const serversPerIP = 2
	return len(its) * serversPerIP
}

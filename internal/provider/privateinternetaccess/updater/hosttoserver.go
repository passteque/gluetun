package updater

import (
	"net/netip"

	"github.com/qdm12/gluetun/internal/models"
)

type nameToServer map[string]models.Server

func (nts nameToServer) add(name, hostname, region, vpnType string,
	tcp, udp, portForward bool, ip netip.Addr,
) (change bool) {
	key := vpnType + "-" + name
	server, ok := nts[key]
	if !ok {
		change = true
		server.VPN = vpnType
		server.ServerName = name
		server.Hostname = hostname
		server.Region = region
		server.PortForward = portForward
	}

	if !server.TCP && tcp {
		change = true
		server.TCP = tcp
	}
	if !server.UDP && udp {
		change = true
		server.UDP = udp
	}

	ipFound := false
	for _, existingIP := range server.IPs {
		if ip == existingIP {
			ipFound = true
			break
		}
	}

	if !ipFound {
		change = true
		server.IPs = append(server.IPs, ip)
	}

	nts[key] = server

	return change
}

func (nts nameToServer) toServersSlice() (servers []models.Server) {
	servers = make([]models.Server, 0, len(nts))
	for _, server := range nts {
		servers = append(servers, server)
	}
	return servers
}

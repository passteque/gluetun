package updater

import (
	"net/netip"

	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
)

type hostToServer map[string]models.Server

func (hts hostToServer) add(host string, tcp, udp bool, port uint16, p2pTagged bool) {
	server, ok := hts[host]
	if !ok {
		server.VPN = vpn.OpenVPN
		server.Hostname = host
	}
	portForward, quantumResistant, obfuscated, p2pInHost := inferPureVPNTraits(host)
	server.PortForward = server.PortForward || portForward
	server.QuantumResistant = server.QuantumResistant || quantumResistant
	server.Obfuscated = server.Obfuscated || obfuscated
	if p2pTagged || p2pInHost {
		server.Categories = appendStringIfMissing(server.Categories, "p2p")
	}
	if tcp {
		server.TCP = true
		if port != 0 {
			server.TCPPorts = appendPortIfMissing(server.TCPPorts, port)
		}
	}
	if udp {
		server.UDP = true
		if port != 0 {
			server.UDPPorts = appendPortIfMissing(server.UDPPorts, port)
		}
	}
	hts[host] = server
}

func appendPortIfMissing(ports []uint16, port uint16) []uint16 {
	for _, existingPort := range ports {
		if existingPort == port {
			return ports
		}
	}
	return append(ports, port)
}

func (hts hostToServer) toHostsSlice() (hosts []string) {
	hosts = make([]string, 0, len(hts))
	for host := range hts {
		hosts = append(hosts, host)
	}
	return hosts
}

func (hts hostToServer) adaptWithIPs(hostToIPs map[string][]netip.Addr) {
	for host, IPs := range hostToIPs {
		server := hts[host]
		server.IPs = IPs
		hts[host] = server
	}
	for host, server := range hts {
		if len(server.IPs) == 0 {
			delete(hts, host)
		}
	}
}

func (hts hostToServer) toServersSlice() (servers []models.Server) {
	servers = make([]models.Server, 0, len(hts))
	for _, server := range hts {
		servers = append(servers, server)
	}
	return servers
}

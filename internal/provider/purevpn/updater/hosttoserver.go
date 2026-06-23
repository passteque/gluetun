package updater

import (
	"net/netip"
	"slices"

	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
)

type hostToServer map[string]models.Server

func (hts hostToServer) add(host string, ips []netip.Addr, tcp, udp bool, tcpPorts, udpPorts []uint16, p2pTagged bool) {
	server, ok := hts[host]
	if !ok {
		server.VPN = vpn.OpenVPN
		server.Hostname = host
	}
	for _, ip := range ips {
		server.IPs = appendIfMissing(server.IPs, ip)
	}
	portForward, quantumResistant, obfuscated, p2pInHost := inferPureVPNTraits(host)
	server.PortForward = server.PortForward || portForward
	server.QuantumResistant = server.QuantumResistant || quantumResistant
	server.Obfuscated = server.Obfuscated || obfuscated
	if p2pTagged || p2pInHost {
		server.Categories = appendIfMissing(server.Categories, "p2p")
	}
	if tcp {
		server.TCP = true
		for _, port := range tcpPorts {
			server.OpenVPNTCPPorts = appendIfMissing(server.OpenVPNTCPPorts, port)
		}
	}
	if udp {
		server.UDP = true
		for _, port := range udpPorts {
			server.OpenVPNUDPPorts = appendIfMissing(server.OpenVPNUDPPorts, port)
		}
	}
	hts[host] = server
}

func (hts hostToServer) mergeWith(other hostToServer) {
	for host, server := range other {
		_, ok := hts[host]
		if !ok {
			hts[host] = server
			continue
		}
		p2pTagged := slices.Contains(server.Categories, "p2p")
		hts.add(host, server.IPs, server.TCP, server.UDP, server.OpenVPNTCPPorts, server.OpenVPNUDPPorts, p2pTagged)
	}
}

func (hts hostToServer) toHostsSlice() (hosts []string) {
	hosts = make([]string, 0, len(hts))
	for host := range hts {
		hosts = append(hosts, host)
	}
	return hosts
}

func (hts hostToServer) adaptWithIPs(hostToIPs map[string][]netip.Addr, override bool) {
	for host, IPs := range hostToIPs {
		server := hts[host]
		if override || len(server.IPs) == 0 {
			server.IPs = IPs
		}
		hts[host] = server
	}
}

func (hts hostToServer) toServersSlice() (servers []models.Server) {
	servers = make([]models.Server, 0, len(hts))
	for _, server := range hts {
		servers = append(servers, server)
	}
	return servers
}

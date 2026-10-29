package updater

import (
	"net/netip"
	"slices"

	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
)

type hostToServer map[string]models.Server

func (hts hostToServer) add(host string, ips []netip.Addr, tcp, udp bool, tcpPorts, udpPorts []uint16, p2p bool) {
	const p2pCategory = "p2p"

	server, ok := hts[host]
	if !ok {
		server.VPN = vpn.OpenVPN
		server.Hostname = host
	}
	for _, ip := range ips {
		if !slices.Contains(server.IPs, ip) {
			server.IPs = append(server.IPs, ip)
		}
	}
	portForward, quantumResistant, obfuscated, p2pInHostname := inferPureVPNTraits(host)
	server.PortForward = server.PortForward || portForward
	server.QuantumResistant = server.QuantumResistant || quantumResistant
	server.Obfuscated = server.Obfuscated || obfuscated
	if (p2p || p2pInHostname) && !slices.Contains(server.Categories, p2pCategory) {
		server.Categories = append(server.Categories, p2pCategory)
	}
	if tcp {
		server.TCP = true
		for _, port := range tcpPorts {
			if !slices.Contains(server.TCPPorts, port) {
				server.TCPPorts = append(server.TCPPorts, port)
			}
		}
	}
	if udp {
		server.UDP = true
		for _, port := range udpPorts {
			if !slices.Contains(server.UDPPorts, port) {
				server.UDPPorts = append(server.UDPPorts, port)
			}
		}
	}
	hts[host] = server
}

func (hts hostToServer) mergeWithFallback(fallback hostToServer) {
	for host, server := range fallback {
		existing, ok := hts[host]
		if !ok {
			hts[host] = server
			continue
		}

		// Do not add IP from fallback if existing server already has IPs
		fallbackIPs := server.IPs
		if len(existing.IPs) > 0 {
			fallbackIPs = nil
		}

		p2p := slices.Contains(server.Categories, "p2p")
		hts.add(host, fallbackIPs, server.TCP, server.UDP, server.TCPPorts, server.UDPPorts, p2p)
	}
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

package models

import "net/netip"

// WireguardConnection contains provider-generated Wireguard connection data.
type WireguardConnection struct {
	Connection Connection
	PrivateKey string
	Addresses  []netip.Prefix
	DNSServers []netip.Addr
	Gateway    netip.Addr
}

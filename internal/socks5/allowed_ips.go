package socks5

import "net/netip"

// ipAllowed returns whether the given client IP is allowed to use the
// SOCKS5 proxy server. An empty list of allowed CIDRs allows all IPs.
func ipAllowed(allowedCIDRs []netip.Prefix, ip netip.Addr) bool {
	if len(allowedCIDRs) == 0 {
		return true
	}
	for _, prefix := range allowedCIDRs {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

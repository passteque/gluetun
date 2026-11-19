package socks5

import "net/netip"

type Settings struct {
	Enabled  bool
	Username string
	Password string
	Address  string
	// AllowedCIDRs are the client IP CIDRs allowed to use the SOCKS5
	// proxy server. If empty, all client IPs are allowed.
	AllowedCIDRs []netip.Prefix
	Logger       Logger
}

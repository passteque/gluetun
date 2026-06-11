package settings

import (
	"fmt"
	"net/http"
	"net/netip"
	"regexp"

	"github.com/qdm12/dns/v2/pkg/blockbuilder"
	"github.com/qdm12/gosettings"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gotree"
)

// DNSBlacklist is settings for the DNS blacklist building.
type DNSBlacklist struct {
	BlockMalicious       *bool
	BlockAds             *bool
	BlockSurveillance    *bool
	AllowedHosts         []string
	AddBlockedHosts      []string
	AddBlockedIPs        []netip.Addr
	AddBlockedIPPrefixes []netip.Prefix
	// RebindingProtectionExemptHostnames is a list of hostnames
	// exempt from DNS rebinding protection. It can contain parent
	// domains which are of the form "*.example.com". Note the wildcard
	// can only be used at the start of the hostname.
	RebindingProtectionExemptHostnames []string
}

func (b *DNSBlacklist) setDefaults() {
	b.BlockMalicious = gosettings.DefaultPointer(b.BlockMalicious, true)
	b.BlockAds = gosettings.DefaultPointer(b.BlockAds, false)
	b.BlockSurveillance = gosettings.DefaultPointer(b.BlockSurveillance, true)
}

var hostRegex = regexp.MustCompile(`^([a-zA-Z0-9]|[a-zA-Z0-9_][a-zA-Z0-9\-_]{0,61}[a-zA-Z0-9_])(\.([a-zA-Z0-9]|[a-zA-Z0-9_][a-zA-Z0-9\-_]{0,61}[a-zA-Z0-9]))*$`) //nolint:lll

func (b DNSBlacklist) validate() (err error) {
	for _, host := range b.AllowedHosts {
		if !hostRegex.MatchString(host) {
			return fmt.Errorf("allowed host is not valid: %s", host)
		}
	}

	for _, host := range b.AddBlockedHosts {
		if !hostRegex.MatchString(host) {
			return fmt.Errorf("blocked host is not valid: %s", host)
		}
	}

	for _, host := range b.RebindingProtectionExemptHostnames {
		if len(host) > 2 && host[:2] == "*." {
			host = host[2:]
		}
		if !hostRegex.MatchString(host) {
			return fmt.Errorf("rebinding protection exempt host is not valid: %s", host)
		}
	}

	return nil
}

func (b DNSBlacklist) copy() (copied DNSBlacklist) {
	return DNSBlacklist{
		BlockMalicious:                     gosettings.CopyPointer(b.BlockMalicious),
		BlockAds:                           gosettings.CopyPointer(b.BlockAds),
		BlockSurveillance:                  gosettings.CopyPointer(b.BlockSurveillance),
		AllowedHosts:                       gosettings.CopySlice(b.AllowedHosts),
		AddBlockedHosts:                    gosettings.CopySlice(b.AddBlockedHosts),
		AddBlockedIPs:                      gosettings.CopySlice(b.AddBlockedIPs),
		AddBlockedIPPrefixes:               gosettings.CopySlice(b.AddBlockedIPPrefixes),
		RebindingProtectionExemptHostnames: gosettings.CopySlice(b.RebindingProtectionExemptHostnames),
	}
}

func (b *DNSBlacklist) overrideWith(other DNSBlacklist) {
	b.BlockMalicious = gosettings.OverrideWithPointer(b.BlockMalicious, other.BlockMalicious)
	b.BlockAds = gosettings.OverrideWithPointer(b.BlockAds, other.BlockAds)
	b.BlockSurveillance = gosettings.OverrideWithPointer(b.BlockSurveillance, other.BlockSurveillance)
	b.AllowedHosts = gosettings.OverrideWithSlice(b.AllowedHosts, other.AllowedHosts)
	b.AddBlockedHosts = gosettings.OverrideWithSlice(b.AddBlockedHosts, other.AddBlockedHosts)
	b.AddBlockedIPs = gosettings.OverrideWithSlice(b.AddBlockedIPs, other.AddBlockedIPs)
	b.AddBlockedIPPrefixes = gosettings.OverrideWithSlice(b.AddBlockedIPPrefixes, other.AddBlockedIPPrefixes)
	b.RebindingProtectionExemptHostnames = gosettings.OverrideWithSlice(b.RebindingProtectionExemptHostnames,
		other.RebindingProtectionExemptHostnames)
}

func (b DNSBlacklist) ToBlockBuilderSettings(client *http.Client) (
	settings blockbuilder.Settings,
) {
	return blockbuilder.Settings{
		Client:               client,
		BlockMalicious:       b.BlockMalicious,
		BlockAds:             b.BlockAds,
		BlockSurveillance:    b.BlockSurveillance,
		AllowedHosts:         b.AllowedHosts,
		AddBlockedHosts:      b.AddBlockedHosts,
		AddBlockedIPs:        b.AddBlockedIPs,
		AddBlockedIPPrefixes: b.AddBlockedIPPrefixes,
	}
}

func (b DNSBlacklist) String() string {
	return b.toLinesNode().String()
}

func (b DNSBlacklist) toLinesNode() (node *gotree.Node) {
	node = gotree.New("DNS filtering settings:")

	node.Appendf("Block malicious: %s", gosettings.BoolToYesNo(b.BlockMalicious))
	node.Appendf("Block ads: %s", gosettings.BoolToYesNo(b.BlockAds))
	node.Appendf("Block surveillance: %s", gosettings.BoolToYesNo(b.BlockSurveillance))

	if len(b.AllowedHosts) > 0 {
		allowedHostsNode := node.Append("Allowed hosts:")
		for _, host := range b.AllowedHosts {
			allowedHostsNode.Append(host)
		}
	}

	if len(b.AddBlockedHosts) > 0 {
		blockedHostsNode := node.Append("Blocked hosts:")
		for _, host := range b.AddBlockedHosts {
			blockedHostsNode.Append(host)
		}
	}

	if len(b.AddBlockedIPs) > 0 {
		blockedIPsNode := node.Append("Blocked IP addresses:")
		for _, ip := range b.AddBlockedIPs {
			blockedIPsNode.Append(ip.String())
		}
	}

	if len(b.AddBlockedIPPrefixes) > 0 {
		blockedIPPrefixesNode := node.Append("Blocked IP networks:")
		for _, ipNetwork := range b.AddBlockedIPPrefixes {
			blockedIPPrefixesNode.Append(ipNetwork.String())
		}
	}

	if len(b.RebindingProtectionExemptHostnames) > 0 {
		exemptHostsNode := node.Append("Rebinding protection exempt hostnames:")
		for _, host := range b.RebindingProtectionExemptHostnames {
			exemptHostsNode.Append(host)
		}
	}

	return node
}

func (b *DNSBlacklist) read(r *reader.Reader) (err error) {
	b.BlockMalicious, err = r.BoolPtr("BLOCK_MALICIOUS")
	if err != nil {
		return err
	}

	b.BlockSurveillance, err = r.BoolPtr("BLOCK_SURVEILLANCE",
		reader.RetroKeys("BLOCK_NSA"))
	if err != nil {
		return err
	}

	b.BlockAds, err = r.BoolPtr("BLOCK_ADS")
	if err != nil {
		return err
	}

	b.AddBlockedIPs, b.AddBlockedIPPrefixes, err = readDNSBlockedIPs(r)
	if err != nil {
		return err
	}

	b.AllowedHosts = r.CSV("DNS_UNBLOCK_HOSTNAMES", reader.RetroKeys("UNBLOCK"))

	b.RebindingProtectionExemptHostnames = r.CSV("DNS_REBINDING_PROTECTION_EXEMPT_HOSTNAMES")

	return nil
}

func readDNSBlockedIPs(r *reader.Reader) (ips []netip.Addr,
	ipPrefixes []netip.Prefix, err error,
) {
	ips, err = r.CSVNetipAddresses("DNS_BLOCK_IPS")
	if err != nil {
		return nil, nil, err
	}
	ipPrefixes, err = r.CSVNetipPrefixes("DNS_BLOCK_IP_PREFIXES")
	if err != nil {
		return nil, nil, err
	}

	// TODO v4 remove this block below
	privateIPs, privateIPPrefixes, err := readDNSPrivateAddresses(r)
	if err != nil {
		return nil, nil, err
	}
	ips = append(ips, privateIPs...)
	ipPrefixes = append(ipPrefixes, privateIPPrefixes...)

	return ips, ipPrefixes, nil
}

func readDNSPrivateAddresses(r *reader.Reader) (ips []netip.Addr,
	ipPrefixes []netip.Prefix, err error,
) {
	privateAddresses := r.CSV("DOT_PRIVATE_ADDRESS", reader.IsRetro("DNS_BLOCK_IP_PREFIXES"))
	if len(privateAddresses) == 0 {
		return nil, nil, nil
	}

	ips = make([]netip.Addr, 0, len(privateAddresses))
	ipPrefixes = make([]netip.Prefix, 0, len(privateAddresses))

	for _, privateAddress := range privateAddresses {
		ip, err := netip.ParseAddr(privateAddress)
		if err == nil {
			ips = append(ips, ip)
			continue
		}

		ipPrefix, err := netip.ParsePrefix(privateAddress)
		if err == nil {
			ipPrefixes = append(ipPrefixes, ipPrefix)
			continue
		}

		return nil, nil, fmt.Errorf(
			"environment variable DOT_PRIVATE_ADDRESS: "+
				"private address is not a valid IP or CIDR range: %s",
			privateAddress)
	}

	return ips, ipPrefixes, nil
}

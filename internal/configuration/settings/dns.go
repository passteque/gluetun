package settings

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/qdm12/dns/v2/pkg/provider"
	"github.com/qdm12/gluetun/internal/configuration/settings/helpers"
	"github.com/qdm12/gosettings"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gotree"
)

const (
	DNSUpstreamTypeDot   = "dot"
	DNSUpstreamTypeDoh   = "doh"
	DNSUpstreamTypePlain = "plain"
)

// DNS contains settings to configure DNS.
type DNS struct {
	// UpstreamType can be [DNSUpstreamTypeDot], [DNSUpstreamTypeDoh]
	// or [DNSUpstreamTypePlain]. It defaults to [DNSUpstreamTypeDot].
	UpstreamType string `json:"upstream_type"`
	// UpdatePeriod is the period to update DNS block lists.
	// It can be set to 0 to disable the update.
	// It defaults to 24h and cannot be nil in
	// the internal state.
	UpdatePeriod *time.Duration
	// Providers is a list of DNS providers.
	// It defaults to ["cloudflare"] and is ignored if the UpstreamType is
	// [DNSUpstreamTypePlain] and the UpstreamPlainAddresses field is set.
	Providers []string `json:"providers"`
	// Caching is true if the server should cache
	// DNS responses.
	Caching *bool `json:"caching"`
	// IPv6 is true if the server should connect over IPv6.
	IPv6 *bool `json:"ipv6"`
	// Blacklist contains settings to configure the filter
	// block lists.
	Blacklist DNSBlacklist
	// UpstreamPlainAddresses are the upstream plaintext DNS resolver
	// addresses to use by the built-in DNS server forwarder.
	// Note, if the upstream type is [dnsUpstreamTypePlain] and this field is set,
	// the Providers field is ignored.
	UpstreamPlainAddresses []netip.AddrPort
}

var (
	ErrDNSUpstreamTypeNotValid = errors.New("DNS upstream type is not valid")
	ErrDNSUpdatePeriodTooShort = errors.New("update period is too short")
	ErrDNSUpstreamPlainNoIPv6  = errors.New("upstream plain addresses do not contain any IPv6 address")
	ErrDNSUpstreamPlainNoIPv4  = errors.New("upstream plain addresses do not contain any IPv4 address")
)

func (d DNS) validate() (err error) {
	if !helpers.IsOneOf(d.UpstreamType, DNSUpstreamTypeDot, DNSUpstreamTypeDoh, DNSUpstreamTypePlain) {
		return fmt.Errorf("%w: %s", ErrDNSUpstreamTypeNotValid, d.UpstreamType)
	}

	const minUpdatePeriod = 30 * time.Second
	if *d.UpdatePeriod != 0 && *d.UpdatePeriod < minUpdatePeriod {
		return fmt.Errorf("%w: %s must be bigger than %s",
			ErrDNSUpdatePeriodTooShort, *d.UpdatePeriod, minUpdatePeriod)
	}

	if d.UpstreamType == DNSUpstreamTypePlain {
		selectedHasPlainIPv4, selectedHasPlainIPv6 := false, false
		for _, addrPort := range d.UpstreamPlainAddresses {
			if !selectedHasPlainIPv4 && addrPort.Addr().Is4() {
				selectedHasPlainIPv4 = true
			}
			if !selectedHasPlainIPv6 && addrPort.Addr().Is6() {
				selectedHasPlainIPv6 = true
			}
			if selectedHasPlainIPv4 && selectedHasPlainIPv6 {
				break
			}
		}
		switch {
		case *d.IPv6 && !selectedHasPlainIPv6:
			return fmt.Errorf("%w: in %d addresses", ErrDNSUpstreamPlainNoIPv6, len(d.UpstreamPlainAddresses))
		case !*d.IPv6 && !selectedHasPlainIPv4:
			return fmt.Errorf("%w: in %d addresses", ErrDNSUpstreamPlainNoIPv4, len(d.UpstreamPlainAddresses))
		}
	}
	// Note: all DNS built in providers have both IPv4 and IPv6 addresses for all modes

	err = d.Blacklist.validate()
	if err != nil {
		return err
	}

	return nil
}

func (d *DNS) Copy() (copied DNS) {
	return DNS{
		UpstreamType:           d.UpstreamType,
		UpdatePeriod:           gosettings.CopyPointer(d.UpdatePeriod),
		Providers:              gosettings.CopySlice(d.Providers),
		Caching:                gosettings.CopyPointer(d.Caching),
		IPv6:                   gosettings.CopyPointer(d.IPv6),
		Blacklist:              d.Blacklist.copy(),
		UpstreamPlainAddresses: gosettings.CopySlice(d.UpstreamPlainAddresses),
	}
}

// overrideWith overrides fields of the receiver
// settings object with any field set in the other
// settings.
func (d *DNS) overrideWith(other DNS) {
	d.UpstreamType = gosettings.OverrideWithComparable(d.UpstreamType, other.UpstreamType)
	d.UpdatePeriod = gosettings.OverrideWithPointer(d.UpdatePeriod, other.UpdatePeriod)
	d.Providers = gosettings.OverrideWithSlice(d.Providers, other.Providers)
	d.Caching = gosettings.OverrideWithPointer(d.Caching, other.Caching)
	d.IPv6 = gosettings.OverrideWithPointer(d.IPv6, other.IPv6)
	d.Blacklist.overrideWith(other.Blacklist)
	d.UpstreamPlainAddresses = gosettings.OverrideWithSlice(d.UpstreamPlainAddresses, other.UpstreamPlainAddresses)
}

func (d *DNS) setDefaults() {
	d.UpstreamType = gosettings.DefaultComparable(d.UpstreamType, DNSUpstreamTypeDot)
	const defaultUpdatePeriod = 24 * time.Hour
	d.UpdatePeriod = gosettings.DefaultPointer(d.UpdatePeriod, defaultUpdatePeriod)
	d.UpstreamPlainAddresses = gosettings.DefaultSlice(d.UpstreamPlainAddresses, []netip.AddrPort{})
	d.Providers = gosettings.DefaultSlice(d.Providers, defaultDNSProviders())
	d.Caching = gosettings.DefaultPointer(d.Caching, true)
	d.IPv6 = gosettings.DefaultPointer(d.IPv6, false)
	d.Blacklist.setDefaults()
}

func defaultDNSProviders() []string {
	return []string{
		provider.Cloudflare().Name,
	}
}

func (d DNS) GetFirstPlaintextIPv4() (ipv4 netip.Addr) {
	if d.UpstreamType == DNSUpstreamTypePlain {
		for _, addrPort := range d.UpstreamPlainAddresses {
			if addrPort.Addr().Is4() {
				return addrPort.Addr()
			}
		}
	}

	ipv4 = findPlainIPv4InProviders(d.Providers)
	if ipv4.IsValid() {
		return ipv4
	}

	// Either:
	// - all upstream plain addresses are IPv6 and no provider is set
	// - all providers set do not have a plaintext IPv4 address
	ipv4 = findPlainIPv4InProviders(defaultDNSProviders())
	if !ipv4.IsValid() {
		panic("no plaintext IPv4 address found in default DNS providers")
	}
	return ipv4
}

func findPlainIPv4InProviders(providerNames []string) netip.Addr {
	providers := provider.NewProviders()
	for _, name := range providerNames {
		provider, err := providers.Get(name)
		if err != nil {
			// Settings should be validated before calling this function,
			// so an error happening here is a programming error.
			panic(err)
		}
		if len(provider.Plain.IPv4) > 0 {
			return provider.Plain.IPv4[0].Addr()
		}
	}
	return netip.Addr{}
}

func (d DNS) String() string {
	return d.toLinesNode().String()
}

func (d DNS) toLinesNode() (node *gotree.Node) {
	node = gotree.New("DNS settings:")

	node.Appendf("Upstream resolver type: %s", d.UpstreamType)

	upstreamResolvers := node.Append("Upstream resolvers:")
	if len(d.UpstreamPlainAddresses) > 0 {
		if d.UpstreamType == DNSUpstreamTypePlain {
			for _, addr := range d.UpstreamPlainAddresses {
				upstreamResolvers.Append(addr.String())
			}
		} else {
			node.Appendf("Upstream plain addresses: ignored because upstream type is not plain")
			for _, provider := range d.Providers {
				upstreamResolvers.Append(provider)
			}
		}
	} else {
		for _, provider := range d.Providers {
			upstreamResolvers.Append(provider)
		}
	}

	node.Appendf("Caching: %s", gosettings.BoolToYesNo(d.Caching))
	node.Appendf("IPv6: %s", gosettings.BoolToYesNo(d.IPv6))

	update := "disabled"
	if *d.UpdatePeriod > 0 {
		update = "every " + d.UpdatePeriod.String()
	}
	node.Appendf("Update period: %s", update)

	node.AppendNode(d.Blacklist.toLinesNode())

	return node
}

func (d *DNS) read(r *reader.Reader) (err error) {
	d.UpstreamType = r.String("DNS_UPSTREAM_RESOLVER_TYPE")

	d.UpdatePeriod, err = r.DurationPtr("DNS_UPDATE_PERIOD")
	if err != nil {
		return err
	}

	d.Providers = r.CSV("DNS_UPSTREAM_RESOLVERS", reader.RetroKeys("DOT_PROVIDERS"))

	d.Caching, err = r.BoolPtr("DNS_CACHING", reader.RetroKeys("DOT_CACHING"))
	if err != nil {
		return err
	}

	d.IPv6, err = r.BoolPtr("DNS_UPSTREAM_IPV6", reader.RetroKeys("DOT_IPV6"))
	if err != nil {
		return err
	}

	err = d.Blacklist.read(r)
	if err != nil {
		return err
	}

	err = d.readUpstreamPlainAddresses(r)
	if err != nil {
		return err
	}

	return nil
}

func (d *DNS) readUpstreamPlainAddresses(r *reader.Reader) (err error) {
	// If DNS_UPSTREAM_PLAIN_ADDRESSES is set, the user must also set DNS_UPSTREAM_TYPE=plain
	// for these to be used. This is an added safety measure to reduce misunderstandings, and
	// reduce odd settings overrides.
	d.UpstreamPlainAddresses, err = r.CSVNetipAddrPorts("DNS_UPSTREAM_PLAIN_ADDRESSES")
	if err != nil {
		return err
	}

	// Retro-compatibility - remove in v4
	// If DNS_ADDRESS is set to a non-localhost address, append it to the other
	// upstream plain addresses, assuming port 53, and force the upstream type to plain
	// to maintain retro-compatibility behavior.
	serverAddress, err := r.NetipAddr("DNS_ADDRESS",
		reader.RetroKeys("DNS_PLAINTEXT_ADDRESS"),
		reader.IsRetro("DNS_UPSTREAM_PLAIN_ADDRESSES"))
	if err != nil {
		return err
	} else if !serverAddress.IsValid() {
		return nil
	}
	isLocalhost := serverAddress.Compare(netip.AddrFrom4([4]byte{127, 0, 0, 1})) == 0
	if isLocalhost {
		return nil
	}
	const defaultPlainPort = 53
	addrPort := netip.AddrPortFrom(serverAddress, defaultPlainPort)
	d.UpstreamPlainAddresses = append(d.UpstreamPlainAddresses, addrPort)
	d.UpstreamType = DNSUpstreamTypePlain
	return nil
}

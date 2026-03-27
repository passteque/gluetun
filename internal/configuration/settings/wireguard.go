package settings

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gosettings"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gosettings/validate"
	"github.com/qdm12/gotree"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Wireguard contains settings to configure the Wireguard client.
type Wireguard struct {
	// PrivateKey is the Wireguard client peer private key.
	// It cannot be nil in the internal state.
	PrivateKey *string `json:"private_key"`
	// PreSharedKey is the Wireguard pre-shared key.
	// It can be the empty string to indicate there
	// is no pre-shared key.
	// It cannot be nil in the internal state.
	PreSharedKey *string `json:"pre_shared_key"`
	// Addresses are the Wireguard interface addresses.
	Addresses []netip.Prefix `json:"addresses"`
	// AllowedIPs are the Wireguard allowed IPs.
	// If left unset, they default to "0.0.0.0/0"
	// and, if IPv6 is supported, "::0".
	AllowedIPs []netip.Prefix `json:"allowed_ips"`
	// Interface is the name of the Wireguard interface
	// to create. It cannot be the empty string in the
	// internal state.
	Interface                   string         `json:"interface"`
	PersistentKeepaliveInterval *time.Duration `json:"persistent_keep_alive_interval"`
	// Maximum Transmission Unit (MTU) of the Wireguard interface.
	// It cannot be nil in the internal state, and defaults to
	// 0 indicating to use PMTUD.
	MTU *uint32 `json:"mtu"`
	// Implementation is the Wireguard implementation to use.
	// It can be "auto", "userspace" or "kernelspace".
	// It defaults to "auto" and cannot be the empty string
	// in the internal state.
	Implementation string `json:"implementation"`
}

var regexpInterfaceName = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

// Validate validates Wireguard settings.
// It should only be ran if the VPN type chosen is Wireguard or AmneziaWg.
func (w Wireguard) validate(vpnProvider string, ipv6Supported, amneziawg bool) (err error) {
	// Validate PrivateKey
	if *w.PrivateKey == "" {
		return fmt.Errorf("%w", ErrWireguardPrivateKeyNotSet)
	}
	_, err = wgtypes.ParseKey(*w.PrivateKey)
	if err != nil {
		err = fmt.Errorf("private key is not valid: %w", err)
		if vpnProvider == providers.Nordvpn &&
			err.Error() == "wgtypes: incorrect key size: 48" {
			err = fmt.Errorf("%w - you might be using your access token instead of the Wireguard private key", err)
		}
		return err
	}

	if vpnProvider == providers.Airvpn {
		if *w.PreSharedKey == "" {
			return fmt.Errorf("%w", ErrWireguardPreSharedKeyNotSet)
		}
	}

	// Validate PreSharedKey
	if *w.PreSharedKey != "" { // Note: this is optional
		_, err = wgtypes.ParseKey(*w.PreSharedKey)
		if err != nil {
			return fmt.Errorf("pre-shared key is not valid: %w", err)
		}
	}

	// Validate Addresses
	if len(w.Addresses) == 0 {
		return fmt.Errorf("%w", ErrWireguardInterfaceAddressNotSet)
	}
	for i, ipNet := range w.Addresses {
		if !ipNet.IsValid() {
			return fmt.Errorf("%w: for address at index %d",
				ErrWireguardInterfaceAddressNotSet, i)
		}

		if !ipv6Supported && ipNet.Addr().Is6() {
			return fmt.Errorf("%w: address %s",
				ErrWireguardInterfaceAddressIPv6, ipNet.String())
		}
	}

	// Validate AllowedIPs
	// WARNING: do not check for IPv6 networks in the allowed IPs,
	// the wireguard code will take care to ignore it.
	if len(w.AllowedIPs) == 0 {
		return fmt.Errorf("%w", ErrWireguardAllowedIPsNotSet)
	}
	for i, allowedIP := range w.AllowedIPs {
		if !allowedIP.IsValid() {
			return fmt.Errorf("%w: for allowed ip %d of %d",
				ErrWireguardAllowedIPNotSet, i+1, len(w.AllowedIPs))
		}
	}

	if *w.PersistentKeepaliveInterval < 0 {
		return fmt.Errorf("%w: %s", ErrWireguardKeepAliveNegative,
			*w.PersistentKeepaliveInterval)
	}

	// Validate interface
	if !regexpInterfaceName.MatchString(w.Interface) {
		return fmt.Errorf("%w: '%s' does not match regex '%s'",
			ErrWireguardInterfaceNotValid, w.Interface, regexpInterfaceName)
	}

	if !amneziawg { // amneziawg should have its own Implementation field and ignore this one
		validImplementations := []string{"auto", "userspace", "kernelspace"}
		if err := validate.IsOneOf(w.Implementation, validImplementations...); err != nil {
			return fmt.Errorf("%w: %w", ErrWireguardImplementationNotValid, err)
		}
	}

	return nil
}

func (w *Wireguard) copy() (copied Wireguard) {
	return Wireguard{
		PrivateKey:                  gosettings.CopyPointer(w.PrivateKey),
		PreSharedKey:                gosettings.CopyPointer(w.PreSharedKey),
		Addresses:                   gosettings.CopySlice(w.Addresses),
		AllowedIPs:                  gosettings.CopySlice(w.AllowedIPs),
		PersistentKeepaliveInterval: gosettings.CopyPointer(w.PersistentKeepaliveInterval),
		Interface:                   w.Interface,
		MTU:                         w.MTU,
		Implementation:              w.Implementation,
	}
}

func (w *Wireguard) overrideWith(other Wireguard) {
	w.PrivateKey = gosettings.OverrideWithPointer(w.PrivateKey, other.PrivateKey)
	w.PreSharedKey = gosettings.OverrideWithPointer(w.PreSharedKey, other.PreSharedKey)
	w.Addresses = gosettings.OverrideWithSlice(w.Addresses, other.Addresses)
	w.AllowedIPs = gosettings.OverrideWithSlice(w.AllowedIPs, other.AllowedIPs)
	w.PersistentKeepaliveInterval = gosettings.OverrideWithPointer(w.PersistentKeepaliveInterval,
		other.PersistentKeepaliveInterval)
	w.Interface = gosettings.OverrideWithComparable(w.Interface, other.Interface)
	w.MTU = gosettings.OverrideWithComparable(w.MTU, other.MTU)
	w.Implementation = gosettings.OverrideWithComparable(w.Implementation, other.Implementation)
}

func (w *Wireguard) setDefaults(vpnProvider string) {
	w.PrivateKey = gosettings.DefaultPointer(w.PrivateKey, "")
	w.PreSharedKey = gosettings.DefaultPointer(w.PreSharedKey, "")
	switch vpnProvider {
	case providers.Nordvpn:
		defaultNordVPNAddress := netip.AddrFrom4([4]byte{10, 5, 0, 2})
		defaultNordVPNPrefix := netip.PrefixFrom(defaultNordVPNAddress, defaultNordVPNAddress.BitLen())
		w.Addresses = gosettings.DefaultSlice(w.Addresses, []netip.Prefix{defaultNordVPNPrefix})
	case providers.Protonvpn:
		defaultAddress := netip.AddrFrom4([4]byte{10, 2, 0, 2})
		defaultPrefix := netip.PrefixFrom(defaultAddress, defaultAddress.BitLen())
		w.Addresses = gosettings.DefaultSlice(w.Addresses, []netip.Prefix{defaultPrefix})
	}
	defaultAllowedIPs := []netip.Prefix{
		netip.PrefixFrom(netip.IPv4Unspecified(), 0),
		netip.PrefixFrom(netip.IPv6Unspecified(), 0),
	}
	w.AllowedIPs = gosettings.DefaultSlice(w.AllowedIPs, defaultAllowedIPs)
	w.PersistentKeepaliveInterval = gosettings.DefaultPointer(w.PersistentKeepaliveInterval, 0)
	w.Interface = gosettings.DefaultComparable(w.Interface, "wg0")
	w.MTU = gosettings.DefaultPointer(w.MTU, 0)
	w.Implementation = gosettings.DefaultComparable(w.Implementation, "auto")
}

func (w Wireguard) String() string {
	return w.toLinesNode().String()
}

func (w Wireguard) toLinesNode() (node *gotree.Node) {
	node = gotree.New("Wireguard settings:")

	if *w.PrivateKey != "" {
		s := gosettings.ObfuscateKey(*w.PrivateKey)
		node.Appendf("Private key: %s", s)
	}

	if *w.PreSharedKey != "" {
		s := gosettings.ObfuscateKey(*w.PreSharedKey)
		node.Appendf("Pre-shared key: %s", s)
	}

	addressesNode := node.Appendf("Interface addresses:")
	for _, address := range w.Addresses {
		addressesNode.Append(address.String())
	}

	allowedIPsNode := node.Appendf("Allowed IPs:")
	for _, allowedIP := range w.AllowedIPs {
		allowedIPsNode.Append(allowedIP.String())
	}

	if *w.PersistentKeepaliveInterval > 0 {
		node.Appendf("Persistent keepalive interval: %s", w.PersistentKeepaliveInterval)
	}

	interfaceNode := node.Appendf("Network interface: %s", w.Interface)
	if *w.MTU == 0 {
		interfaceNode.Append("MTU: use path MTU discovery")
	} else {
		interfaceNode.Appendf("MTU: %d", *w.MTU)
	}

	if w.Implementation != "auto" {
		node.Appendf("Implementation: %s", w.Implementation)
	}

	return node
}

func (w *Wireguard) read(r *reader.Reader, amneziaWG bool) (err error) {
	prefix := "WIREGUARD"
	if amneziaWG {
		prefix = "AMNEZIAWG"
	}
	w.PrivateKey = r.Get(prefix+"_PRIVATE_KEY", reader.ForceLowercase(false))
	w.PreSharedKey = r.Get(prefix+"_PRESHARED_KEY", reader.ForceLowercase(false))
	w.Interface = r.String("VPN_INTERFACE",
		reader.RetroKeys(prefix+"_INTERFACE"), reader.ForceLowercase(false))

	if !amneziaWG {
		w.Implementation = r.String("WIREGUARD_IMPLEMENTATION")
	}

	addressStrings := r.CSV(prefix+"_ADDRESSES", reader.RetroKeys(prefix+"_ADDRESS"))
	// WARNING: do not initialize w.Addresses to an empty slice
	// or the defaults for nordvpn will not work.
	for _, addressString := range addressStrings {
		if !strings.ContainsRune(addressString, '/') {
			addressString += "/32"
		}
		addressString = strings.TrimSpace(addressString)
		address, err := netip.ParsePrefix(addressString)
		if err != nil {
			return fmt.Errorf("parsing address: %w", err)
		}
		w.Addresses = append(w.Addresses, address)
	}

	w.AllowedIPs, err = r.CSVNetipPrefixes(prefix + "_ALLOWED_IPS")
	if err != nil {
		return err // already wrapped
	}

	w.PersistentKeepaliveInterval, err = r.DurationPtr(prefix + "_PERSISTENT_KEEPALIVE_INTERVAL")
	if err != nil {
		return err
	}

	w.MTU, err = r.Uint32Ptr(prefix + "_MTU")
	if err != nil {
		return err
	}
	return nil
}

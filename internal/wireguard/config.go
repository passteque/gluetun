package wireguard

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func ConfigureDevice(client *wgctrl.Client, settings Settings) (err error) {
	deviceConfig, err := makeDeviceConfig(settings)
	if err != nil {
		return fmt.Errorf("making device configuration: %w", err)
	}

	err = client.ConfigureDevice(settings.InterfaceName, deviceConfig)
	if err != nil {
		return fmt.Errorf("configuring device: %w", err)
	}

	return nil
}

func makeDeviceConfig(settings Settings) (config wgtypes.Config, err error) {
	privateKey, err := wgtypes.ParseKey(settings.PrivateKey)
	if err != nil {
		return config, errors.New("cannot parse private key")
	}

	publicKey, err := wgtypes.ParseKey(settings.PublicKey)
	if err != nil {
		return config, fmt.Errorf("cannot parse public key: %s", settings.PublicKey)
	}

	var preSharedKey *wgtypes.Key
	if settings.PreSharedKey != "" {
		preSharedKeyValue, err := wgtypes.ParseKey(settings.PreSharedKey)
		if err != nil {
			return config, errors.New("cannot parse pre-shared key")
		}
		preSharedKey = &preSharedKeyValue
	}

	var persistentKeepaliveInterval *time.Duration
	if settings.PersistentKeepaliveInterval > 0 {
		persistentKeepaliveInterval = new(time.Duration)
		*persistentKeepaliveInterval = settings.PersistentKeepaliveInterval
	}

	firewallMark := int(settings.FirewallMark)
	allowedIPs := make([]net.IPNet, len(settings.AllowedIPs))
	for i, allowedIP := range settings.AllowedIPs {
		allowedIPs[i] = net.IPNet{
			IP:   allowedIP.Addr().AsSlice(),
			Mask: net.CIDRMask(allowedIP.Bits(), allowedIP.Addr().BitLen()),
		}
	}

	config = wgtypes.Config{
		PrivateKey:   &privateKey,
		ReplacePeers: true,
		FirewallMark: &firewallMark,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:                   publicKey,
				PresharedKey:                preSharedKey,
				AllowedIPs:                  allowedIPs,
				PersistentKeepaliveInterval: persistentKeepaliveInterval,
				ReplaceAllowedIPs:           true,
				Endpoint: &net.UDPAddr{
					IP:   settings.Endpoint.Addr().AsSlice(),
					Port: int(settings.Endpoint.Port()),
				},
			},
		},
	}

	return config, nil
}

func allIPv4() (prefix netip.Prefix) {
	const bits = 0
	return netip.PrefixFrom(netip.IPv4Unspecified(), bits)
}

func allIPv6() (prefix netip.Prefix) {
	const bits = 0
	return netip.PrefixFrom(netip.IPv6Unspecified(), bits)
}

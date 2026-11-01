package models

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Server_Equal(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		a     *Server
		b     Server
		equal bool
	}{
		"same IPs": {
			a: &Server{
				IPs: []netip.Addr{netip.AddrFrom4([4]byte{1, 2, 3, 4})},
			},
			b: Server{
				IPs: []netip.Addr{netip.AddrFrom4([4]byte{1, 2, 3, 4})},
			},
			equal: true,
		},
		"same IP strings": {
			a: &Server{
				IPs: []netip.Addr{netip.AddrFrom4([4]byte{1, 2, 3, 4})},
			},
			b: Server{
				IPs: []netip.Addr{netip.AddrFrom4([4]byte{1, 2, 3, 4})},
			},
			equal: true,
		},
		"different IPs": {
			a: &Server{
				IPs: []netip.Addr{netip.AddrFrom4([4]byte{1, 2, 3, 4}), netip.AddrFrom4([4]byte{2, 3, 4, 5})},
			},
			b: Server{
				IPs: []netip.Addr{netip.AddrFrom4([4]byte{1, 2, 3, 4}), netip.AddrFrom4([4]byte{1, 2, 3, 4})},
			},
		},
		"all fields equal": {
			a: &Server{
				VPN:         "vpn",
				Country:     "country",
				Region:      "region",
				City:        "city",
				ISP:         "isp",
				Owned:       true,
				Number:      1,
				ServerName:  "server_name",
				Hostname:    "hostname",
				TCP:         true,
				UDP:         true,
				OvpnX509:    "x509",
				RetroLoc:    "retroloc",
				MultiHop:    true,
				WgPubKey:    "wgpubkey",
				Free:        true,
				Stream:      true,
				SecureCore:  true,
				Tor:         true,
				PortForward: true,
				IPs:         []netip.Addr{netip.AddrFrom4([4]byte{1, 2, 3, 4})},
				Keep:        true,
			},
			b: Server{
				VPN:         "vpn",
				Country:     "country",
				Region:      "region",
				City:        "city",
				ISP:         "isp",
				Owned:       true,
				Number:      1,
				ServerName:  "server_name",
				Hostname:    "hostname",
				TCP:         true,
				UDP:         true,
				OvpnX509:    "x509",
				RetroLoc:    "retroloc",
				MultiHop:    true,
				WgPubKey:    "wgpubkey",
				Free:        true,
				Stream:      true,
				SecureCore:  true,
				Tor:         true,
				PortForward: true,
				IPs:         []netip.Addr{netip.AddrFrom4([4]byte{1, 2, 3, 4})},
				Keep:        true,
			},
			equal: true,
		},
		"different field": {
			a: &Server{
				VPN: "vpn",
			},
			b: Server{
				VPN: "other vpn",
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ipsOfANotNil := testCase.a.IPs != nil
			ipsOfBNotNil := testCase.b.IPs != nil

			equal := testCase.a.Equal(testCase.b)

			assert.Equal(t, testCase.equal, equal)

			// Ensure IPs field is not modified
			if ipsOfANotNil {
				assert.NotNil(t, testCase.a)
			}
			if ipsOfBNotNil {
				assert.NotNil(t, testCase.b)
			}
		})
	}
}

func Test_Server_HasMinimumInformation(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		server Server
		err    error
	}{
		"valid OpenVPN server": {
			server: Server{
				VPN: "openvpn",
				UDP: true,
				IPs: []netip.Addr{netip.AddrFrom4([4]byte{1, 2, 3, 4})},
			},
		},
		"valid Wireguard server with static pubkey": {
			server: Server{
				VPN:      "wireguard",
				WgPubKey: "pubkey123",
				IPs:      []netip.Addr{netip.AddrFrom4([4]byte{1, 2, 3, 4})},
			},
		},
		"valid Wireguard server with dynamic credentials": {
			server: Server{
				VPN:        "wireguard",
				ServerName: "bahamas413",
				IPs:        []netip.Addr{netip.AddrFrom4([4]byte{1, 2, 3, 4})},
			},
		},
		"empty vpn field": {
			server: Server{
				IPs: []netip.Addr{netip.AddrFrom4([4]byte{1, 2, 3, 4})},
			},
			err: assert.AnError,
		},
		"empty ips field": {
			server: Server{
				VPN: "openvpn",
				UDP: true,
			},
			err: assert.AnError,
		},
		"wireguard with network protocol": {
			server: Server{
				VPN:      "wireguard",
				WgPubKey: "pubkey123",
				UDP:      true,
				IPs:      []netip.Addr{netip.AddrFrom4([4]byte{1, 2, 3, 4})},
			},
			err: assert.AnError,
		},
		"openvpn with no protocol": {
			server: Server{
				VPN: "openvpn",
				IPs: []netip.Addr{netip.AddrFrom4([4]byte{1, 2, 3, 4})},
			},
			err: assert.AnError,
		},
		"wireguard with empty pubkey and empty server name": {
			server: Server{
				VPN: "wireguard",
				IPs: []netip.Addr{netip.AddrFrom4([4]byte{1, 2, 3, 4})},
			},
			err: assert.AnError,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := testCase.server.HasMinimumInformation()

			if testCase.err != nil {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

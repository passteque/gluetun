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
				VPN:              "vpn",
				Country:          "country",
				Region:           "region",
				City:             "city",
				ISP:              "isp",
				Owned:            true,
				Number:           1,
				ServerName:       "server_name",
				Hostname:         "hostname",
				TCP:              true,
				UDP:              true,
				OvpnX509:         "x509",
				RetroLoc:         "retroloc",
				MultiHop:         true,
				WgPubKey:         "wgpubkey",
				Free:             true,
				Stream:           true,
				SecureCore:       true,
				Tor:              true,
				PortForward:      true,
				QuantumResistant: true,
				Obfuscated:       true,
				IPs:              []netip.Addr{netip.AddrFrom4([4]byte{1, 2, 3, 4})},
				Keep:             true,
			},
			b: Server{
				VPN:              "vpn",
				Country:          "country",
				Region:           "region",
				City:             "city",
				ISP:              "isp",
				Owned:            true,
				Number:           1,
				ServerName:       "server_name",
				Hostname:         "hostname",
				TCP:              true,
				UDP:              true,
				OvpnX509:         "x509",
				RetroLoc:         "retroloc",
				MultiHop:         true,
				WgPubKey:         "wgpubkey",
				Free:             true,
				Stream:           true,
				SecureCore:       true,
				Tor:              true,
				PortForward:      true,
				QuantumResistant: true,
				Obfuscated:       true,
				IPs:              []netip.Addr{netip.AddrFrom4([4]byte{1, 2, 3, 4})},
				Keep:             true,
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

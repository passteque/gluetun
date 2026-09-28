package settings

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
)

type mockFilterChoicesGetter struct {
	choices models.FilterChoices
}

func (m mockFilterChoicesGetter) GetFilterChoices(string) models.FilterChoices {
	return m.choices
}

func Test_VPN_Validate_PIA_Wireguard(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		vpnSettings VPN
		err         error
	}{
		"valid PIA wireguard": {
			vpnSettings: VPN{
				Type: vpn.Wireguard,
				Provider: Provider{
					Name: providers.PrivateInternetAccess,
					ServerSelection: ServerSelection{
						VPN: vpn.Wireguard,
					},
					PortForwarding: PortForwarding{
						Enabled: ptrTo(false),
					},
				},
				OpenVPN: OpenVPN{
					User:     ptrTo("piauser"),
					Password: ptrTo("piapass"),
				},
				Wireguard: Wireguard{
					PrivateKey:                  ptrTo(""),
					PreSharedKey:                ptrTo(""),
					AllowedIPs:                  []netip.Prefix{netip.PrefixFrom(netip.IPv4Unspecified(), 0)},
					PersistentKeepaliveInterval: ptrTo(time.Duration(0)),
					Interface:                   "wg0",
					Implementation:              "auto",
				},
			},
		},
		"PIA wireguard missing user": {
			vpnSettings: VPN{
				Type: vpn.Wireguard,
				Provider: Provider{
					Name: providers.PrivateInternetAccess,
					ServerSelection: ServerSelection{
						VPN: vpn.Wireguard,
					},
					PortForwarding: PortForwarding{
						Enabled: ptrTo(false),
					},
				},
				OpenVPN: OpenVPN{
					User:     ptrTo(""),
					Password: ptrTo("piapass"),
				},
				Wireguard: Wireguard{
					PrivateKey:                  ptrTo(""),
					PreSharedKey:                ptrTo(""),
					AllowedIPs:                  []netip.Prefix{netip.PrefixFrom(netip.IPv4Unspecified(), 0)},
					PersistentKeepaliveInterval: ptrTo(time.Duration(0)),
					Interface:                   "wg0",
					Implementation:              "auto",
				},
			},
			err: errors.New("user is empty"),
		},
		"PIA wireguard missing password": {
			vpnSettings: VPN{
				Type: vpn.Wireguard,
				Provider: Provider{
					Name: providers.PrivateInternetAccess,
					ServerSelection: ServerSelection{
						VPN: vpn.Wireguard,
					},
					PortForwarding: PortForwarding{
						Enabled: ptrTo(false),
					},
				},
				OpenVPN: OpenVPN{
					User:     ptrTo("piauser"),
					Password: ptrTo(""),
				},
				Wireguard: Wireguard{
					PrivateKey:                  ptrTo(""),
					PreSharedKey:                ptrTo(""),
					AllowedIPs:                  []netip.Prefix{netip.PrefixFrom(netip.IPv4Unspecified(), 0)},
					PersistentKeepaliveInterval: ptrTo(time.Duration(0)),
					Interface:                   "wg0",
					Implementation:              "auto",
				},
			},
			err: errors.New("password is empty"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			vpnSettings := testCase.vpnSettings
			vpnSettings.setDefaults()

			filterChoicesGetter := mockFilterChoicesGetter{}
			warner := (Warner)(nil)
			const ipv6Supported = false

			err := vpnSettings.Validate(filterChoicesGetter, ipv6Supported, warner)

			if testCase.err != nil {
				assert.Equal(t, testCase.err.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

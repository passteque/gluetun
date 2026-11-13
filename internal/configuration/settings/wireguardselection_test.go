package settings

import (
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/stretchr/testify/assert"
)

func Test_WireguardSelection_validate(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		selection  WireguardSelection
		provider   string
		errMessage string
	}{
		"custom_with_endpoint_ip": {
			selection: WireguardSelection{
				EndpointIP:       netip.AddrFrom4([4]byte{1, 2, 3, 4}),
				EndpointHostname: new(""),
				EndpointPort:     new(uint16(51820)),
				PublicKey:        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			},
			provider: providers.Custom,
		},
		"custom_with_endpoint_hostname": {
			selection: WireguardSelection{
				EndpointIP:       netip.IPv4Unspecified(),
				EndpointHostname: new("myhost.dyndns.org"),
				EndpointPort:     new(uint16(51820)),
				PublicKey:        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			},
			provider: providers.Custom,
		},
		"custom_with_neither_ip_nor_hostname": {
			selection: WireguardSelection{
				EndpointIP:       netip.IPv4Unspecified(),
				EndpointHostname: new(""),
				EndpointPort:     new(uint16(51820)),
				PublicKey:        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			},
			provider:   providers.Custom,
			errMessage: "endpoint IP or endpoint hostname is not set",
		},
		"custom_with_both_ip_and_hostname": {
			selection: WireguardSelection{
				EndpointIP:       netip.AddrFrom4([4]byte{1, 2, 3, 4}),
				EndpointHostname: new("myhost.dyndns.org"),
				EndpointPort:     new(uint16(51820)),
				PublicKey:        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			},
			provider:   providers.Custom,
			errMessage: "endpoint IP and endpoint hostname are mutually exclusive",
		},
		"nordvpn_no_endpoint_needed": {
			selection: WireguardSelection{
				EndpointIP:       netip.IPv4Unspecified(),
				EndpointHostname: new(""),
				EndpointPort:     new(uint16(0)),
				PublicKey:        "",
			},
			provider: providers.Nordvpn,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := testCase.selection.validate(testCase.provider)

			if testCase.errMessage == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, testCase.errMessage)
			}
		})
	}
}

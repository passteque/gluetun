package utils

import (
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
)

func Test_ConnectionPicker_pickConnection(t *testing.T) {
	t.Parallel()

	picker := NewConnectionPicker()

	poolA := []models.Connection{
		{Port: 1}, {Port: 2}, {Port: 3},
	}
	connection := picker.pickConnection(poolA)
	assert.Equal(t, models.Connection{Port: 1}, connection)

	connection = picker.pickConnection(poolA)
	assert.Equal(t, models.Connection{Port: 2}, connection)

	connection = picker.pickConnection(poolA)
	assert.Equal(t, models.Connection{Port: 3}, connection)

	connection = picker.pickConnection(poolA)
	assert.Equal(t, models.Connection{Port: 1}, connection)

	poolB := []models.Connection{
		{Port: 10}, {Port: 20},
	}
	connection = picker.pickConnection(poolB)
	assert.Equal(t, models.Connection{Port: 10}, connection)

	connection = picker.pickConnection(poolB)
	assert.Equal(t, models.Connection{Port: 20}, connection)

	connection = picker.pickConnection(poolB)
	assert.Equal(t, models.Connection{Port: 10}, connection)
}

func Test_pickConnection(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		connections []models.Connection
		selection   settings.ServerSelection
		connection1 models.Connection
		connection2 models.Connection
		errMessage  string
	}{
		"empty_connections": {
			errMessage: "no connection to pick from",
		},
		"openvpn_cycles": {
			connections: []models.Connection{
				{Type: vpn.OpenVPN, Port: 1, Hostname: "one"},
				{Type: vpn.OpenVPN, Port: 2, Hostname: "two"},
			},
			selection: settings.ServerSelection{VPN: vpn.OpenVPN},
			connection1: models.Connection{
				Type: vpn.OpenVPN, Port: 1,
				Hostname: "one",
			},
			connection2: models.Connection{
				Type: vpn.OpenVPN, Port: 2,
				Hostname: "two",
			},
		},
		"openvpn_endpoint_ip_overrides_cycle_pick": {
			connections: []models.Connection{
				{Type: vpn.OpenVPN, Hostname: "one", IP: netip.AddrFrom4([4]byte{1, 1, 1, 1})},
				{Type: vpn.OpenVPN, Hostname: "two", IP: netip.AddrFrom4([4]byte{2, 2, 2, 2})},
			},
			selection: settings.ServerSelection{
				VPN: vpn.OpenVPN,
				OpenVPN: settings.OpenVPNSelection{
					EndpointIP: netip.AddrFrom4([4]byte{9, 9, 9, 9}),
				},
			},
			connection1: models.Connection{
				Type: vpn.OpenVPN, Hostname: "one",
				IP: netip.AddrFrom4([4]byte{9, 9, 9, 9}),
			},
			connection2: models.Connection{
				Type: vpn.OpenVPN, Hostname: "two",
				IP: netip.AddrFrom4([4]byte{9, 9, 9, 9}),
			},
		},
		"wireguard_endpoint_ip_picks_target": {
			connections: []models.Connection{
				{Type: vpn.Wireguard, Hostname: "one", IP: netip.AddrFrom4([4]byte{1, 1, 1, 1})},
				{Type: vpn.Wireguard, Hostname: "two", IP: netip.AddrFrom4([4]byte{2, 2, 2, 2})},
			},
			selection: settings.ServerSelection{
				VPN: vpn.Wireguard,
				Wireguard: settings.WireguardSelection{
					EndpointIP: netip.AddrFrom4([4]byte{2, 2, 2, 2}),
				},
			},
			connection1: models.Connection{
				Type: vpn.Wireguard, Hostname: "two",
				IP: netip.AddrFrom4([4]byte{2, 2, 2, 2}),
			},
			connection2: models.Connection{
				Type: vpn.Wireguard, Hostname: "two",
				IP: netip.AddrFrom4([4]byte{2, 2, 2, 2}),
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			connPicker := NewConnectionPicker()

			connection, err := pickConnection(testCase.connections,
				testCase.selection, connPicker)
			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
				assert.Equal(t, models.Connection{}, connection)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, testCase.connection1, connection)

			connection, err = pickConnection(testCase.connections,
				testCase.selection, connPicker)
			assert.NoError(t, err)
			assert.Equal(t, testCase.connection2, connection)
		})
	}
}

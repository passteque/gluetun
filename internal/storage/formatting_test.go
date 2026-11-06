package storage

import (
	"testing"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_noServerFoundError_wireguardOmitsOpenVPNSelection(t *testing.T) {
	t.Parallel()

	selection := settings.ServerSelection{
		VPN:     vpn.Wireguard,
		Regions: []string{"CA Vancouver"},
	}.WithDefaults(providers.PrivateInternetAccess)
	*selection.PortForwardOnly = true

	err := noServerFoundError(selection)
	require.Error(t, err)
	assert.ErrorContains(t, err,
		"no server found: for VPN wireguard; region CA Vancouver; port forwarding only")
	assert.NotContains(t, err.Error(), "protocol")
	assert.NotContains(t, err.Error(), "encryption preset")
	assert.NotContains(t, err.Error(), "target ip address")
}

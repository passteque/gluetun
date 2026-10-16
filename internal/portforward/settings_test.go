package portforward

import (
	"context"
	"testing"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/portforward/service"
	"github.com/qdm12/gluetun/internal/provider/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Settings_updateWith_stopsPIAWithoutRuntimeState(t *testing.T) {
	t.Parallel()

	settings := Settings{
		VPNIsUp: ptrTo(true),
		Service: service.Settings{
			Filepath:       "/tmp/forwarded_port",
			PortForwarder:  piaPortForwarderStub{},
			Interface:      "wg0",
			ServerName:     "vancouver439",
			CanPortForward: true,
			PortsCount:     1,
			Username:       "username",
			Password:       "password",
		},
	}

	updated, err := settings.updateWith(Settings{VPNIsUp: ptrTo(false)})
	require.NoError(t, err)
	assert.False(t, *updated.VPNIsUp)
	assert.Empty(t, updated.Service.ServerName)
	assert.False(t, updated.Service.Gateway.IsValid())
	assert.False(t, updated.Service.CanPortForward)
}

type piaPortForwarderStub struct{}

func (piaPortForwarderStub) Name() string {
	return providers.PrivateInternetAccess
}

func (piaPortForwarderStub) PortForward(context.Context, utils.PortForwardObjects) (map[uint16]uint16, error) {
	return map[uint16]uint16{}, nil
}

func (piaPortForwarderStub) KeepPortForward(context.Context, utils.PortForwardObjects) error {
	return nil
}

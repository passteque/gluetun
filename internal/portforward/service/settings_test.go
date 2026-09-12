package service

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Settings_OverrideWith_replacesConnectionRuntimeState(t *testing.T) {
	t.Parallel()

	settings := Settings{
		Gateway:        netip.MustParseAddr("10.0.0.1"),
		ServerName:     "old-server",
		CanPortForward: true,
		Username:       "username",
		Password:       "password",
		PortsCount:     1,
	}

	settings.OverrideWith(Settings{})

	assert.False(t, settings.Gateway.IsValid())
	assert.Empty(t, settings.ServerName)
	assert.False(t, settings.CanPortForward)
	assert.Equal(t, "username", settings.Username)
	assert.Equal(t, "password", settings.Password)
	assert.Equal(t, uint16(1), settings.PortsCount)
}

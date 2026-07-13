package settings

import (
	"testing"

	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gosettings/reader/sources/env"
	"github.com/stretchr/testify/assert"
)

func Test_PortForwarding_String(t *testing.T) {
	t.Parallel()

	settings := PortForwarding{
		Enabled: ptrTo(false),
	}

	s := settings.String()

	assert.Empty(t, s)
}

func Test_PortForwarding_read_serverName(t *testing.T) {
	t.Parallel()

	source := env.New(env.Settings{
		Environ: []string{"VPN_PORT_FORWARDING_SERVER_NAME=vancouver439"},
	})
	settingsReader := reader.New(reader.Settings{Sources: []reader.Source{source}})

	var settings PortForwarding
	err := settings.read(settingsReader)

	assert.NoError(t, err)
	assert.Equal(t, "vancouver439", settings.ServerName)
}

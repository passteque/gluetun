package amneziawg

import (
	"strings"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
	"github.com/qdm12/gluetun/internal/wireguard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Settings_uapiConfig_device(t *testing.T) {
	t.Parallel()

	testTUN := tuntest.NewChannelTUN()
	// Keep the device down so configuring it does not open network sockets.
	<-testTUN.TUN().Events()
	engine := device.NewDevice(testTUN.TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(engine.Close)
	configuration := Settings{
		Wireguard:                   wireguard.Settings{PublicKey: "oMNSf/zJ0pt1ciy+qIRk8Rlyfs9accwuRLnKd85Yl1Q="},
		JunkPacketCount:             4,
		JunkPacketMin:               20,
		JunkPacketMax:               60,
		PaddingS1:                   64,
		PaddingS2:                   64,
		PaddingS3:                   64,
		PaddingS4:                   64,
		HeaderH1:                    "101-109",
		HeaderH2:                    "201-209",
		HeaderH3:                    "301-309",
		HeaderH4:                    "401-409",
		InitPacketI1:                "<b 0x1234>",
		InitPacketI2:                "<r 8>",
		InitPacketI3:                "<rd 8>",
		InitPacketI4:                "<rc 8>",
		InitPacketI5:                "<t>",
		HeaderProtectionKey:         "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ=",
		ContentPaddingAddition:      [2]uint32{64, 128},
		RekeyAfterTime:              [2]uint32{110, 126},
		RekeyTimeout:                [2]uint32{5, 5},
		RejectAfterTime:             [2]uint32{170, 182},
		KeepaliveTimeout:            [2]uint32{12, 17},
		MaxHandshakeAttempts:        [2]uint32{3, 3},
		PersistentKeepaliveInterval: [2]uint32{25, 35},
		RandomTrailers:              true,
		DisableCookies:              true,
	}
	deviceConfig, err := configuration.uapiConfig()
	require.NoError(t, err)
	require.NoError(t, engine.IpcSet(deviceConfig))
	require.NoError(t, engine.IpcSet("replace_peers=true\n"+
		"public_key=a0c3527ffcc9d29b75722cbea88464f119727ecf5a71cc2e44b9ca77ce589754\n"+
		"endpoint=198.51.100.2:51820\nreplace_allowed_ips=true\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n"))
	peerConfig, err := configuration.peerUAPIConfig()
	require.NoError(t, err)
	require.NoError(t, engine.IpcSet(peerConfig))
	actual, err := engine.IpcGet()
	require.NoError(t, err)
	for line := range strings.SplitSeq(deviceConfig, "\n") {
		line = strings.ReplaceAll(line, "=true", "=1")
		assert.Contains(t, actual, line+"\n")
	}
	assert.Contains(t, actual, "persistent_keepalive_interval=25-35\n")
	assert.Contains(t, actual, "endpoint=198.51.100.2:51820\n")
	assert.Contains(t, actual, "allowed_ip=0.0.0.0/0\n")
}

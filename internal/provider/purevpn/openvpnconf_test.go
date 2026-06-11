package purevpn

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
)

func TestProviderOpenVPNConfig_UsesBuiltInCryptoMaterial(t *testing.T) {
	t.Parallel()

	p := Provider{}
	connection := models.Connection{
		IP:       netip.MustParseAddr("1.2.3.4"),
		Port:     15021,
		Protocol: constants.UDP,
		Hostname: "us2-udp.ptoserver.com",
	}
	openvpnSettings := settings.OpenVPN{}.WithDefaults(providers.Purevpn)

	lines := p.OpenVPNConfig(connection, openvpnSettings, false)

	assert.True(t, hasLineContaining(lines, "remote-cert-tls server"))
	assert.True(t, hasLineContaining(lines, "key-direction 1"))
	assert.True(t, hasLineContaining(lines, "compress"))
	assert.True(t, hasLineContaining(lines, "route-method exe"))
	assert.True(t, hasLineContaining(lines, "route-delay 0"))
	assert.True(t, hasLineContaining(lines, "script-security 2"))
	assert.True(t, hasLineContaining(lines, "explicit-exit-notify 2"))
	assert.True(t, hasLineContaining(lines, "<ca>"))
	assert.True(t, hasLineContaining(lines, "</ca>"))
	assert.True(t, hasLineContaining(lines, "<cert>"))
	assert.True(t, hasLineContaining(lines, "</cert>"))
	assert.True(t, hasLineContaining(lines, "<key>"))
	assert.True(t, hasLineContaining(lines, "</key>"))
	assert.True(t, hasLineContaining(lines, "<tls-auth>"))
	assert.True(t, hasLineContaining(lines, "</tls-auth>"))
}

func TestOpenVPNConfig_UsesInventoryPortOnly(t *testing.T) {
	t.Parallel()

	p := Provider{}
	connection := models.Connection{
		IP:       netip.MustParseAddr("1.2.3.4"),
		Port:     1194,
		Protocol: constants.UDP,
	}

	lines := p.OpenVPNConfig(connection, testOpenVPNSettings(), true)

	assert.Equal(t, 1, countExactLine(lines, "remote 1.2.3.4 1194"))
	assert.Zero(t, countExactLine(lines, "remote 1.2.3.4 53"))
	assert.Zero(t, countExactLine(lines, "remote 1.2.3.4 80"))
}

func testOpenVPNSettings() settings.OpenVPN {
	return settings.OpenVPN{
		User:          strPtr(""),
		Auth:          strPtr(""),
		MSSFix:        uint16Ptr(0),
		Interface:     "tun0",
		ProcessUser:   "root",
		Verbosity:     intPtr(1),
		EncryptedKey:  strPtr(""),
		KeyPassphrase: strPtr(""),
		Cert:          strPtr(""),
		Key:           strPtr(""),
	}
}

func strPtr(value string) *string { return &value }
func uint16Ptr(value uint16) *uint16 { return &value }
func intPtr(value int) *int { return &value }

func countExactLine(lines []string, target string) (count int) {
	for _, line := range lines {
		if line == target {
			count++
		}
	}
	return count
}

func hasLineContaining(lines []string, needle string) bool {
	for _, line := range lines {
		if strings.Contains(line, needle) {
			return true
		}
	}
	return false
}

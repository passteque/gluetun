package ghostpath

import (
	"crypto/x509"
	"encoding/base64"
	"net/netip"
	"strings"
	"testing"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestOpenVPNSettings() settings.OpenVPN {
	return settings.OpenVPN{
		User:         new("user"),
		Password:     new("password"),
		Auth:         new(""),
		Cert:         new(""),
		Key:          new(""),
		EncryptedKey: new(""),
		MSSFix:       new(uint16(0)),
		Interface:    "tun0",
		Verbosity:    new(1),
	}
}

func Test_Provider_OpenVPNConfig(t *testing.T) {
	t.Parallel()

	provider := New(nil, nil, nil, nil)

	openVPNSettings := newTestOpenVPNSettings()

	connection := models.Connection{
		Type:     "openvpn",
		IP:       netip.MustParseAddr("1.2.3.4"),
		Port:     443,
		Protocol: constants.UDP,
	}

	lines := provider.OpenVPNConfig(connection, openVPNSettings, false)
	config := strings.Join(lines, "\n")

	assert.Contains(t, config, "remote 1.2.3.4 443")
	assert.Contains(t, config, "proto udp")
	assert.Contains(t, config, "data-ciphers-fallback aes-256-cbc")
	assert.Contains(t, config, "remote-cert-tls server")
	assert.Contains(t, config, "tls-cert-profile insecure")
	assert.Contains(t, config, "redirect-gateway")
	assert.Contains(t, config, "auth-user-pass")
	for _, tag := range []string{"ca", "cert", "key"} {
		assert.Contains(t, config, "<"+tag+">")
		assert.Contains(t, config, "</"+tag+">")
	}
}

func Test_embeddedCertificatesAndKey(t *testing.T) {
	t.Parallel()

	provider := New(nil, nil, nil, nil)
	openVPNSettings := newTestOpenVPNSettings()
	connection := models.Connection{
		IP: netip.MustParseAddr("1.2.3.4"), Port: 443, Protocol: constants.UDP,
	}
	lines := provider.OpenVPNConfig(connection, openVPNSettings, false)

	blocks := map[string]string{}
	var currentTag string
	for _, line := range lines {
		switch {
		case line == "<ca>" || line == "<cert>" || line == "<key>":
			currentTag = strings.Trim(line, "<>")
		case strings.HasPrefix(line, "</"):
			currentTag = ""
		case currentTag != "" && !strings.HasPrefix(line, "-----"):
			blocks[currentTag] += line
		}
	}

	for _, tag := range []string{"ca", "cert"} {
		der, err := base64.StdEncoding.DecodeString(blocks[tag])
		require.NoError(t, err, tag)
		_, err = x509.ParseCertificate(der)
		assert.NoError(t, err, tag)
	}

	keyDER, err := base64.StdEncoding.DecodeString(blocks["key"])
	require.NoError(t, err)
	_, err = x509.ParsePKCS8PrivateKey(keyDER)
	assert.NoError(t, err)
}

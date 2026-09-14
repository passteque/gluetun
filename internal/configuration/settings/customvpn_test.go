package settings

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/qdm12/gluetun/internal/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_CustomVPN_validate(t *testing.T) {
	t.Parallel()

	binDir := t.TempDir()
	binaryPath := filepath.Join(binDir, "custom-vpn")
	const binaryPermissions = 0o700
	err := os.WriteFile(binaryPath, []byte("#!/bin/sh\n"), binaryPermissions)
	require.NoError(t, err)

	testCases := map[string]struct {
		settings   CustomVPN
		errMessage string
	}{
		"binary_not_set": {
			errMessage: "binary path is not set",
		},
		"binary_not_found": {
			settings: CustomVPN{
				Binary: filepath.Join(binDir, "does-not-exist"),
			},
			errMessage: "finding binary",
		},
		"bad_arguments": {
			settings: CustomVPN{
				Binary: binaryPath,
				Args:   new("--config 'unterminated"),
			},
			errMessage: "splitting arguments",
		},
		"bad_interface_name": {
			settings: CustomVPN{
				Binary:    binaryPath,
				Args:      new(""),
				Interface: "tun0/../etc",
			},
			errMessage: "interface name is not valid",
		},
		"bad_ready_line_regex": {
			settings: CustomVPN{
				Binary:    binaryPath,
				Args:      new(""),
				Interface: "tun0",
				ReadyLine: new("(unclosed"),
			},
			errMessage: "compiling ready line regular expression",
		},
		"endpoint_ip_not_set": {
			settings: CustomVPN{
				Binary:    binaryPath,
				Args:      new(""),
				Interface: "tun0",
				ReadyLine: new(""),
			},
			errMessage: "endpoint IP address is not set",
		},
		"endpoint_port_not_set": {
			settings: CustomVPN{
				Binary:     binaryPath,
				Args:       new(""),
				Interface:  "tun0",
				ReadyLine:  new(""),
				EndpointIP: netip.MustParseAddr("1.2.3.4"),
			},
			errMessage: "endpoint port is not set",
		},
		"bad_endpoint_protocol": {
			settings: CustomVPN{
				Binary:           binaryPath,
				Args:             new(""),
				Interface:        "tun0",
				ReadyLine:        new(""),
				EndpointIP:       netip.MustParseAddr("1.2.3.4"),
				EndpointPort:     1194,
				EndpointProtocol: "icmp",
			},
			errMessage: "endpoint protocol is not valid",
		},
		"valid_minimal": {
			settings: CustomVPN{
				Binary:           binaryPath,
				Args:             new(""),
				Interface:        "tun0",
				ReadyLine:        new(""),
				EndpointIP:       netip.MustParseAddr("1.2.3.4"),
				EndpointPort:     1194,
				EndpointProtocol: constants.UDP,
			},
		},
		"valid_full": {
			settings: CustomVPN{
				Binary:           binaryPath,
				Args:             new("--config \"/etc/custom vpn/config.conf\" --verbose"),
				Interface:        "utun3",
				ReadyLine:        new(`^.*[Cc]onnected.*$`),
				EndpointIP:       netip.MustParseAddr("2001:db8::1"),
				EndpointPort:     443,
				EndpointProtocol: constants.TCP,
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := testCase.settings.validate()

			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_CustomVPN_setDefaults(t *testing.T) {
	t.Parallel()

	settings := CustomVPN{}

	settings.setDefaults()

	assert.Equal(t, "", *settings.Args)
	assert.Equal(t, "tun0", settings.Interface)
	assert.Equal(t, "", *settings.ReadyLine)
	assert.Equal(t, constants.UDP, settings.EndpointProtocol)
}

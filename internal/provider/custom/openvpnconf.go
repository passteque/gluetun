package custom

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/openvpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/utils"
)

func (p *Provider) OpenVPNConfig(connection models.Connection,
	settings settings.OpenVPN, ipv6Supported bool,
) (lines []string) {
	lines, _, err := p.extractor.Data(*settings.ConfFile)
	if err != nil {
		// Configuration file is already validated in settings validation in
		// internal/configuration/settings/openvpn.go in `validateOpenVPNConfigFilepath`.
		// Therefore this error is the result of a programming error.
		panic(fmt.Sprintf("failed extracting information from custom configuration file: %s", err))
	}

	lines = modifyConfig(lines, connection, settings, ipv6Supported)

	return lines
}

func modifyConfig(lines []string, connection models.Connection,
	settings settings.OpenVPN, ipv6Supported bool,
) (modified []string) {
	// Remove some lines
	for _, line := range lines {
		switch {
		case
			// Remove empty lines
			line == "",
			// Remove future to be duplicates
			line == "mute-replay-warnings",
			line == "auth-nocache",
			line == "pull-filter ignore \"auth-token\"",
			line == "auth-retry nointeract",
			line == "suppress-timestamps",
			line == "persist-tun",
			line == "persist-key",
			// Remove values always modified
			strings.HasPrefix(line, "verb "),
			strings.HasPrefix(line, "auth-user-pass "),
			strings.HasPrefix(line, "user "),
			strings.HasPrefix(line, "proto "),
			strings.HasPrefix(line, "remote "),
			strings.HasPrefix(line, "dev "),
			// Remove values eventually modified
			len(settings.Ciphers) > 0 && hasPrefixOneOf(line,
				"cipher ", "ncp-ciphers ", "data-ciphers ", "data-ciphers-fallback "),
			*settings.Auth != "" && strings.HasPrefix(line, "auth "),
			*settings.MSSFix > 0 && strings.HasPrefix(line, "mssfix "),
			!ipv6Supported && hasPrefixOneOf(line, "tun-ipv6",
				`pull-filter ignore "route-ipv6"`,
				`pull-filter ignore "ifconfig-ipv6"`):
		default:
			modified = append(modified, line)
		}
	}

	// Add values
	protocol := connection.Protocol
	if protocol == constants.TCP {
		protocol = "tcp-client"
	}
	modified = append(modified, "proto "+protocol)
	modified = append(modified, fmt.Sprintf("remote %s %d", connection.IP, connection.Port))
	modified = append(modified, "dev "+settings.Interface)
	modified = append(modified, "mute-replay-warnings")
	modified = append(modified, "auth-nocache")
	modified = append(modified, "pull-filter ignore \"auth-token\"") // prevent auth failed loop
	modified = append(modified, "auth-retry nointeract")
	modified = append(modified, "suppress-timestamps")
	modified = append(modified, "hand-window 20") // default is 60 seconds which is too long
	if *settings.User != "" {
		modified = append(modified, "auth-user-pass "+openvpn.AuthConf)
	}
	modified = append(modified, "verb "+strconv.Itoa(*settings.Verbosity))
	if len(settings.Ciphers) > 0 {
		modified = append(modified, utils.CipherLines(settings.Ciphers)...)
	}
	if *settings.Auth != "" {
		modified = append(modified, "auth "+*settings.Auth)
	}
	if *settings.MSSFix > 0 {
		modified = append(modified, "mssfix "+strconv.Itoa(int(*settings.MSSFix)))
	}
	if !ipv6Supported {
		modified = append(modified, `pull-filter ignore "route-ipv6"`)
		modified = append(modified, `pull-filter ignore "ifconfig-ipv6"`)
	}
	if settings.ProcessUser != "root" {
		modified = append(modified, "user "+settings.ProcessUser)
		modified = append(modified, "persist-tun")
		modified = append(modified, "persist-key")
	}

	modified = append(modified, "") // trailing line

	return modified
}

func hasPrefixOneOf(s string, prefixes ...string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

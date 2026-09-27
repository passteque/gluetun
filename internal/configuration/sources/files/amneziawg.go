package files

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/ini.v1"
)

func (s *Source) lazyLoadAmneziawgConf() AmneziawgConfig {
	if s.cached.amneziawgLoaded {
		return s.cached.amneziawgConf
	}

	s.cached.amneziawgLoaded = true
	var err error
	s.cached.amneziawgConf, err = ParseAmneziawgConf(filepath.Join(s.rootDirectory, "amneziawg", "awg0.conf"))
	if err != nil {
		s.warner.Warnf("skipping Amneziawg config: %s", err)
	}
	return s.cached.amneziawgConf
}

type AmneziawgConfig struct {
	Wireguard              WireguardConfig
	Jc                     *string
	Jmin                   *string
	Jmax                   *string
	S1                     *string
	S2                     *string
	S3                     *string
	S4                     *string
	H1                     *string
	H2                     *string
	H3                     *string
	H4                     *string
	I1                     *string
	I2                     *string
	I3                     *string
	I4                     *string
	I5                     *string
	HeaderProtectionKey    *string
	ContentPaddingAddition *string
	RekeyAfterTime         *string
	RekeyTimeout           *string
	RejectAfterTime        *string
	KeepaliveTimeout       *string
	MaxHandshakeAttempts   *string
	RandomTrailers         *string
	DisableCookies         *string
}

func ParseAmneziawgConf(path string) (config AmneziawgConfig, err error) {
	iniFile, err := ini.InsensitiveLoad(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return AmneziawgConfig{}, nil
		}
		return AmneziawgConfig{}, fmt.Errorf("loading ini from reader: %w", err)
	}

	config.Wireguard, err = ParseWireguardConf(path)
	if err != nil {
		return AmneziawgConfig{}, err
	}

	interfaceSection, err := iniFile.GetSection("Interface")
	if err != nil {
		// can never happen
		return AmneziawgConfig{}, fmt.Errorf("getting interface section: %w", err)
	}

	config.Jc = getINIKeyFromSection(interfaceSection, "Jc")
	config.Jmin = getINIKeyFromSection(interfaceSection, "Jmin")
	config.Jmax = getINIKeyFromSection(interfaceSection, "Jmax")
	config.S1 = getINIKeyFromSection(interfaceSection, "S1")
	config.S2 = getINIKeyFromSection(interfaceSection, "S2")
	config.S3 = getINIKeyFromSection(interfaceSection, "S3")
	config.S4 = getINIKeyFromSection(interfaceSection, "S4")
	config.H1 = getINIKeyFromSection(interfaceSection, "H1")
	config.H2 = getINIKeyFromSection(interfaceSection, "H2")
	config.H3 = getINIKeyFromSection(interfaceSection, "H3")
	config.H4 = getINIKeyFromSection(interfaceSection, "H4")
	config.I1 = getINIKeyFromSection(interfaceSection, "I1")
	config.I2 = getINIKeyFromSection(interfaceSection, "I2")
	config.I3 = getINIKeyFromSection(interfaceSection, "I3")
	config.I4 = getINIKeyFromSection(interfaceSection, "I4")
	config.I5 = getINIKeyFromSection(interfaceSection, "I5")
	config.HeaderProtectionKey = getINIKeyFromSection(interfaceSection, "HeaderProtectionKey")
	config.ContentPaddingAddition = getINIKeyFromSection(interfaceSection, "ContentPaddingAddition")
	config.RekeyAfterTime = getINIKeyFromSection(interfaceSection, "RekeyAfterTime")
	config.RekeyTimeout = getINIKeyFromSection(interfaceSection, "RekeyTimeout")
	config.RejectAfterTime = getINIKeyFromSection(interfaceSection, "RejectAfterTime")
	config.KeepaliveTimeout = getINIKeyFromSection(interfaceSection, "KeepaliveTimeout")
	config.MaxHandshakeAttempts = getINIKeyFromSection(interfaceSection, "MaxHandshakeAttempts")
	config.RandomTrailers = getINIKeyFromSection(interfaceSection, "RandomTrailers")
	config.DisableCookies = getINIKeyFromSection(interfaceSection, "DisableCookies")

	return config, nil
}

// Get returns the configuration value for an AmneziaWG settings source key.
func (c AmneziawgConfig) Get(key string) (value string, isSet bool) {
	fields := [...]struct {
		key   string
		value *string
	}{
		{"amneziawg_private_key", c.Wireguard.PrivateKey},
		{"amneziawg_preshared_key", c.Wireguard.PreSharedKey},
		{"amneziawg_addresses", c.Wireguard.Addresses},
		{"amneziawg_public_key", c.Wireguard.PublicKey},
		{"amneziawg_endpoint_ip", c.Wireguard.EndpointIP},
		{"amneziawg_endpoint_port", c.Wireguard.EndpointPort},
		{"amneziawg_allowed_ips", c.Wireguard.AllowedIPs},
		{"amneziawg_persistent_keepalive_interval", c.Wireguard.PersistentKeepalive},
		{"amneziawg_dns", c.Wireguard.DNS},
		{"amneziawg_jc", c.Jc},
		{"amneziawg_jmin", c.Jmin},
		{"amneziawg_jmax", c.Jmax},
		{"amneziawg_s1", c.S1},
		{"amneziawg_s2", c.S2},
		{"amneziawg_s3", c.S3},
		{"amneziawg_s4", c.S4},
		{"amneziawg_h1", c.H1},
		{"amneziawg_h2", c.H2},
		{"amneziawg_h3", c.H3},
		{"amneziawg_h4", c.H4},
		{"amneziawg_i1", c.I1},
		{"amneziawg_i2", c.I2},
		{"amneziawg_i3", c.I3},
		{"amneziawg_i4", c.I4},
		{"amneziawg_i5", c.I5},
		{"amneziawg_header_protection_key", c.HeaderProtectionKey},
		{"amneziawg_content_padding_addition", c.ContentPaddingAddition},
		{"amneziawg_rekey_after_time", c.RekeyAfterTime},
		{"amneziawg_rekey_timeout", c.RekeyTimeout},
		{"amneziawg_reject_after_time", c.RejectAfterTime},
		{"amneziawg_keepalive_timeout", c.KeepaliveTimeout},
		{"amneziawg_max_handshake_attempts", c.MaxHandshakeAttempts},
		{"amneziawg_random_trailers", c.RandomTrailers},
		{"amneziawg_disable_cookies", c.DisableCookies},
	}
	for _, field := range fields {
		if field.key == key {
			return strPtrToStringIsSet(field.value)
		}
	}
	return "", false
}

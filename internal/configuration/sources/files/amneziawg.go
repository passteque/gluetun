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
	PersistentKeepalive    *string
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

	peerSection, err := iniFile.GetSection("Peer")
	if err == nil {
		config.PersistentKeepalive = getINIKeyFromSection(peerSection, "PersistentKeepalive")
	} else if !regexINISectionNotExist.MatchString(err.Error()) {
		return AmneziawgConfig{}, fmt.Errorf("getting peer section: %w", err)
	}

	return config, nil
}

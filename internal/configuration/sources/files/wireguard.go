package files

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"

	"gopkg.in/ini.v1"
)

func (s *Source) lazyLoadWireguardConf() WireguardConfig {
	if s.cached.wireguardLoaded {
		return s.cached.wireguardConf
	}

	s.cached.wireguardLoaded = true
	var err error
	s.cached.wireguardConf, err = ParseWireguardConf(filepath.Join(s.rootDirectory, "wireguard", "wg0.conf"))
	if err != nil {
		s.warner.Warnf("skipping Wireguard config: %s", err)
	}
	return s.cached.wireguardConf
}

type WireguardConfig struct {
	PrivateKey          *string
	PreSharedKey        *string
	Addresses           *string
	DNS                 *string
	PublicKey           *string
	EndpointIP          *string
	EndpointPort        *string
	AllowedIPs          *string
	PersistentKeepalive *string
}

var regexINISectionNotExist = regexp.MustCompile(`^section ".+" does not exist$`)

func ParseWireguardConf(path string) (config WireguardConfig, err error) {
	iniFile, err := ini.InsensitiveLoad(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return WireguardConfig{}, nil
		}
		return WireguardConfig{}, fmt.Errorf("loading ini from reader: %w", err)
	}

	interfaceSection, err := iniFile.GetSection("Interface")
	if err == nil {
		parseWireguardInterfaceSection(interfaceSection, &config)
	} else if !regexINISectionNotExist.MatchString(err.Error()) {
		// can never happen
		return WireguardConfig{}, fmt.Errorf("getting interface section: %w", err)
	}

	peerSection, err := iniFile.GetSection("Peer")
	if err == nil {
		parseWireguardPeerSection(peerSection, &config)
	} else if !regexINISectionNotExist.MatchString(err.Error()) {
		// can never happen
		return WireguardConfig{}, fmt.Errorf("getting peer section: %w", err)
	}

	return config, nil
}

func parseWireguardInterfaceSection(interfaceSection *ini.Section, config *WireguardConfig) {
	config.PrivateKey = getINIKeyFromSection(interfaceSection, "PrivateKey")
	config.Addresses = getINIKeyFromSection(interfaceSection, "Address")
	config.DNS = getINIKeyFromSection(interfaceSection, "DNS")
}

func parseWireguardPeerSection(peerSection *ini.Section, config *WireguardConfig) {
	config.PreSharedKey = getINIKeyFromSection(peerSection, "PresharedKey")
	config.PublicKey = getINIKeyFromSection(peerSection, "PublicKey")
	config.AllowedIPs = getINIKeyFromSection(peerSection, "AllowedIPs")
	config.PersistentKeepalive = getINIKeyFromSection(peerSection, "PersistentKeepalive")
	endpoint := getINIKeyFromSection(peerSection, "Endpoint")
	if endpoint != nil {
		host, port, err := net.SplitHostPort(*endpoint)
		if err == nil {
			config.EndpointIP = &host
			config.EndpointPort = &port
		} else {
			config.EndpointIP = endpoint
		}
	}
}

var regexINIKeyNotExist = regexp.MustCompile(`key ".*" not exists$`)

func getINIKeyFromSection(section *ini.Section, key string) (value *string) {
	iniKey, err := section.GetKey(key)
	if err != nil {
		if regexINIKeyNotExist.MatchString(err.Error()) {
			return nil
		}
		// can never happen
		panic(fmt.Sprintf("getting key %q: %s", key, err))
	}
	value = new(string)
	*value = iniKey.String()
	return value
}

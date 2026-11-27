package files

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
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
	PrivateKey       *string
	PreSharedKey     *string
	Addresses        *string
	PublicKey        *string
	EndpointIP       *string
	EndpointHostname *string
	EndpointPort     *string
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
		config.PrivateKey, config.Addresses = parseWireguardInterfaceSection(interfaceSection)
	} else if !regexINISectionNotExist.MatchString(err.Error()) {
		// can never happen
		return WireguardConfig{}, fmt.Errorf("getting interface section: %w", err)
	}

	peerSection, err := iniFile.GetSection("Peer")
	if err == nil {
		config.PreSharedKey, config.PublicKey, config.EndpointIP,
			config.EndpointHostname, config.EndpointPort = parseWireguardPeerSection(peerSection)
	} else if !regexINISectionNotExist.MatchString(err.Error()) {
		// can never happen
		return WireguardConfig{}, fmt.Errorf("getting peer section: %w", err)
	}

	return config, nil
}

func parseWireguardInterfaceSection(interfaceSection *ini.Section) (
	privateKey, addresses *string,
) {
	privateKey = getINIKeyFromSection(interfaceSection, "PrivateKey")
	addresses = getINIKeyFromSection(interfaceSection, "Address")
	return privateKey, addresses
}

func parseWireguardPeerSection(peerSection *ini.Section) (
	preSharedKey, publicKey, endpointIP, endpointHostname, endpointPort *string,
) {
	preSharedKey = getINIKeyFromSection(peerSection, "PresharedKey")
	publicKey = getINIKeyFromSection(peerSection, "PublicKey")
	endpoint := getINIKeyFromSection(peerSection, "Endpoint")
	if endpoint != nil {
		host, port, err := net.SplitHostPort(*endpoint)
		if err == nil {
			endpointPort = &port
		} else {
			host = *endpoint
		}
		if _, err := netip.ParseAddr(host); err == nil {
			endpointIP = &host
		} else {
			endpointHostname = &host
		}
	}

	return preSharedKey, publicKey, endpointIP, endpointHostname, endpointPort
}

var regexINIKeyNotExist = regexp.MustCompile(`key ".*" does not exist$`)

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

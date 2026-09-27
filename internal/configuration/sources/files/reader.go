package files

import (
	"os"
	"path/filepath"
	"strings"
)

type Source struct {
	rootDirectory string
	environ       map[string]string
	warner        Warner
	cached        struct {
		wireguardLoaded bool
		wireguardConf   WireguardConfig
		amneziawgLoaded bool
		amneziawgConf   AmneziawgConfig
	}
}

func New(warner Warner) (source *Source) {
	osEnviron := os.Environ()
	environ := make(map[string]string, len(osEnviron))
	for _, pair := range osEnviron {
		const maxSplit = 2
		split := strings.SplitN(pair, "=", maxSplit)
		environ[split[0]] = split[1]
	}

	return &Source{
		rootDirectory: "/gluetun",
		environ:       environ,
		warner:        warner,
	}
}

func (s *Source) String() string { return "files" }

func (s *Source) Get(key string) (value string, isSet bool) {
	if key == "" {
		return "", false
	}
	// TODO v4 custom environment variable to set the files parent directory
	// and not to set each file to a specific path
	envKey := strings.ToUpper(key)
	envKey = strings.ReplaceAll(envKey, "-", "_")
	envKey += "_FILE"
	path := s.environ[envKey]
	if path == "" {
		path = filepath.Join(s.rootDirectory, key)
	}

	// Special file handling
	switch key {
	// TODO timezone from /etc/localtime
	case "client.crt", "client.key", "openvpn_encrypted_key":
		value, isSet, err := ReadPEMFile(path)
		if err != nil {
			s.warner.Warnf("skipping %s: parsing PEM: %s", path, err)
		}
		return value, isSet
	case "wireguard_private_key":
		return strPtrToStringIsSet(s.lazyLoadWireguardConf().PrivateKey)
	case "wireguard_preshared_key":
		return strPtrToStringIsSet(s.lazyLoadWireguardConf().PreSharedKey)
	case "wireguard_addresses":
		return strPtrToStringIsSet(s.lazyLoadWireguardConf().Addresses)
	case "wireguard_public_key":
		return strPtrToStringIsSet(s.lazyLoadWireguardConf().PublicKey)
	case "wireguard_endpoint_ip":
		return strPtrToStringIsSet(s.lazyLoadWireguardConf().EndpointIP)
	case "wireguard_endpoint_port":
		return strPtrToStringIsSet(s.lazyLoadWireguardConf().EndpointPort)
	}

	if strings.HasPrefix(key, "amneziawg_") {
		config := s.lazyLoadAmneziawgConf()
		value, isSet = config.Get(key)
		if isSet {
			return value, true
		}
	}

	value, isSet, err := ReadFromFile(path)
	if err != nil {
		s.warner.Warnf("skipping %s: reading file: %s", path, err)
	}
	return value, isSet
}

func (s *Source) KeyTransform(key string) string {
	switch key {
	// TODO v4 remove these irregular cases
	case "OPENVPN_KEY":
		return "client.key"
	case "OPENVPN_CERT":
		return "client.crt"
	case "OPENVPN_ENCRYPTED_KEY":
		return "openvpn_encrypted_key"
	default:
		key = strings.ToLower(key) // HTTPROXY_USER -> httpproxy_user
		return key
	}
}

func strPtrToStringIsSet(ptr *string) (s string, isSet bool) {
	if ptr == nil {
		return "", false
	}
	return *ptr, true
}

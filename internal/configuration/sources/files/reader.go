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

	value, isSet, matched := s.getAmneziawgKey(key)
	if matched {
		return value, isSet
	}

	value, isSet, err := ReadFromFile(path)
	if err != nil {
		s.warner.Warnf("skipping %s: reading file: %s", path, err)
	}
	return value, isSet
}

func (s *Source) getAmneziawgKey(key string) (value string, isSet, matched bool) {
	switch key {
	case "amnezia_private_key":
		value, isSet = strPtrToStringIsSet(s.lazyLoadAmneziawgConf().Wireguard.PrivateKey)
	case "amnezia_preshared_key":
		value, isSet = strPtrToStringIsSet(s.lazyLoadAmneziawgConf().Wireguard.PreSharedKey)
	case "amnezia_addresses":
		value, isSet = strPtrToStringIsSet(s.lazyLoadAmneziawgConf().Wireguard.Addresses)
	case "amnezia_public_key":
		value, isSet = strPtrToStringIsSet(s.lazyLoadAmneziawgConf().Wireguard.PublicKey)
	case "amnezia_endpoint_ip":
		value, isSet = strPtrToStringIsSet(s.lazyLoadAmneziawgConf().Wireguard.EndpointIP)
	case "amnezia_endpoint_port":
		value, isSet = strPtrToStringIsSet(s.lazyLoadAmneziawgConf().Wireguard.EndpointPort)
	case "amnezia_jc":
		value, isSet = strPtrToStringIsSet(s.lazyLoadAmneziawgConf().Jc)
	case "amnezia_jmin":
		value, isSet = strPtrToStringIsSet(s.lazyLoadAmneziawgConf().Jmin)
	case "amnezia_jmax":
		value, isSet = strPtrToStringIsSet(s.lazyLoadAmneziawgConf().Jmax)
	case "amnezia_s1":
		value, isSet = strPtrToStringIsSet(s.lazyLoadAmneziawgConf().S1)
	case "amnezia_s2":
		value, isSet = strPtrToStringIsSet(s.lazyLoadAmneziawgConf().S2)
	case "amnezia_s3":
		value, isSet = strPtrToStringIsSet(s.lazyLoadAmneziawgConf().S3)
	case "amnezia_s4":
		value, isSet = strPtrToStringIsSet(s.lazyLoadAmneziawgConf().S4)
	case "amnezia_h1":
		value, isSet = strPtrToStringIsSet(s.lazyLoadAmneziawgConf().H1)
	case "amnezia_h2":
		value, isSet = strPtrToStringIsSet(s.lazyLoadAmneziawgConf().H2)
	case "amnezia_h3":
		value, isSet = strPtrToStringIsSet(s.lazyLoadAmneziawgConf().H3)
	case "amnezia_h4":
		value, isSet = strPtrToStringIsSet(s.lazyLoadAmneziawgConf().H4)
	case "amnezia_i1":
		value, isSet = strPtrToStringIsSet(s.lazyLoadAmneziawgConf().I1)
	case "amnezia_i2":
		value, isSet = strPtrToStringIsSet(s.lazyLoadAmneziawgConf().I2)
	case "amnezia_i3":
		value, isSet = strPtrToStringIsSet(s.lazyLoadAmneziawgConf().I3)
	case "amnezia_i4":
		value, isSet = strPtrToStringIsSet(s.lazyLoadAmneziawgConf().I4)
	case "amnezia_i5":
		value, isSet = strPtrToStringIsSet(s.lazyLoadAmneziawgConf().I5)
	default:
		return "", false, false
	}
	return value, isSet, true
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

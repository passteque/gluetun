package internal

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const credentialsFilename = "credentials"

const (
	vpnTypeOpenVPN   = "openvpn"
	vpnTypeWireGuard = "wireguard"
)

type providerCredentials struct {
	OpenVPN   *openvpnCredentials
	WireGuard *wireguardCredentials
}

type openvpnCredentials struct {
	Username string
	Password string
	Key      string
	Cert     string
}

type wireguardCredentials struct {
	PrivateKey   string
	Address      string
	PresharedKey string
}

func loadCredentials(data []byte) (map[string]providerCredentials, error) {
	credentials := make(map[string]providerCredentials)
	err := gob.NewDecoder(bytes.NewReader(data)).Decode(&credentials)
	if err != nil {
		return nil, fmt.Errorf("decoding credentials: %w", err)
	}
	return credentials, nil
}

func marshalCredentials(credentials map[string]providerCredentials) ([]byte, error) {
	buffer := bytes.NewBuffer(nil)
	err := gob.NewEncoder(buffer).Encode(credentials)
	if err != nil {
		return nil, fmt.Errorf("encoding credentials: %w", err)
	}
	return buffer.Bytes(), nil
}

func validateCredentials(providerNameToCredentials map[string]providerCredentials) error {
	for provider, credentials := range providerNameToCredentials {
		if credentials.OpenVPN == nil && credentials.WireGuard == nil {
			return fmt.Errorf("provider %q has no openvpn or wireguard credentials", provider)
		}
		if credentials.OpenVPN != nil {
			err := validateOpenvpnCredentials(provider, credentials.OpenVPN)
			if err != nil {
				return err
			}
		}
		if credentials.WireGuard != nil {
			err := validateWireguardCredentials(provider, credentials.WireGuard)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func validateOpenvpnCredentials(provider string, creds *openvpnCredentials) error {
	switch {
	case creds.Username == "" && creds.Password != "":
		return fmt.Errorf("provider %q openvpn credentials are missing the username", provider)
	case creds.Password == "" && creds.Username != "":
		return fmt.Errorf("provider %q openvpn credentials are missing the password", provider)
	case creds.Username == "" && creds.Password == "" && creds.Key == "" && creds.Cert == "":
		return fmt.Errorf("provider %q openvpn credentials are missing the username and password", provider)
	}
	return nil
}

func validateWireguardCredentials(provider string, creds *wireguardCredentials) error {
	if creds.PrivateKey == "" {
		return fmt.Errorf("provider %q wireguard credentials are missing the private key", provider)
	} else if _, err := wgtypes.ParseKey(creds.PrivateKey); err != nil {
		return fmt.Errorf("provider %q wireguard credentials have an invalid private key: %w", provider, err)
	}

	if creds.Address != "" {
		_, err := netip.ParsePrefix(creds.Address)
		if err != nil {
			return fmt.Errorf("provider %q wireguard credentials have an invalid address %q: %w", provider, creds.Address, err)
		}
	}

	if creds.PresharedKey != "" {
		if _, err := wgtypes.ParseKey(creds.PresharedKey); err != nil {
			return fmt.Errorf("provider %q wireguard credentials have an invalid preshared key: %w", provider, err)
		}
	}
	return nil
}

func lookupCredentials(credentials map[string]providerCredentials, provider, vpnType string) ([]string, error) {
	providerCreds, exists := credentials[provider]
	if !exists {
		existing := slices.Collect(maps.Keys(credentials))
		return nil, fmt.Errorf("no credentials found for provider %q, available providers are: %s",
			provider, strings.Join(existing, ", "))
	}

	switch vpnType {
	case vpnTypeWireGuard:
		if providerCreds.WireGuard == nil {
			return nil, fmt.Errorf("no wireguard credentials found for provider %q", provider)
		}
		return buildWireGuardEnv(providerCreds.WireGuard), nil
	case vpnTypeOpenVPN:
		if providerCreds.OpenVPN == nil {
			return nil, fmt.Errorf("no openvpn credentials found for provider %q", provider)
		}
		return buildOpenvpnEnv(providerCreds.OpenVPN), nil
	default:
		return nil, fmt.Errorf("unknown vpn type %q, must be wireguard or openvpn", vpnType)
	}
}

func buildWireGuardEnv(creds *wireguardCredentials) []string {
	envVars := []string{
		"WIREGUARD_PRIVATE_KEY=" + creds.PrivateKey,
	}
	if creds.Address != "" {
		envVars = append(envVars, "WIREGUARD_ADDRESSES="+creds.Address)
	}
	if creds.PresharedKey != "" {
		envVars = append(envVars, "WIREGUARD_PRESHARED_KEY="+creds.PresharedKey)
	}
	return envVars
}

func buildOpenvpnEnv(creds *openvpnCredentials) []string {
	return []string{
		"OPENVPN_USER=" + creds.Username,
		"OPENVPN_PASSWORD=" + creds.Password,
		"OPENVPN_KEY=" + creds.Key,
		"OPENVPN_CERT=" + creds.Cert,
	}
}

func addCredential(credentials map[string]providerCredentials, provider, vpnType string,
	openvpnCredentials *openvpnCredentials, wireguardCredentials *wireguardCredentials,
) error {
	providerCredentials := credentials[provider]

	switch vpnType {
	case vpnTypeOpenVPN:
		providerCredentials.OpenVPN = openvpnCredentials
	case vpnTypeWireGuard:
		providerCredentials.WireGuard = wireguardCredentials
	default:
		return fmt.Errorf("unknown vpn type %q, must be wireguard or openvpn", vpnType)
	}

	credentials[provider] = providerCredentials
	return nil
}

func deleteCredential(credentials map[string]providerCredentials, provider, vpnType string) error {
	providerCredentials, exists := credentials[provider]
	if !exists {
		return fmt.Errorf("provider %q does not exist", provider)
	}

	switch vpnType {
	case vpnTypeOpenVPN:
		if providerCredentials.OpenVPN == nil {
			return fmt.Errorf("provider %q has no openvpn credentials", provider)
		}
		providerCredentials.OpenVPN = nil
	case vpnTypeWireGuard:
		if providerCredentials.WireGuard == nil {
			return fmt.Errorf("provider %q has no wireguard credentials", provider)
		}
		providerCredentials.WireGuard = nil
	default:
		return fmt.Errorf("unknown vpn type %q, must be wireguard or openvpn", vpnType)
	}

	if providerCredentials.OpenVPN == nil && providerCredentials.WireGuard == nil {
		delete(credentials, provider)
		return nil
	}

	credentials[provider] = providerCredentials
	return nil
}

func formatCredentialForDump(provider, vpnType string,
	providerCredentials providerCredentials,
) (output string, err error) {
	var builder strings.Builder

	builder.WriteString("provider: ")
	builder.WriteString(provider)
	builder.WriteString("\n")
	builder.WriteString("vpn_type: ")
	builder.WriteString(vpnType)
	builder.WriteString("\n")

	switch vpnType {
	case vpnTypeOpenVPN:
		if providerCredentials.OpenVPN == nil {
			return "", fmt.Errorf("no openvpn credentials found for provider %q", provider)
		}
		builder.WriteString("username: ")
		builder.WriteString(providerCredentials.OpenVPN.Username)
		builder.WriteString("\n")
		builder.WriteString("password: ")
		builder.WriteString(providerCredentials.OpenVPN.Password)
		builder.WriteString("\nkey: ")
		builder.WriteString(providerCredentials.OpenVPN.Key)
		builder.WriteString("\ncert: ")
		builder.WriteString(providerCredentials.OpenVPN.Cert)
		builder.WriteString("\n")
	case vpnTypeWireGuard:
		if providerCredentials.WireGuard == nil {
			return "", fmt.Errorf("no wireguard credentials found for provider %q", provider)
		}
		builder.WriteString("private_key: ")
		builder.WriteString(providerCredentials.WireGuard.PrivateKey)
		builder.WriteString("\n")
		builder.WriteString("address: ")
		builder.WriteString(providerCredentials.WireGuard.Address)
		builder.WriteString("\n")
		builder.WriteString("preshared_key: ")
		builder.WriteString(providerCredentials.WireGuard.PresharedKey)
	default:
		return "", fmt.Errorf("unknown vpn type %q, must be wireguard or openvpn", vpnType)
	}

	return builder.String(), nil
}

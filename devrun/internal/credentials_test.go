package internal

import (
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func Test_addCredential(t *testing.T) {
	t.Parallel()

	wireguardPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	testCases := map[string]struct {
		initialCredentials map[string]providerCredentials
		provider           string
		vpnType            string
		openvpnCredentials *openvpnCredentials
		wireguardCreds     *wireguardCredentials
		expectedLength     int
		expectedOpenVPN    bool
		expectedWireGuard  bool
	}{
		"adds_openvpn_credentials": {
			initialCredentials: map[string]providerCredentials{},
			provider:           "protonvpn",
			vpnType:            "openvpn",
			openvpnCredentials: &openvpnCredentials{Username: "user", Password: "pass"},
			expectedLength:     1,
			expectedOpenVPN:    true,
		},
		"adds_wireguard_credentials": {
			initialCredentials: map[string]providerCredentials{},
			provider:           "mullvad",
			vpnType:            "wireguard",
			wireguardCreds: &wireguardCredentials{
				PrivateKey: wireguardPrivateKey.String(),
				Address:    "10.0.0.2/32",
			},
			expectedLength:    1,
			expectedWireGuard: true,
		},
		"preserves_other_protocol": {
			initialCredentials: map[string]providerCredentials{
				"protonvpn": {
					WireGuard: &wireguardCredentials{PrivateKey: wireguardPrivateKey.String()},
				},
			},
			provider:           "protonvpn",
			vpnType:            "openvpn",
			openvpnCredentials: &openvpnCredentials{Username: "user", Password: "pass"},
			expectedLength:     1,
			expectedOpenVPN:    true,
			expectedWireGuard:  true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			credentials := cloneCredentials(testCase.initialCredentials)

			err := addCredential(credentials, testCase.provider, testCase.vpnType,
				testCase.openvpnCredentials, testCase.wireguardCreds)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			providerCredentials := credentials[testCase.provider]
			if len(credentials) != testCase.expectedLength {
				t.Fatalf("expected %d providers, got %d", testCase.expectedLength, len(credentials))
			}
			if (providerCredentials.OpenVPN != nil) != testCase.expectedOpenVPN {
				t.Fatalf("expected openvpn presence %t, got %t", testCase.expectedOpenVPN, providerCredentials.OpenVPN != nil)
			}
			if (providerCredentials.WireGuard != nil) != testCase.expectedWireGuard {
				t.Fatalf("expected wireguard presence %t, got %t", testCase.expectedWireGuard, providerCredentials.WireGuard != nil)
			}
		})
	}
}

func Test_deleteCredential(t *testing.T) {
	t.Parallel()

	wireguardPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	testCases := map[string]struct {
		initialCredentials map[string]providerCredentials
		provider           string
		vpnType            string
		expectedLength     int
		expectedOpenVPN    bool
		expectedWireGuard  bool
	}{
		"deletes_openvpn_only": {
			initialCredentials: map[string]providerCredentials{
				"protonvpn": {
					OpenVPN:   &openvpnCredentials{Username: "user", Password: "pass"},
					WireGuard: &wireguardCredentials{PrivateKey: wireguardPrivateKey.String()},
				},
			},
			provider:          "protonvpn",
			vpnType:           "openvpn",
			expectedLength:    1,
			expectedWireGuard: true,
		},
		"deletes_last_protocol_and_provider": {
			initialCredentials: map[string]providerCredentials{
				"protonvpn": {
					OpenVPN: &openvpnCredentials{Username: "user", Password: "pass"},
				},
			},
			provider:       "protonvpn",
			vpnType:        "openvpn",
			expectedLength: 0,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			credentials := cloneCredentials(testCase.initialCredentials)

			err := deleteCredential(credentials, testCase.provider, testCase.vpnType)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(credentials) != testCase.expectedLength {
				t.Fatalf("expected %d providers, got %d", testCase.expectedLength, len(credentials))
			}

			providerCredentials, exists := credentials[testCase.provider]
			if !exists {
				return
			}

			if (providerCredentials.OpenVPN != nil) != testCase.expectedOpenVPN {
				t.Fatalf("expected openvpn presence %t, got %t", testCase.expectedOpenVPN, providerCredentials.OpenVPN != nil)
			}
			if (providerCredentials.WireGuard != nil) != testCase.expectedWireGuard {
				t.Fatalf("expected wireguard presence %t, got %t", testCase.expectedWireGuard, providerCredentials.WireGuard != nil)
			}
		})
	}
}

func Test_validateCredentials(t *testing.T) {
	t.Parallel()

	wireguardPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	testCases := map[string]struct {
		credentials map[string]providerCredentials
		wantError   bool
	}{
		"both_protocols_valid": {
			credentials: map[string]providerCredentials{
				"protonvpn": {
					OpenVPN:   &openvpnCredentials{Username: "user", Password: "pass"},
					WireGuard: &wireguardCredentials{PrivateKey: wireguardPrivateKey.String()},
				},
			},
		},
		"invalid_wireguard_when_both_present": {
			credentials: map[string]providerCredentials{
				"protonvpn": {
					OpenVPN:   &openvpnCredentials{Username: "user", Password: "pass"},
					WireGuard: &wireguardCredentials{PrivateKey: "invalid"},
				},
			},
			wantError: true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := validateCredentials(testCase.credentials)
			if testCase.wantError && err == nil {
				t.Fatal("expected an error but got nil")
			}
			if !testCase.wantError && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}

func Test_marshalLoadCredentials(t *testing.T) {
	t.Parallel()

	wireguardPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	credentials := map[string]providerCredentials{
		"mullvad": {
			WireGuard: &wireguardCredentials{
				PrivateKey: wireguardPrivateKey.String(),
				Address:    "10.0.0.2/32",
			},
		},
		"protonvpn": {
			OpenVPN: &openvpnCredentials{
				Username: "user",
				Password: "pass",
			},
		},
	}

	encoded, err := marshalCredentials(credentials)
	if err != nil {
		t.Fatalf("unexpected marshal error: %v", err)
	}

	decoded, err := loadCredentials(encoded)
	if err != nil {
		t.Fatalf("unexpected load error: %v", err)
	}

	if len(decoded) != len(credentials) {
		t.Fatalf("expected %d providers, got %d", len(credentials), len(decoded))
	}

	if decoded["mullvad"].WireGuard == nil {
		t.Fatal("expected mullvad wireguard credentials to be present")
	}
	if decoded["protonvpn"].OpenVPN == nil {
		t.Fatal("expected protonvpn openvpn credentials to be present")
	}
	if decoded["protonvpn"].OpenVPN.Password != "pass" {
		t.Fatalf("expected protonvpn password %q, got %q", "pass", decoded["protonvpn"].OpenVPN.Password)
	}
}

func Test_formatCredentialForDump(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		provider            string
		vpnType             string
		providerCredentials providerCredentials
		expectedOutput      string
		wantError           bool
	}{
		"openvpn": {
			provider: "protonvpn",
			vpnType:  vpnTypeOpenVPN,
			providerCredentials: providerCredentials{
				OpenVPN: &openvpnCredentials{
					Username: "user",
					Password: "pass",
					Key:      "key",
					Cert:     "cert",
				},
			},
			expectedOutput: "provider: protonvpn\n" +
				"vpn_type: openvpn\n" +
				"username: user\n" +
				"password: pass\n" +
				"key: key\n" +
				"cert: cert\n",
		},
		"wireguard": {
			provider: "mullvad",
			vpnType:  vpnTypeWireGuard,
			providerCredentials: providerCredentials{
				WireGuard: &wireguardCredentials{
					PrivateKey:   "private",
					Address:      "10.0.0.2/32",
					PresharedKey: "preshared",
				},
			},
			expectedOutput: "provider: mullvad\n" +
				"vpn_type: wireguard\n" +
				"private_key: private\n" +
				"address: 10.0.0.2/32\n" +
				"preshared_key: preshared",
		},
		"missing_protocol": {
			provider:  "protonvpn",
			vpnType:   vpnTypeOpenVPN,
			wantError: true,
		},
		"unknown_protocol": {
			provider:  "protonvpn",
			vpnType:   "other",
			wantError: true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			output, err := formatCredentialForDump(
				testCase.provider,
				testCase.vpnType,
				testCase.providerCredentials,
			)

			if testCase.wantError {
				if err == nil {
					t.Fatal("expected an error but got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			if output != testCase.expectedOutput {
				t.Fatalf("expected output %q, got %q", testCase.expectedOutput, output)
			}
		})
	}
}

func cloneCredentials(credentials map[string]providerCredentials) map[string]providerCredentials {
	clone := make(map[string]providerCredentials, len(credentials))
	for provider, providerCredentials := range credentials {
		copied := providerCredentials
		if providerCredentials.OpenVPN != nil {
			openvpnCredentials := *providerCredentials.OpenVPN
			copied.OpenVPN = &openvpnCredentials
		}
		if providerCredentials.WireGuard != nil {
			wireguardCredentials := *providerCredentials.WireGuard
			copied.WireGuard = &wireguardCredentials
		}
		clone[provider] = copied
	}
	return clone
}

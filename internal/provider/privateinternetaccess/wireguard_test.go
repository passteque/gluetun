package privateinternetaccess

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/wireguard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type roundTripFunc func(r *http.Request) (*http.Response, error)

func (s roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return s(r)
}

type mockFirewall struct {
	acceptCalls []struct {
		protocol string
		intf     string
		ip       netip.Addr
		port     uint16
		remove   bool
	}
	acceptErr error
}

func (m *mockFirewall) AcceptOutput(_ context.Context, protocol, intf string, ip netip.Addr, port uint16, remove bool) error {
	if m == nil {
		return nil
	}
	m.acceptCalls = append(m.acceptCalls, struct {
		protocol string
		intf     string
		ip       netip.Addr
		port     uint16
		remove   bool
	}{protocol: protocol, intf: intf, ip: ip, port: port, remove: remove})
	return m.acceptErr
}

func Test_Provider_WireguardConfig(t *testing.T) {
	t.Parallel()

	testServerKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	validServerPubKey := testServerKey.PublicKey().String()

	testCases := map[string]struct {
		connection        models.Connection
		vpnSettings       settings.VPN
		wireguardSettings wireguard.Settings
		httpClient        *http.Client
		firewall          *mockFirewall
		addWireguardKey   func(ctx context.Context, serverName string, serverIP netip.Addr,
			token, publicKey string) (result addKeyResult, err error)
		expectedWgSettings wireguard.Settings
		expectedConnection models.Connection
		expectedErr        error
	}{
		"success": {
			connection: models.Connection{
				ServerName: "bahamas413",
				IP:         netip.AddrFrom4([4]byte{95, 181, 238, 98}),
			},
			vpnSettings: settings.VPN{
				OpenVPN: settings.OpenVPN{
					User:     ptrTo("user123"),
					Password: ptrTo("pass456"),
				},
			},
			httpClient: &http.Client{
				Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					assert.Equal(t, "https://www.privateinternetaccess.com/api/client/v2/token", r.URL.String())
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewBufferString(`{"token":"test-token"}`)),
					}, nil
				}),
			},
			firewall: &mockFirewall{},
			addWireguardKey: func(_ context.Context, serverName string, serverIP netip.Addr,
				token, publicKey string,
			) (result addKeyResult, err error) {
				assert.Equal(t, "bahamas413", serverName)
				assert.Equal(t, netip.AddrFrom4([4]byte{95, 181, 238, 98}), serverIP)
				assert.Equal(t, "test-token", token)
				assert.NotEmpty(t, publicKey)
				return addKeyResult{
					Status:     "OK",
					ServerKey:  validServerPubKey,
					ServerPort: 1337,
					ServerIP:   "95.181.238.98",
					PeerIP:     "10.0.0.2",
					PeerPubkey: publicKey,
					DNSServers: []string{"10.0.0.242"},
				}, nil
			},
			expectedWgSettings: wireguard.Settings{
				PublicKey: validServerPubKey,
				Addresses: []netip.Prefix{
					netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, 0, 2}), 32),
				},
				Endpoint: netip.AddrPortFrom(
					netip.AddrFrom4([4]byte{95, 181, 238, 98}), 1337),
				PersistentKeepaliveInterval: 25 * time.Second,
			},
			expectedConnection: models.Connection{
				ServerName: "bahamas413",
				IP:         netip.AddrFrom4([4]byte{95, 181, 238, 98}),
				Port:       1337,
				PubKey:     validServerPubKey,
			},
		},
		"empty server name": {
			connection: models.Connection{
				IP: netip.AddrFrom4([4]byte{95, 181, 238, 98}),
			},
			expectedErr: errors.New("server name is empty"),
		},
		"invalid connection IP": {
			connection: models.Connection{
				ServerName: "bahamas413",
			},
			expectedErr: errors.New("connection IP is not valid"),
		},
		"empty username": {
			connection: models.Connection{
				ServerName: "bahamas413",
				IP:         netip.AddrFrom4([4]byte{95, 181, 238, 98}),
			},
			vpnSettings: settings.VPN{
				OpenVPN: settings.OpenVPN{
					User:     ptrTo(""),
					Password: ptrTo("pass456"),
				},
			},
			expectedErr: errors.New("user is empty"),
		},
		"empty password": {
			connection: models.Connection{
				ServerName: "bahamas413",
				IP:         netip.AddrFrom4([4]byte{95, 181, 238, 98}),
			},
			vpnSettings: settings.VPN{
				OpenVPN: settings.OpenVPN{
					User:     ptrTo("user123"),
					Password: ptrTo(""),
				},
			},
			expectedErr: errors.New("password is empty"),
		},
		"token fetch failure": {
			connection: models.Connection{
				ServerName: "bahamas413",
				IP:         netip.AddrFrom4([4]byte{95, 181, 238, 98}),
			},
			vpnSettings: settings.VPN{
				OpenVPN: settings.OpenVPN{
					User:     ptrTo("user123"),
					Password: ptrTo("pass456"),
				},
			},
			httpClient: &http.Client{
				Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
					return nil, errors.New("network error")
				}),
			},
			expectedErr: errors.New("fetching auth token:"),
		},
		"add wireguard key failure": {
			connection: models.Connection{
				ServerName: "bahamas413",
				IP:         netip.AddrFrom4([4]byte{95, 181, 238, 98}),
			},
			vpnSettings: settings.VPN{
				OpenVPN: settings.OpenVPN{
					User:     ptrTo("user123"),
					Password: ptrTo("pass456"),
				},
			},
			httpClient: &http.Client{
				Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewBufferString(`{"token":"test-token"}`)),
					}, nil
				}),
			},
			addWireguardKey: func(_ context.Context, _ string, _ netip.Addr,
				_, _ string,
			) (result addKeyResult, err error) {
				return result, errors.New("addKey failed")
			},
			expectedErr: errors.New("adding wireguard key: addKey failed"),
		},
		"invalid server key returned": {
			connection: models.Connection{
				ServerName: "bahamas413",
				IP:         netip.AddrFrom4([4]byte{95, 181, 238, 98}),
			},
			vpnSettings: settings.VPN{
				OpenVPN: settings.OpenVPN{
					User:     ptrTo("user123"),
					Password: ptrTo("pass456"),
				},
			},
			httpClient: &http.Client{
				Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewBufferString(`{"token":"test-token"}`)),
					}, nil
				}),
			},
			addWireguardKey: func(_ context.Context, _ string, _ netip.Addr,
				_, _ string,
			) (result addKeyResult, err error) {
				return addKeyResult{
					Status:     "OK",
					ServerKey:  "invalid-key",
					ServerPort: 1337,
					PeerIP:     "10.0.0.2",
				}, nil
			},
			expectedErr: errors.New("parsing server public key:"),
		},
		"invalid peer ip returned": {
			connection: models.Connection{
				ServerName: "bahamas413",
				IP:         netip.AddrFrom4([4]byte{95, 181, 238, 98}),
			},
			vpnSettings: settings.VPN{
				OpenVPN: settings.OpenVPN{
					User:     ptrTo("user123"),
					Password: ptrTo("pass456"),
				},
			},
			httpClient: &http.Client{
				Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewBufferString(`{"token":"test-token"}`)),
					}, nil
				}),
			},
			addWireguardKey: func(_ context.Context, _ string, _ netip.Addr,
				_, _ string,
			) (result addKeyResult, err error) {
				return addKeyResult{
					Status:     "OK",
					ServerKey:  validServerPubKey,
					ServerPort: 1337,
					PeerIP:     "not-an-ip",
				}, nil
			},
			expectedErr: errors.New("parsing peer IP:"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			p := &Provider{
				client:          testCase.httpClient,
				addWireguardKey: testCase.addWireguardKey,
			}

			connection := testCase.connection
			wgSettings, err := p.WireguardConfig(t.Context(), &connection,
				testCase.vpnSettings, testCase.wireguardSettings, testCase.firewall)

			if testCase.expectedErr != nil {
				require.Error(t, err)
				assert.ErrorContains(t, err, testCase.expectedErr.Error())
				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, wgSettings.PrivateKey)
			assert.Equal(t, testCase.expectedWgSettings.PublicKey, wgSettings.PublicKey)
			assert.Equal(t, testCase.expectedWgSettings.Addresses, wgSettings.Addresses)
			assert.Equal(t, testCase.expectedWgSettings.Endpoint, wgSettings.Endpoint)
			assert.Equal(t, testCase.expectedWgSettings.PersistentKeepaliveInterval, wgSettings.PersistentKeepaliveInterval)
			assert.Equal(t, testCase.expectedConnection, connection)
		})
	}
}

func Test_addWireguardKeyWithClient(t *testing.T) {
	t.Parallel()

	testServerIP := netip.AddrFrom4([4]byte{95, 181, 238, 98})

	testCases := map[string]struct {
		client         *http.Client
		expectedResult addKeyResult
		expectedErr    error
	}{
		"success": {
			client: &http.Client{
				Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					assert.Equal(t, "https://95.181.238.98:1337/addKey?pt=test-token&pubkey=test-pubkey", r.URL.String())
					return &http.Response{
						StatusCode: http.StatusOK,
						Body: io.NopCloser(bytes.NewBufferString(`{
							"status": "OK",
							"server_key": "srvkey123",
							"server_port": 1337,
							"server_ip": "95.181.238.98",
							"server_vip": "10.0.0.1",
							"peer_ip": "10.0.0.2",
							"peer_pubkey": "test-pubkey",
							"dns_servers": ["10.0.0.242"]
						}`)),
					}, nil
				}),
			},
			expectedResult: addKeyResult{
				Status:     "OK",
				ServerKey:  "srvkey123",
				ServerPort: 1337,
				ServerIP:   "95.181.238.98",
				ServerVIP:  "10.0.0.1",
				PeerIP:     "10.0.0.2",
				PeerPubkey: "test-pubkey",
				DNSServers: []string{"10.0.0.242"},
			},
		},
		"http status non-200": {
			client: &http.Client{
				Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusUnauthorized,
						Status:     "401 Unauthorized",
						Request: &http.Request{
							URL: &url.URL{
								Scheme: "https",
								Host:   "test.com",
							},
						},
						Body: io.NopCloser(bytes.NewBufferString(`{"status":"ERROR","message":"invalid token"}`)),
					}, nil
				}),
			},
			expectedErr: errors.New("HTTP status code not OK: https://test.com: 401 401 Unauthorized: response received: status \"ERROR\" and message \"invalid token\""),
		},
		"server non-ok status": {
			client: &http.Client{
				Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewBufferString(`{"status":"ERROR","message":"bad key"}`)),
					}, nil
				}),
			},
			expectedErr: errors.New("server returned non-OK status \"ERROR\": bad key"),
		},
		"invalid json body": {
			client: &http.Client{
				Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewBufferString(`{invalid`)),
					}, nil
				}),
			},
			expectedErr: errors.New("decoding response: invalid character 'i' looking for beginning of object key string"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			result, err := addWireguardKeyWithClient(t.Context(), testCase.client,
				testServerIP, "test-token", "test-pubkey")

			if testCase.expectedErr != nil {
				require.Error(t, err)
				assert.ErrorContains(t, err, testCase.expectedErr.Error())
				return
			}

			require.NoError(t, err)
			assert.Equal(t, testCase.expectedResult, result)
		})
	}
}

func Test_fetchAuthV3TokenWithClient(t *testing.T) {
	t.Parallel()

	testServerIP := netip.AddrFrom4([4]byte{95, 181, 238, 98})

	testCases := map[string]struct {
		client        *http.Client
		expectedToken string
		expectedErr   error
	}{
		"success": {
			client: &http.Client{
				Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					assert.Equal(t, "https://95.181.238.98:443/authv3/generateToken", r.URL.String())
					user, pass, ok := r.BasicAuth()
					assert.True(t, ok)
					assert.Equal(t, "testuser", user)
					assert.Equal(t, "testpass", pass)
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewBufferString(`{"token":"authv3-token"}`)),
					}, nil
				}),
			},
			expectedToken: "authv3-token",
		},
		"empty token with error message": {
			client: &http.Client{
				Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewBufferString(`{"token":"","message":"invalid credentials"}`)),
					}, nil
				}),
			},
			expectedErr: errors.New("error from server: invalid credentials"),
		},
		"non-200 status": {
			client: &http.Client{
				Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusUnauthorized,
						Status:     "401 Unauthorized",
						Request: &http.Request{
							URL: &url.URL{
								Scheme: "https",
								Host:   "test.com",
							},
						},
						Body: io.NopCloser(bytes.NewBufferString(`{"status":"ERROR","message":"unauthorized"}`)),
					}, nil
				}),
			},
			expectedErr: errors.New("HTTP status code not OK: https://test.com: 401 401 Unauthorized: response received: status \"ERROR\" and message \"unauthorized\""),
		},
		"invalid json body": {
			client: &http.Client{
				Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewBufferString(`{invalid`)),
					}, nil
				}),
			},
			expectedErr: errors.New("decoding response: invalid character 'i' looking for beginning of object key string"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			token, err := fetchAuthV3TokenWithClient(t.Context(), testCase.client,
				testServerIP, "testuser", "testpass")

			if testCase.expectedErr != nil {
				require.Error(t, err)
				assert.ErrorContains(t, err, testCase.expectedErr.Error())
				return
			}

			require.NoError(t, err)
			assert.Equal(t, testCase.expectedToken, token)
		})
	}
}

func Test_Provider_getToken(t *testing.T) {
	t.Parallel()

	testServerIP := netip.AddrFrom4([4]byte{95, 181, 238, 98})

	testCases := map[string]struct {
		provider      Provider
		expectedToken string
		expectedErr   error
	}{
		"authv3 success": {
			provider: Provider{
				fetchAuthToken: func(_ context.Context, _ string, _ netip.Addr, _, _ string) (string, error) {
					return "authv3-token", nil
				},
			},
			expectedToken: "authv3-token",
		},
		"authv3 fallback to v2 success": {
			provider: Provider{
				fetchAuthToken: func(_ context.Context, _ string, _ netip.Addr, _, _ string) (string, error) {
					return "", errors.New("authv3 failed")
				},
				client: &http.Client{
					Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBufferString(`{"token":"v2-token"}`)),
						}, nil
					}),
				},
			},
			expectedToken: "v2-token",
		},
		"both fail": {
			provider: Provider{
				fetchAuthToken: func(_ context.Context, _ string, _ netip.Addr, _, _ string) (string, error) {
					return "", errors.New("authv3 timeout")
				},
				client: &http.Client{
					Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
						return nil, errors.New("v2 network error")
					}),
				},
			},
			expectedErr: errors.New("authv3 token: authv3 timeout, client v2 token: Post \"https://www.privateinternetaccess.com/api/client/v2/token\": v2 network error"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			token, err := testCase.provider.getToken(t.Context(), (*mockFirewall)(nil), "bahamas413",
				testServerIP, "user", "pass")

			if testCase.expectedErr != nil {
				require.Error(t, err)
				assert.ErrorContains(t, err, testCase.expectedErr.Error())
				return
			}

			require.NoError(t, err)
			assert.Equal(t, testCase.expectedToken, token)
		})
	}
}

func ptrTo[T any](v T) *T {
	return &v
}

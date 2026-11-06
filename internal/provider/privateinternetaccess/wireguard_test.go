package privateinternetaccess

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func Test_Provider_RegisterWireguard(t *testing.T) {
	t.Parallel()

	serverPrivateKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	serverPublicKey := serverPrivateKey.PublicKey().String()
	client := &http.Client{
		Transport: piaRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			var body string
			switch request.URL.Path {
			case "/api/client/v2/token":
				body = `{"token":"pia-token"}`
			case "/addKey":
				registeredPublicKey := request.URL.Query().Get("pubkey")
				body = `{"status":"OK","server_key":"` + serverPublicKey +
					`","server_port":51820,"server_ip":"198.51.100.3",` +
					`"server_vip":"10.13.161.1","peer_ip":"10.13.161.2",` +
					`"peer_pubkey":"` + registeredPublicKey + `",` +
					`"dns_servers":["10.0.0.242"]}`
			default:
				t.Fatalf("unexpected request path %s", request.URL.Path)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Body:       io.NopCloser(strings.NewReader(body)),
			}, nil
		}),
	}
	selectedServerIP := netip.MustParseAddr("198.51.100.2")
	cleanups := 0
	restrictedClient := &testRestrictedClient{
		openHTTPSByHostname: func(_ context.Context, hostname string) (*http.Client, func() error, error) {
			assert.Equal(t, "www.privateinternetaccess.com:443", hostname)
			return client, func() error {
				cleanups++
				return nil
			}, nil
		},
		openHTTPSWithRootCAs: func(_ context.Context, serverName string,
			addrPort netip.AddrPort, rootCAs *x509.CertPool,
		) (*http.Client, func() error, error) {
			assert.Equal(t, testPIAServerName, serverName)
			assert.Equal(t, netip.AddrPortFrom(selectedServerIP, wireguardRegistrationPort), addrPort)
			assert.NotNil(t, rootCAs)
			return client, func() error {
				cleanups++
				return nil
			}, nil
		},
	}
	provider := New(nil, time.Now, nil)
	selectedConnection := models.Connection{
		Type:        vpn.Wireguard,
		IP:          selectedServerIP,
		Port:        wireguardRegistrationPort,
		Protocol:    constants.UDP,
		Hostname:    "ca-vancouver.privacy.network",
		ServerName:  testPIAServerName,
		PortForward: true,
	}

	registration, err := provider.RegisterWireguard(t.Context(), selectedConnection,
		"username", "password", restrictedClient)
	require.NoError(t, err)

	assert.Equal(t, 2, cleanups)
	assert.Equal(t, netip.MustParseAddr("198.51.100.3"), registration.Connection.IP)
	assert.Equal(t, uint16(51820), registration.Connection.Port)
	assert.Equal(t, constants.UDP, registration.Connection.Protocol)
}

func Test_fetchAddKey(t *testing.T) {
	t.Parallel()

	const serverName = testPIAServerName
	const token = "pia-token"
	clientPrivateKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	clientPublicKey := clientPrivateKey.PublicKey().String()
	serverPrivateKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	serverPublicKey := serverPrivateKey.PublicKey().String()

	type receivedRequest struct {
		host       string
		path       string
		token      string
		publicKey  string
		pk         string
		serverName string
	}
	received := make(chan receivedRequest, 1)
	handler := http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		received <- receivedRequest{
			host:       request.Host,
			path:       request.URL.Path,
			token:      request.URL.Query().Get("pt"),
			publicKey:  request.URL.Query().Get("pubkey"),
			pk:         request.URL.Query().Get("pk"),
			serverName: request.TLS.ServerName,
		}
		responseWriter.Header().Set("Content-Type", "application/json")
		_, _ = responseWriter.Write([]byte(`{"status":"OK","server_key":"` + serverPublicKey +
			`","server_port":1337,"server_ip":"1.2.3.4","server_vip":"1.2.3.5",` +
			`"peer_ip":"10.13.161.2","dns_servers":["10.0.0.242"]}`))
	})
	server := httptest.NewUnstartedServer(handler)

	certificate, rootCAs := newTestServerCertificate(t, serverName)
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	listenerAddress, err := netip.ParseAddrPort(server.Listener.Addr().String())
	require.NoError(t, err)
	client := server.Client()
	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return new(net.Dialer).DialContext(ctx, network, server.Listener.Addr().String())
	}
	tlsConfig := transport.TLSClientConfig.Clone()
	tlsConfig.InsecureSkipVerify = false
	tlsConfig.RootCAs = rootCAs
	tlsConfig.ServerName = serverName
	transport.TLSClientConfig = tlsConfig

	data, err := fetchAddKey(context.Background(), client, serverName,
		listenerAddress.Port(), token, clientPublicKey)
	require.NoError(t, err)

	request := <-received
	assert.Equal(t, net.JoinHostPort(serverName, strconv.Itoa(int(listenerAddress.Port()))), request.host)
	assert.Equal(t, "/addKey", request.path)
	assert.Equal(t, token, request.token)
	assert.Equal(t, clientPublicKey, request.publicKey)
	assert.Empty(t, request.pk)
	assert.Equal(t, serverName, request.serverName)
	assert.Equal(t, serverPublicKey, data.ServerKey)
}

func Test_mapAddKeyResponse(t *testing.T) {
	t.Parallel()

	serverPrivateKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	serverPublicKey := serverPrivateKey.PublicKey().String()
	const registrationPort = 1337
	selectedConnection := models.Connection{
		Type:        vpn.Wireguard,
		IP:          netip.MustParseAddr("198.51.100.2"),
		Port:        registrationPort,
		Protocol:    constants.UDP,
		Hostname:    "ca-vancouver.privacy.network",
		ServerName:  testPIAServerName,
		PortForward: true,
	}
	const wireguardPort = 51820
	response := addKeyResponse{
		Status:     "OK",
		ServerKey:  serverPublicKey,
		ServerPort: wireguardPort,
		ServerIP:   netip.MustParseAddr("198.51.100.3"),
		ServerVIP:  netip.MustParseAddr("10.13.161.1"),
		PeerIP:     netip.MustParseAddr("10.13.161.2"),
		DNSServers: []netip.Addr{netip.MustParseAddr("10.0.0.242")},
	}

	clientPrivateKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	response.PeerPubKey = clientPrivateKey.PublicKey().String()
	registration, err := mapAddKeyResponse(selectedConnection, clientPrivateKey.String(), response)
	require.NoError(t, err)

	expectedConnection := selectedConnection
	expectedConnection.IP = response.ServerIP
	expectedConnection.Port = response.ServerPort
	expectedConnection.PubKey = response.ServerKey
	assert.Equal(t, expectedConnection, registration.Connection)
	assert.Equal(t, clientPrivateKey.String(), registration.PrivateKey)
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.13.161.2/32")}, registration.Addresses)
	assert.Equal(t, response.DNSServers, registration.DNSServers)
	assert.Equal(t, response.ServerVIP, registration.Gateway)

	response.PeerPubKey = serverPublicKey
	_, err = mapAddKeyResponse(selectedConnection, clientPrivateKey.String(), response)
	assert.ErrorContains(t, err, "registered client public key does not match generated private key")
}

func Test_mapAddKeyResponse_rejectsUnsupportedIPAddresses(t *testing.T) {
	t.Parallel()

	serverPrivateKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	clientPrivateKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	validResponse := addKeyResponse{
		ServerKey:  serverPrivateKey.PublicKey().String(),
		ServerPort: 51820,
		ServerIP:   netip.MustParseAddr("198.51.100.3"),
		ServerVIP:  netip.MustParseAddr("10.13.161.1"),
		PeerIP:     netip.MustParseAddr("10.13.161.2"),
	}
	testCases := map[string]struct {
		update     func(response *addKeyResponse)
		errMessage string
	}{
		"server_ip_unspecified": {
			update: func(response *addKeyResponse) {
				response.ServerIP = netip.IPv4Unspecified()
			},
			errMessage: "server IP is unspecified",
		},
		"server_ip_ipv6": {
			update: func(response *addKeyResponse) {
				response.ServerIP = netip.MustParseAddr("2001:db8::3")
			},
			errMessage: "server IP is IPv6, which PIA registration does not support",
		},
		"server_virtual_ip_unspecified": {
			update: func(response *addKeyResponse) {
				response.ServerVIP = netip.IPv4Unspecified()
			},
			errMessage: "server virtual IP is unspecified",
		},
		"server_virtual_ip_ipv6": {
			update: func(response *addKeyResponse) {
				response.ServerVIP = netip.MustParseAddr("2001:db8::1")
			},
			errMessage: "server virtual IP is IPv6, which PIA registration does not support",
		},
		"peer_ip_unspecified": {
			update: func(response *addKeyResponse) {
				response.PeerIP = netip.IPv4Unspecified()
			},
			errMessage: "peer IP is unspecified",
		},
		"peer_ip_ipv6": {
			update: func(response *addKeyResponse) {
				response.PeerIP = netip.MustParseAddr("2001:db8::2")
			},
			errMessage: "peer IP is IPv6, which PIA registration does not support",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			response := validResponse
			testCase.update(&response)
			_, err := mapAddKeyResponse(models.Connection{}, clientPrivateKey.String(), response)

			require.Error(t, err)
			assert.ErrorContains(t, err, testCase.errMessage)
		})
	}
}

func newTestServerCertificate(t *testing.T, serverName string) (
	certificate tls.Certificate, rootCAs *x509.CertPool,
) {
	t.Helper()

	caPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	const caSerialNumber = 1
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(caSerialNumber),
		Subject:               pkix.Name{CommonName: "PIA test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate,
		&caPrivateKey.PublicKey, caPrivateKey)
	require.NoError(t, err)
	caCertificate, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	serverPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	const serverSerialNumber = 2
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(serverSerialNumber),
		Subject:      pkix.Name{CommonName: serverName},
		DNSNames:     []string{serverName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate,
		caCertificate, &serverPrivateKey.PublicKey, caPrivateKey)
	require.NoError(t, err)

	rootCAs = x509.NewCertPool()
	rootCAs.AddCert(caCertificate)
	return tls.Certificate{
		Certificate: [][]byte{serverDER, caDER},
		PrivateKey:  serverPrivateKey,
	}, rootCAs
}

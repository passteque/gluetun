package privateinternetaccess

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/common"
	"github.com/qdm12/gluetun/internal/wireguard"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var _ common.WireguardConfiger = (*Provider)(nil)

type addKeyResult struct {
	Status     string   `json:"status"`
	ServerKey  string   `json:"server_key"`
	ServerPort uint16   `json:"server_port"`
	ServerIP   string   `json:"server_ip"`
	ServerVIP  string   `json:"server_vip"`
	PeerIP     string   `json:"peer_ip"`
	PeerPubkey string   `json:"peer_pubkey"`
	DNSServers []string `json:"dns_servers"`
	Message    string   `json:"message"`
}

func (p *Provider) WireguardConfig(ctx context.Context, connection *models.Connection,
	vpnSettings settings.VPN, wireguardSettings wireguard.Settings,
	fw common.Firewall,
) (wgSettings wireguard.Settings, err error) {
	if connection.ServerName == "" {
		return wireguardSettings, errors.New("server name is empty")
	}

	if !connection.IP.IsValid() {
		return wireguardSettings, errors.New("connection IP is not valid")
	}

	username := *vpnSettings.OpenVPN.User
	if username == "" {
		username = vpnSettings.Provider.PortForwarding.Username
	}
	if username == "" {
		return wireguardSettings, errors.New("user is empty")
	}

	password := *vpnSettings.OpenVPN.Password
	if password == "" {
		password = vpnSettings.Provider.PortForwarding.Password
	}
	if password == "" {
		return wireguardSettings, errors.New("password is empty")
	}

	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return wireguardSettings, fmt.Errorf("generating private key: %w", err)
	}
	publicKey := privateKey.PublicKey()

	token, err := p.getToken(ctx, fw, connection.ServerName, connection.IP, username, password)
	if err != nil {
		return wireguardSettings, fmt.Errorf("fetching auth token: %w", err)
	}

	if fw != nil {
		const remove = false
		err = fw.AcceptOutput(ctx, "tcp", "*", connection.IP, 1337, remove)
		if err != nil {
			return wireguardSettings, fmt.Errorf("allowing output to wireguard port 1337: %w", err)
		}
		defer func() {
			const remove = true
			_ = fw.AcceptOutput(context.Background(), "tcp", "*", connection.IP, 1337, remove)
		}()
	}

	result, err := p.addWireguardKey(ctx, connection.ServerName, connection.IP, token, publicKey.String())
	if err != nil {
		return wireguardSettings, fmt.Errorf("adding wireguard key: %w", err)
	}

	_, err = wgtypes.ParseKey(result.ServerKey)
	if err != nil {
		return wireguardSettings, fmt.Errorf("parsing server public key: %w", err)
	}

	peerIPString := result.PeerIP
	if !strings.ContainsRune(peerIPString, '/') {
		peerIPString += "/32"
	}
	peerPrefix, err := netip.ParsePrefix(peerIPString)
	if err != nil {
		return wireguardSettings, fmt.Errorf("parsing peer IP: %w", err)
	}

	wireguardSettings.PrivateKey = privateKey.String()
	wireguardSettings.PublicKey = result.ServerKey
	wireguardSettings.Addresses = []netip.Prefix{peerPrefix}

	if wireguardSettings.PersistentKeepaliveInterval == 0 {
		const defaultPersistentKeepalive = 25 * time.Second
		wireguardSettings.PersistentKeepaliveInterval = defaultPersistentKeepalive
	}

	if result.ServerPort > 0 {
		connection.Port = result.ServerPort
	}
	wireguardSettings.Endpoint = netip.AddrPortFrom(connection.IP, connection.Port)
	connection.PubKey = result.ServerKey

	return wireguardSettings, nil
}

func (p *Provider) getToken(ctx context.Context, fw common.Firewall,
	serverName string, serverIP netip.Addr, username, password string,
) (token string, err error) {
	if p.fetchAuthToken != nil {
		if fw != nil {
			const remove = false
			_ = fw.AcceptOutput(ctx, "tcp", "*", serverIP, 443, remove)
			defer func() {
				const remove = true
				_ = fw.AcceptOutput(context.Background(), "tcp", "*", serverIP, 443, remove)
			}()
		}
		token, err = p.fetchAuthToken(ctx, serverName, serverIP, username, password)
		if err == nil {
			return token, nil
		}
	}

	if p.client != nil {
		v2Token, v2Err := fetchTokenThroughFirewall(ctx, fw, p.client, username, password)
		if v2Err == nil {
			return v2Token, nil
		}
		if err != nil {
			return "", fmt.Errorf("authv3 token: %w, client v2 token: %w", err, v2Err)
		}
		return "", fmt.Errorf("client v2 token: %w", v2Err)
	}

	if err != nil {
		return "", err
	}

	return "", errors.New("cannot fetch token: no client available")
}

func fetchTokenThroughFirewall(ctx context.Context, fw common.Firewall,
	client *http.Client, username, password string,
) (token string, err error) {
	const host = "www.privateinternetaccess.com"
	resolvedIPs, err := resolveDomainThroughFirewall(ctx, fw, host)
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", host, err)
	}

	if fw != nil {
		for _, ip := range resolvedIPs {
			const remove = false
			_ = fw.AcceptOutput(ctx, "tcp", "*", ip, 443, remove)
		}
		defer func() {
			for _, ip := range resolvedIPs {
				const remove = true
				_ = fw.AcceptOutput(context.Background(), "tcp", "*", ip, 443, remove)
			}
		}()
	}

	return fetchToken(ctx, client, username, password)
}

func resolveDomainThroughFirewall(ctx context.Context, fw common.Firewall,
	domain string,
) (ips []netip.Addr, err error) {
	dnsIPs := []netip.Addr{
		netip.AddrFrom4([4]byte{1, 1, 1, 1}),
		netip.AddrFrom4([4]byte{1, 0, 0, 1}),
		netip.AddrFrom4([4]byte{8, 8, 8, 8}),
		netip.AddrFrom4([4]byte{8, 8, 4, 4}),
		netip.AddrFrom4([4]byte{9, 9, 9, 9}),
	}

	if fw != nil {
		for _, dnsIP := range dnsIPs {
			const remove = false
			_ = fw.AcceptOutput(ctx, "udp", "*", dnsIP, 53, remove)
			_ = fw.AcceptOutput(ctx, "tcp", "*", dnsIP, 53, remove)
		}
		defer func() {
			for _, dnsIP := range dnsIPs {
				const remove = true
				_ = fw.AcceptOutput(context.Background(), "udp", "*", dnsIP, 53, remove)
				_ = fw.AcceptOutput(context.Background(), "tcp", "*", dnsIP, 53, remove)
			}
		}()
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			conn, dialErr := d.DialContext(ctx, "udp", "1.1.1.1:53")
			if dialErr == nil {
				return conn, nil
			}
			conn, dialErr = d.DialContext(ctx, "udp", "8.8.8.8:53")
			if dialErr == nil {
				return conn, nil
			}
			return d.DialContext(ctx, network, address)
		},
	}

	netIPs, err := resolver.LookupIP(ctx, "ip4", domain)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", domain, err)
	}

	netipAddrs := make([]netip.Addr, 0, len(netIPs))
	for _, ip := range netIPs {
		addr, ok := netip.AddrFromSlice(ip.To4())
		if ok {
			netipAddrs = append(netipAddrs, addr)
		}
	}

	if len(netipAddrs) == 0 {
		return nil, fmt.Errorf("no IPv4 address found for %s", domain)
	}

	return netipAddrs, nil
}

func fetchAuthV3Token(ctx context.Context, serverName string, serverIP netip.Addr,
	username, password string,
) (token string, err error) {
	client, err := newHTTPClient(serverName)
	if err != nil {
		return "", fmt.Errorf("creating HTTP client: %w", err)
	}

	return fetchAuthV3TokenWithClient(ctx, client, serverIP, username, password)
}

func fetchAuthV3TokenWithClient(ctx context.Context, client *http.Client, serverIP netip.Addr,
	username, password string,
) (token string, err error) {
	const timeout = 10 * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	apiURL := url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(serverIP.String(), "443"),
		Path:   "/authv3/generateToken",
	}

	errSubstitutions := map[string]string{
		url.QueryEscape(username): "<username>",
		url.QueryEscape(password): "<password>",
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL.String(), nil)
	if err != nil {
		return "", replaceInErr(err, errSubstitutions)
	}
	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth(username, password)

	response, err := client.Do(request)
	if err != nil {
		return "", replaceInErr(err, errSubstitutions)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return "", makeNOKStatusError(response, errSubstitutions)
	}

	decoder := json.NewDecoder(response.Body)
	var result struct {
		Token   string `json:"token"`
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	if err := decoder.Decode(&result); err != nil {
		return "", fmt.Errorf("decoding response: %w", err)
	}

	if result.Token == "" {
		if result.Message != "" {
			return "", fmt.Errorf("error from server: %s", result.Message)
		}
		return "", errors.New("token received is empty")
	}

	return result.Token, nil
}

func addWireguardKey(ctx context.Context, serverName string, serverIP netip.Addr,
	token, publicKey string,
) (result addKeyResult, err error) {
	client, err := newHTTPClient(serverName)
	if err != nil {
		return result, fmt.Errorf("creating HTTP client: %w", err)
	}

	return addWireguardKeyWithClient(ctx, client, serverIP, token, publicKey)
}

func addWireguardKeyWithClient(ctx context.Context, client *http.Client, serverIP netip.Addr,
	token, publicKey string,
) (result addKeyResult, err error) {
	const timeout = 10 * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	queryParams := make(url.Values)
	queryParams.Add("pt", token)
	queryParams.Add("pubkey", publicKey)

	apiURL := url.URL{
		Scheme:   "https",
		Host:     net.JoinHostPort(serverIP.String(), "1337"),
		Path:     "/addKey",
		RawQuery: queryParams.Encode(),
	}

	errSubstitutions := map[string]string{
		url.QueryEscape(token):     "<token>",
		url.QueryEscape(publicKey): "<public_key>",
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL.String(), nil)
	if err != nil {
		return result, replaceInErr(err, errSubstitutions)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := client.Do(request)
	if err != nil {
		return result, replaceInErr(err, errSubstitutions)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return result, makeNOKStatusError(response, errSubstitutions)
	}

	decoder := json.NewDecoder(response.Body)
	if err := decoder.Decode(&result); err != nil {
		return result, fmt.Errorf("decoding response: %w", err)
	}

	if result.Status != "OK" {
		return result, fmt.Errorf("server returned non-OK status %q: %s", result.Status, result.Message)
	}

	return result, nil
}

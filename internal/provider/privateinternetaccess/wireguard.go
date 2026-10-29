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
	"strconv"
	"time"

	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/common"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type addKeyResponse struct {
	Status     string       `json:"status"`
	ServerKey  string       `json:"server_key"`
	ServerPort uint16       `json:"server_port"`
	ServerIP   netip.Addr   `json:"server_ip"`
	ServerVIP  netip.Addr   `json:"server_vip"`
	PeerIP     netip.Addr   `json:"peer_ip"`
	PeerPubKey string       `json:"peer_pubkey"`
	DNSServers []netip.Addr `json:"dns_servers"`
}

const wireguardRegistrationPort uint16 = 1337

// RegisterWireguard registers a fresh ephemeral key with the selected PIA
// server and returns all provider-generated connection settings.
func (p *Provider) RegisterWireguard(ctx context.Context, connection models.Connection,
	username, password string, restrictedClient common.RestrictedClient,
) (wireguardConnection models.WireguardConnection, err error) {
	switch {
	case restrictedClient == nil:
		return wireguardConnection, errors.New("restricted network client is not set")
	case connection.ServerName == "":
		return wireguardConnection, errors.New("registration server name is not set")
	case username == "":
		return wireguardConnection, errors.New("username is not set")
	case password == "":
		return wireguardConnection, errors.New("password is not set")
	}
	if err := validateRegistrationIPv4(connection.IP, "registration server IP"); err != nil {
		return wireguardConnection, err
	}

	token, err := p.fetchWireguardToken(ctx, username, password, restrictedClient)
	if err != nil {
		return wireguardConnection, fmt.Errorf("fetching token: %w", err)
	}

	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return wireguardConnection, fmt.Errorf("generating Wireguard private key: %w", err)
	}
	publicKey := privateKey.PublicKey().String()

	rootCAs, err := newPIACertificatePool(connection.ServerName)
	if err != nil {
		return wireguardConnection, fmt.Errorf("creating PIA certificate pool: %w", err)
	}
	registrationAddrPort := netip.AddrPortFrom(connection.IP, wireguardRegistrationPort)
	client, cleanup, err := restrictedClient.OpenHTTPSWithRootCAs(ctx,
		connection.ServerName, registrationAddrPort, rootCAs)
	if err != nil {
		return wireguardConnection, fmt.Errorf("opening registration connection: %w", err)
	}
	defer cleanupRestrictedConnection(cleanup, &err)

	response, err := fetchAddKey(ctx, client, connection.ServerName,
		wireguardRegistrationPort, token, publicKey)
	if err != nil {
		return wireguardConnection, fmt.Errorf("registering Wireguard key: %w", err)
	}

	wireguardConnection, err = mapAddKeyResponse(connection, privateKey.String(), response)
	if err != nil {
		return models.WireguardConnection{}, fmt.Errorf("mapping registration response: %w", err)
	}
	return wireguardConnection, nil
}

func (p *Provider) fetchWireguardToken(ctx context.Context, username, password string,
	restrictedClient common.RestrictedClient,
) (token string, err error) {
	if restrictedClient == nil {
		return "", errors.New("restricted network client is not set")
	}

	const tokenServerName = "www.privateinternetaccess.com"
	client, cleanup, err := restrictedClient.OpenHTTPSByHostname(ctx,
		net.JoinHostPort(tokenServerName, "443"))
	if err != nil {
		return "", fmt.Errorf("opening token server connection: %w", err)
	}
	defer cleanupRestrictedConnection(cleanup, &err)

	token, err = fetchToken(ctx, client, username, password)
	if err != nil {
		return "", fmt.Errorf("fetching from token server: %w", err)
	}
	return token, nil
}

func fetchAddKey(ctx context.Context, client *http.Client, serverName string,
	serverPort uint16, token, publicKey string,
) (data addKeyResponse, err error) {
	const timeout = 10 * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	query := make(url.Values)
	query.Add("pt", token)
	query.Add("pubkey", publicKey)
	requestURL := url.URL{
		Scheme:   "https",
		Host:     net.JoinHostPort(serverName, strconv.Itoa(int(serverPort))),
		Path:     "/addKey",
		RawQuery: query.Encode(),
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return data, replaceInErr(err, map[string]string{url.QueryEscape(token): "<token>"})
	}

	response, err := client.Do(request)
	if err != nil {
		return data, replaceInErr(err, map[string]string{url.QueryEscape(token): "<token>"})
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return data, makeNOKStatusError(response,
			map[string]string{url.QueryEscape(token): "<token>"})
	}

	err = json.NewDecoder(response.Body).Decode(&data)
	if err != nil {
		return data, fmt.Errorf("decoding response: %w", err)
	}
	if data.Status != "OK" {
		return data, fmt.Errorf("bad response received with status %q", data.Status)
	}
	return data, nil
}

func mapAddKeyResponse(connection models.Connection, privateKey string,
	response addKeyResponse,
) (wireguardConnection models.WireguardConnection, err error) {
	parsedPrivateKey, err := wgtypes.ParseKey(privateKey)
	if err != nil {
		return wireguardConnection, fmt.Errorf("client private key is not valid: %w", err)
	}
	registeredPublicKey := parsedPrivateKey.PublicKey().String()
	if response.PeerPubKey != "" && response.PeerPubKey != registeredPublicKey {
		return wireguardConnection, errors.New("registered client public key does not match generated private key")
	}

	_, err = wgtypes.ParseKey(response.ServerKey)
	if err != nil {
		return wireguardConnection, fmt.Errorf("server public key is not valid: %w", err)
	}
	if response.ServerPort == 0 {
		return wireguardConnection, errors.New("server port is not set")
	}
	err = validateRegistrationIPv4(response.ServerIP, "server IP")
	if err != nil {
		return wireguardConnection, err
	}
	err = validateRegistrationIPv4(response.ServerVIP, "server virtual IP")
	if err != nil {
		return wireguardConnection, err
	}
	err = validateRegistrationIPv4(response.PeerIP, "peer IP")
	if err != nil {
		return wireguardConnection, err
	}

	connection.Type = vpn.Wireguard
	connection.IP = response.ServerIP
	connection.Port = response.ServerPort
	connection.Protocol = constants.UDP
	connection.PubKey = response.ServerKey

	address := netip.PrefixFrom(response.PeerIP, response.PeerIP.BitLen())
	return models.WireguardConnection{
		Connection: connection,
		PrivateKey: privateKey,
		Addresses:  []netip.Prefix{address},
		DNSServers: append([]netip.Addr(nil), response.DNSServers...),
		Gateway:    response.ServerVIP,
	}, nil
}

func validateRegistrationIPv4(address netip.Addr, fieldName string) error {
	switch {
	case !address.IsValid():
		return fmt.Errorf("%s is not set", fieldName)
	case address.IsUnspecified():
		return fmt.Errorf("%s is unspecified", fieldName)
	case !address.Is4():
		return fmt.Errorf("%s is IPv6, which PIA registration does not support", fieldName)
	default:
		return nil
	}
}

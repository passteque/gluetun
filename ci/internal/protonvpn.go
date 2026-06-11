package internal

import (
	"context"
	"fmt"
	"regexp"
	"time"
)

func ProtonVPNWireguardPortForwardingTest(ctx context.Context, logger Logger) error {
	expectedSecrets := []string{
		"Wireguard private key",
	}
	secrets, err := readSecrets(ctx, expectedSecrets, logger)
	if err != nil {
		return fmt.Errorf("reading secrets: %w", err)
	}

	env := []string{
		"VPN_SERVICE_PROVIDER=protonvpn",
		"VPN_TYPE=wireguard",
		"LOG_LEVEL=debug",
		"SERVER_COUNTRIES=United States",
		"WIREGUARD_PRIVATE_KEY=" + secrets[0],
		"VPN_PORT_FORWARDING=on",
	}
	const timeout = 80 * time.Second
	return runContainerTest(ctx, env, []*regexp.Regexp{successRegexp, portForwardingRegexp}, timeout, logger)
}

func ProtonVPNOpenVPNPortForwardingTest(ctx context.Context, logger Logger) error {
	expectedSecrets := []string{
		"OpenVPN username",
		"OpenVPN password",
	}
	secrets, err := readSecrets(ctx, expectedSecrets, logger)
	if err != nil {
		return fmt.Errorf("reading secrets: %w", err)
	}

	env := []string{
		"VPN_SERVICE_PROVIDER=protonvpn",
		"VPN_TYPE=openvpn",
		"LOG_LEVEL=debug",
		"SERVER_COUNTRIES=United States",
		"OPENVPN_USER=" + secrets[0],
		"OPENVPN_PASSWORD=" + secrets[1],
		"VPN_PORT_FORWARDING=on",
	}
	const timeout = 80 * time.Second
	return runContainerTest(ctx, env, []*regexp.Regexp{successRegexp, portForwardingRegexp}, timeout, logger)
}

package internal

import (
	"context"
	"fmt"
	"regexp"
	"time"
)

func AirVPNWireguardTest(ctx context.Context, logger Logger) error {
	expectedSecrets := []string{
		"Wireguard private key",
		"Wireguard preshared key",
		"Wireguard addresses",
	}
	secrets, err := readSecrets(ctx, expectedSecrets, logger)
	if err != nil {
		return fmt.Errorf("reading secrets: %w", err)
	}

	env := []string{
		"VPN_SERVICE_PROVIDER=airvpn",
		"VPN_TYPE=wireguard",
		"LOG_LEVEL=debug",
		"SERVER_COUNTRIES=United States",
		"WIREGUARD_PRIVATE_KEY=" + secrets[0],
		"WIREGUARD_PRESHARED_KEY=" + secrets[1],
		"WIREGUARD_ADDRESSES=" + secrets[2],
	}
	const timeout = 60 * time.Second
	return runContainerTest(ctx, env, []*regexp.Regexp{successRegexp}, timeout, logger)
}

func AirVPNOpenVPNTest(ctx context.Context, logger Logger) error {
	expectedSecrets := []string{
		"OpenVPN key",
		"OpenVPN cert",
	}
	secrets, err := readSecrets(ctx, expectedSecrets, logger)
	if err != nil {
		return fmt.Errorf("reading secrets: %w", err)
	}

	env := []string{
		"VPN_SERVICE_PROVIDER=airvpn",
		"VPN_TYPE=openvpn",
		"LOG_LEVEL=debug",
		"SERVER_COUNTRIES=United States",
		"OPENVPN_KEY=" + secrets[0],
		"OPENVPN_CERT=" + secrets[1],
	}
	const timeout = 60 * time.Second
	return runContainerTest(ctx, env, []*regexp.Regexp{successRegexp}, timeout, logger)
}

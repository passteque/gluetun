package internal //nolint:dupl

import (
	"context"
	"fmt"
	"regexp"
	"time"
)

func WindscribeWireguardTest(ctx context.Context, logger Logger) error {
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
		"VPN_SERVICE_PROVIDER=windscribe",
		"VPN_TYPE=wireguard",
		"LOG_LEVEL=debug",
		"SERVER_REGIONS=US East",
		"WIREGUARD_PRIVATE_KEY=" + secrets[0],
		"WIREGUARD_PRESHARED_KEY=" + secrets[1],
		"WIREGUARD_ADDRESSES=" + secrets[2],
	}
	const timeout = 60 * time.Second
	return runContainerTest(ctx, env, []*regexp.Regexp{successRegexp}, timeout, logger)
}

func WindscribeOpenVPNTest(ctx context.Context, logger Logger) error {
	expectedSecrets := []string{
		"OpenVPN user",
		"OpenVPN password",
	}
	secrets, err := readSecrets(ctx, expectedSecrets, logger)
	if err != nil {
		return fmt.Errorf("reading secrets: %w", err)
	}

	env := []string{
		"VPN_SERVICE_PROVIDER=windscribe",
		"VPN_TYPE=openvpn",
		"LOG_LEVEL=debug",
		"SERVER_REGIONS=US East",
		"OPENVPN_USER=" + secrets[0],
		"OPENVPN_PASSWORD=" + secrets[1],
	}
	const timeout = 60 * time.Second
	return runContainerTest(ctx, env, []*regexp.Regexp{successRegexp}, timeout, logger)
}

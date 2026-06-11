package internal

import (
	"context"
	"fmt"
	"regexp"
	"time"
)

func PrivateInternetAccessOpenVPNPortForwardingTest(ctx context.Context, logger Logger) error {
	expectedSecrets := []string{
		"OpenVPN username",
		"OpenVPN password",
	}
	secrets, err := readSecrets(ctx, expectedSecrets, logger)
	if err != nil {
		return fmt.Errorf("reading secrets: %w", err)
	}

	env := []string{
		"VPN_SERVICE_PROVIDER=private internet access",
		"VPN_TYPE=openvpn",
		"LOG_LEVEL=debug",
		"SERVER_REGIONS=CA Montreal",
		"OPENVPN_USER=" + secrets[0],
		"OPENVPN_PASSWORD=" + secrets[1],
		"VPN_PORT_FORWARDING=on",
	}
	const timeout = 80 * time.Second
	return runContainerTest(ctx, env, []*regexp.Regexp{successRegexp, portForwardingRegexp}, timeout, logger)
}

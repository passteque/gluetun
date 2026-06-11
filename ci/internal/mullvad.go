package internal

import (
	"context"
	"fmt"
	"regexp"
	"time"
)

func MullvadTest(ctx context.Context, logger Logger) error {
	expectedSecrets := []string{
		"Wireguard private key",
		"Wireguard address",
	}
	secrets, err := readSecrets(ctx, expectedSecrets, logger)
	if err != nil {
		return fmt.Errorf("reading secrets: %w", err)
	}

	env := []string{
		"VPN_SERVICE_PROVIDER=mullvad",
		"VPN_TYPE=wireguard",
		"LOG_LEVEL=debug",
		"SERVER_COUNTRIES=USA",
		"WIREGUARD_PRIVATE_KEY=" + secrets[0],
		"WIREGUARD_ADDRESSES=" + secrets[1],
	}
	const timeout = 60 * time.Second
	return runContainerTest(ctx, env, []*regexp.Regexp{successRegexp}, timeout, logger)
}

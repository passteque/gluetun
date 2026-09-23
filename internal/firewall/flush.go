package firewall

import (
	"context"
	"fmt"
	"net/netip"
	"time"
)

// flushExistingConnections kills the existing connections that would
// otherwise be accepted by the "established, related" traffic rules once
// the firewall is enabled, letting them leak traffic outside of the VPN.
//
// It first tries flushing the conntrack tables via netlink, which is the
// cleanest way to kill the connections. If this fails for any reason —
// for example on older kernels that do not support the conntrack delete
// message, see https://github.com/qdm12/gluetun/issues/3152 — it falls
// back to iptables-based alternatives, in order of preference:
//  1. marking the new connections, and filtering the unmarked ones,
//  2. rejecting the public output traffic for one second,
//  3. dropping the public output traffic for one second.
//
// This function never fails: killing the existing connections is an
// optimization, not a requirement for the firewall to be functional, so
// it only logs a warning if none of the methods succeeded.
func (c *Config) flushExistingConnections(ctx context.Context) {
	tries := []struct {
		name string
		f    func(ctx context.Context, prefixes []netip.Prefix) error
	}{
		{name: "flushing conntrack", f: func(_ context.Context, _ []netip.Prefix) error {
			return c.netlinker.FlushConntrack()
		}},
		{name: "marking and filtering unmarked packets", f: c.impl.AcceptOutputPublicOnlyNewTraffic},
		{name: "rejecting connections for one second", f: c.rejectOutputTrafficTemporarily},
		{name: "dropping connections for one second", f: c.dropOutputTrafficTemporarily},
	}

	localPrefixes := make([]netip.Prefix, 0, len(c.localNetworks))
	for _, network := range c.localNetworks {
		localPrefixes = append(localPrefixes, network.IPNet)
	}

	errs := make([]error, 0, len(tries))
	firstTry := true
	var previousTryName string
	var previousTryErr error
	for _, try := range tries {
		if !firstTry {
			c.logger.Debugf("falling back to %s because %s failed: %s",
				try.name, previousTryName, previousTryErr)
		}
		firstTry = false
		err := try.f(ctx, localPrefixes)
		if err == nil {
			return
		}
		err = fmt.Errorf("%s: %w", try.name, err)
		errs = append(errs, err)
		previousTryName = try.name
		previousTryErr = err
	}
	c.logger.Warnf("flushing existing connections failed: %v", errs)
}

func (c *Config) rejectOutputTrafficTemporarily(ctx context.Context, localPrefixes []netip.Prefix) error {
	return setupThenRevert(ctx, func(ctx context.Context, remove bool) error {
		return c.impl.RejectOutputPublicTraffic(ctx, localPrefixes, remove)
	})
}

func (c *Config) dropOutputTrafficTemporarily(ctx context.Context, localPrefixes []netip.Prefix) error {
	return setupThenRevert(ctx, func(ctx context.Context, remove bool) error {
		return c.impl.DropOutputPublicTraffic(ctx, localPrefixes, remove)
	})
}

// setupThenRevert is a helper function to run a setup function that takes a remove boolean argument,
// and then run the same function with remove set to true after one second or when the context is canceled,
// whichever comes first.
func setupThenRevert(ctx context.Context, f func(ctx context.Context, remove bool) error) error {
	remove := false
	err := f(ctx, remove)
	if err != nil {
		return fmt.Errorf("setting up: %w", err)
	}
	timer := time.NewTimer(time.Second)
	select {
	case <-timer.C:
	case <-ctx.Done():
		timer.Stop()
	}
	remove = true
	// Use [context.Background] to make sure this is removed, even if the context
	// passed to this function is canceled.
	err = f(context.Background(), remove)
	if err != nil {
		return fmt.Errorf("reverting: %w", err)
	}
	return nil
}

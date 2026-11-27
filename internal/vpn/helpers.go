package vpn

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/models"
)

func ptrTo[T any](value T) *T { return &value }

// resolveEndpoint resolves an endpoint hostname to an IP address using the
// resolver, preferring an IPv6 address when IPv6 is supported, otherwise
// the first IPv4 address, falling back to the first address available.
func resolveEndpoint(ctx context.Context, resolver Resolver,
	hostname string, ipv6Supported bool, logger interface{ Info(string) },
) (ip netip.Addr, err error) {
	addresses, err := resolver.ResolveName(ctx, hostname)
	if err != nil {
		return ip, fmt.Errorf("resolving endpoint hostname %q: %w", hostname, err)
	}
	if len(addresses) == 0 {
		return ip, fmt.Errorf("resolving endpoint hostname %q: no IP address found", hostname)
	}

	ip = pickResolvedIP(addresses, ipv6Supported)
	logger.Info("resolved endpoint hostname " + hostname + " to " + ip.String())
	return ip, nil
}

// pickResolvedIP picks the best IP from resolved addresses, preferring IPv6
// when supported, otherwise the first IPv4 address.
func pickResolvedIP(addresses []netip.Addr, ipv6Supported bool) netip.Addr {
	if ipv6Supported {
		for _, address := range addresses {
			if address.Is6() {
				return address
			}
		}
	}
	for _, address := range addresses {
		if address.Is4() {
			return address
		}
	}
	return addresses[0]
}

// waitForError waits 100ms for an error in the waitError channel.
func (l *Loop) waitForError(ctx context.Context,
	waitError chan error,
) (err error) {
	const waitDurationForError = 100 * time.Millisecond
	timer := time.NewTimer(waitDurationForError)
	select {
	case <-ctx.Done():
		if !timer.Stop() {
			<-timer.C
		}
		return ctx.Err()
	case <-timer.C:
		return nil
	case err := <-waitError:
		close(waitError)
		if !timer.Stop() {
			<-timer.C
		}
		return err
	}
}

func (l *Loop) crashed(ctx context.Context, err error) {
	l.signalOrSetStatus(constants.Crashed)
	l.logAndWait(ctx, err)
}

func (l *Loop) signalOrSetStatus(status models.LoopStatus) {
	if l.userTrigger {
		l.userTrigger = false
		select {
		case l.running <- status:
		default: // receiver calling ApplyStatus dropped out
		}
	} else {
		l.statusManager.SetStatus(status)
	}
}

func (l *Loop) logAndWait(ctx context.Context, err error) {
	if err != nil {
		l.logger.Error(err.Error())
	}
	l.logger.Info("retrying in " + l.backoffTime.String())
	timer := time.NewTimer(l.backoffTime)
	l.backoffTime *= 2
	select {
	case <-timer.C:
	case <-ctx.Done():
		if !timer.Stop() {
			<-timer.C
		}
	}
}

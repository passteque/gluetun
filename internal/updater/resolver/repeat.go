package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"time"
)

type Repeat struct {
	resolver *net.Resolver
}

func NewRepeat(dialer Dialer) *Repeat {
	return &Repeat{
		resolver: newResolver(dialer),
	}
}

type RepeatSettings struct {
	Address         string
	MaxDuration     time.Duration
	BetweenDuration time.Duration
	MaxNoNew        int
	// Maximum consecutive DNS resolution failures
	MaxFails int
	SortIPs  bool
}

func (r *Repeat) Resolve(ctx context.Context, host string, settings RepeatSettings) (
	ips []netip.Addr, err error,
) {
	timedCtx, cancel := context.WithTimeout(ctx, settings.MaxDuration)
	defer cancel()

	noNewCounter := 0
	failCounter := 0
	uniqueIPs := make(map[string]struct{})

	for err == nil {
		// TODO
		// - one resolving every 100ms for round robin DNS responses
		// - one every second for time based DNS cycling responses
		noNewCounter, failCounter, err = r.resolveOnce(ctx, timedCtx, host, settings, uniqueIPs, noNewCounter, failCounter)
	}

	if len(uniqueIPs) == 0 {
		return nil, err
	}

	ips = uniqueIPsToSlice(uniqueIPs)

	if settings.SortIPs {
		sort.Slice(ips, func(i, j int) bool {
			return ips[i].Compare(ips[j]) < 1
		})
	}

	return ips, nil
}

var (
	ErrMaxNoNew = errors.New("reached the maximum number of no new update")
	ErrMaxFails = errors.New("reached the maximum number of consecutive failures")
)

func (r *Repeat) resolveOnce(ctx, timedCtx context.Context, host string,
	settings RepeatSettings, uniqueIPs map[string]struct{}, noNewCounter, failCounter int) (
	newNoNewCounter, newFailCounter int, err error,
) {
	IPs, err := r.lookupIPs(timedCtx, host)
	if err != nil {
		failCounter++
		if settings.MaxFails > 0 && failCounter == settings.MaxFails {
			return noNewCounter, failCounter, fmt.Errorf("%w: %d failed attempts resolving %s: %s",
				ErrMaxFails, settings.MaxFails, host, err)
		}
		// it's fine to fail some of the resolutions
		return noNewCounter, failCounter, nil
	}
	failCounter = 0 // reset the counter if we had no error

	anyNew := false
	for _, IP := range IPs {
		key := IP.String()
		if _, ok := uniqueIPs[key]; !ok {
			anyNew = true
			uniqueIPs[key] = struct{}{}
		}
	}

	if !anyNew {
		noNewCounter++
	}

	if settings.MaxNoNew > 0 && noNewCounter == settings.MaxNoNew {
		// we reached the maximum number of resolutions without
		// finding any new IP address to our unique IP addresses set.
		return noNewCounter, failCounter,
			fmt.Errorf("%w: %d times no updated for %d IP addresses found",
				ErrMaxNoNew, noNewCounter, len(uniqueIPs))
	}

	timer := time.NewTimer(settings.BetweenDuration)
	select {
	case <-timer.C:
		return noNewCounter, failCounter, nil
	case <-ctx.Done():
		if !timer.Stop() {
			<-timer.C
		}
		return noNewCounter, failCounter, ctx.Err()
	case <-timedCtx.Done():
		if err := ctx.Err(); err != nil {
			// timedCtx was canceled from its parent context
			return noNewCounter, failCounter, err
		}
		return noNewCounter, failCounter,
			fmt.Errorf("reached the timeout: %w", timedCtx.Err())
	}
}

func (r *Repeat) lookupIPs(ctx context.Context, host string) (ips []netip.Addr, err error) {
	addresses, err := r.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips = make([]netip.Addr, 0, len(addresses))
	for i := range addresses {
		ip, ok := netip.AddrFromSlice(addresses[i].IP)
		if !ok {
			continue
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

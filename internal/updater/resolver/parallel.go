package resolver

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
)

type Parallel struct {
	repeatResolver *Repeat
}

func NewParallelResolver(dialer Dialer) *Parallel {
	return &Parallel{
		repeatResolver: NewRepeat(dialer),
	}
}

type ParallelSettings struct {
	// Hosts to resolve in parallel.
	Hosts     []string
	Repeat    RepeatSettings
	FailEarly bool
	// Maximum ratio of the hosts failing DNS resolution
	// divided by the total number of hosts requested.
	// This value is between 0 and 1. Note this is only
	// applicable if FailEarly is not set to true.
	MaxFailRatio float64
}

type parallelResult struct {
	host string
	IPs  []netip.Addr
}

var (
	ErrMinFound     = errors.New("not enough hosts found")
	ErrMaxFailRatio = errors.New("maximum failure ratio reached")
)

func (pr *Parallel) Resolve(ctx context.Context, settings ParallelSettings) (
	hostToIPs map[string][]netip.Addr, warnings []string, err error,
) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan parallelResult)
	defer close(results)
	errors := make(chan error)
	defer close(errors)

	for _, host := range settings.Hosts {
		go pr.resolveAsync(ctx, host, settings.Repeat, results, errors)
	}

	hostToIPs = make(map[string][]netip.Addr, len(settings.Hosts))
	maxFails := int(settings.MaxFailRatio * float64(len(settings.Hosts)))

	for range settings.Hosts {
		select {
		case newErr := <-errors:
			if settings.FailEarly {
				if err == nil {
					// only set the error to the first error encountered
					// and not the context canceled errors coming after.
					err = newErr
					cancel()
				}
				break
			}

			// do not add warnings coming from the call to cancel()
			if len(warnings) < maxFails {
				warnings = append(warnings, newErr.Error())
			}

			if len(warnings) == maxFails {
				cancel() // cancel only once when we reach maxFails
			}
		case result := <-results:
			hostToIPs[result.host] = result.IPs
		}
	}

	if err != nil { // fail early
		return nil, warnings, err
	}

	failureRatio := float64(len(warnings)) / float64(len(settings.Hosts))
	if failureRatio > settings.MaxFailRatio {
		return hostToIPs, warnings,
			fmt.Errorf("%w: %.2f failure ratio reached", ErrMaxFailRatio, failureRatio)
	}

	return hostToIPs, warnings, nil
}

func (pr *Parallel) resolveAsync(ctx context.Context, host string,
	settings RepeatSettings, results chan<- parallelResult, errors chan<- error,
) {
	IPs, err := pr.repeatResolver.Resolve(ctx, host, settings)
	if err != nil {
		errors <- err
		return
	}
	results <- parallelResult{
		host: host,
		IPs:  IPs,
	}
}

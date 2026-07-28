package healthcheck

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/qdm12/gluetun/internal/healthcheck/dns"
	"github.com/qdm12/gluetun/internal/healthcheck/icmp"
)

type Checker struct {
	tlsDialAddrs   []string
	dialer         *net.Dialer
	echoer         *icmp.Echoer
	dnsClient      *dns.Client
	logger         Logger
	icmpTargetIPs  []netip.Addr
	smallCheckType string
	startupOnFail  bool
	configMutex    sync.Mutex

	icmpNotPermitted *bool

	// Internal periodic service signals
	stop context.CancelFunc
	done <-chan struct{}
}

func NewChecker(logger Logger) *Checker {
	return &Checker{
		dialer: &net.Dialer{
			Resolver: &net.Resolver{
				PreferGo: true,
			},
		},
		echoer:    icmp.NewEchoer(logger),
		dnsClient: dns.New(),
		logger:    logger,
	}
}

// SetConfig sets the following:
// - TCP+TLS dial addresses
// - ICMP echo IP addresses to target
// - the desired small check type (dns or icmp)
// - whether to startup the periodic checks if the startup check fails.
// This function MUST be called before calling [Checker.Start].
func (c *Checker) SetConfig(tlsDialAddrs []string, icmpTargets []netip.Addr,
	smallCheckType string, startupOnFail bool,
) {
	c.configMutex.Lock()
	defer c.configMutex.Unlock()
	c.tlsDialAddrs = tlsDialAddrs
	c.icmpTargetIPs = icmpTargets
	c.smallCheckType = smallCheckType
	c.startupOnFail = startupOnFail
}

// Start starts the [Checker] which behaves differently according to its
// internal field startupOnFail, which is set by calling [Checker.SetConfig].
//
// By default, startupOnFail should be false and the behavior is as follows:
// A blocking 6s-timed TCP+TLS check is performed first. If it fails,
// an error is returned and the [Checker] is not started.
// On success, it starts the periodic checks in a separate goroutine, returning
// the runError error channel and a nil error.
//
// If startupOnFail is true, the behavior is as follows:
// A blocking 6s-timed TCP+TLS check is performed first. If it fails,
// the error is sent to the runError channel, but no error is returned
// and the [Checker] continues to start the periodic checks in a separate goroutine, returning
// the runError error channel and a nil error.
//
// The periodic checks consist in:
// - a "small" ICMP echo check every minute
// - a "full" TCP+TLS check every 5 minutes
//
// The [Checker] has to be ultimately stopped by calling [Checker.Stop].
func (c *Checker) Start(ctx context.Context) (runError <-chan error, err error) {
	if len(c.tlsDialAddrs) == 0 || len(c.icmpTargetIPs) == 0 || c.smallCheckType == "" {
		panic("call Checker.SetConfig with non empty values before Checker.Start")
	}

	if c.icmpNotPermitted != nil && *c.icmpNotPermitted {
		// restore forced check type to dns if icmp was found to be not permitted
		c.smallCheckType = smallCheckDNS
	}
	c.echoer.Reset()

	// runErrorCh MUST be buffered in the case startupOnFail is true, and
	// a startup error was encountered, to avoid blocking the startup
	// goroutine when sending the error, especially since the caller may
	// not be ready to receive from the channel yet.
	runErrorCh := make(chan error, 1)
	runError = runErrorCh
	err = c.startupCheck(ctx)
	if err != nil {
		err = fmt.Errorf("startup check: %w", err)
		if !c.startupOnFail {
			return nil, err
		}
		runErrorCh <- err
	}

	ready := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	c.stop = cancel
	done := make(chan struct{})
	c.done = done
	const smallCheckPeriod = time.Minute
	smallCheckTimer := time.NewTimer(smallCheckPeriod)
	const fullCheckPeriod = 5 * time.Minute
	fullCheckTimer := time.NewTimer(fullCheckPeriod)
	go func() {
		defer close(done)
		close(ready)
		for {
			select {
			case <-ctx.Done():
				fullCheckTimer.Stop()
				smallCheckTimer.Stop()
				return
			case <-smallCheckTimer.C:
				err := c.smallPeriodicCheck(ctx)
				if err != nil {
					err = fmt.Errorf("small periodic check: %w", err)
				}
				select {
				case <-ctx.Done():
					continue
				case runErrorCh <- err:
				}
				smallCheckTimer.Reset(smallCheckPeriod)
			case <-fullCheckTimer.C:
				err := c.fullPeriodicCheck(ctx)
				if err != nil {
					err = fmt.Errorf("full periodic check: %w", err)
				}
				select {
				case <-ctx.Done():
					continue
				case runErrorCh <- err:
				}
				fullCheckTimer.Reset(fullCheckPeriod)
			}
		}
	}()
	<-ready
	return runError, nil
}

func (c *Checker) Stop() error {
	c.stop()
	<-c.done
	c.tlsDialAddrs = nil
	c.icmpTargetIPs = nil
	c.smallCheckType = ""
	return nil
}

func (c *Checker) smallPeriodicCheck(ctx context.Context) error {
	c.configMutex.Lock()
	icmpTargetIPs := make([]netip.Addr, len(c.icmpTargetIPs))
	copy(icmpTargetIPs, c.icmpTargetIPs)
	c.configMutex.Unlock()
	tryTimeouts := []time.Duration{
		5 * time.Second,
		5 * time.Second,
		5 * time.Second,
		10 * time.Second,
		10 * time.Second,
		10 * time.Second,
		15 * time.Second,
		15 * time.Second,
		15 * time.Second,
		30 * time.Second,
	}
	check := func(ctx context.Context, try int) error {
		if c.smallCheckType == smallCheckDNS {
			return c.dnsClient.Check(ctx)
		}
		ip := icmpTargetIPs[try%len(icmpTargetIPs)]
		err := c.echoer.Echo(ctx, ip)
		if c.icmpNotPermitted == nil && errors.Is(err, icmp.ErrNotPermitted) {
			c.icmpNotPermitted = new(bool)
			*c.icmpNotPermitted = true
			c.smallCheckType = smallCheckDNS
			c.logger.Infof("%s; permanently falling back to %s checks",
				err, smallCheckTypeToString(c.smallCheckType))
			return c.dnsClient.Check(ctx)
		}
		return err
	}
	return withRetries(ctx, tryTimeouts, c.logger, smallCheckTypeToString(c.smallCheckType), check)
}

func (c *Checker) fullPeriodicCheck(ctx context.Context) error {
	// 20s timeout in case the connection is under stress
	// See https://github.com/qdm12/gluetun/issues/2270
	tryTimeouts := []time.Duration{10 * time.Second, 15 * time.Second, 30 * time.Second}
	check := func(ctx context.Context, try int) error {
		tlsDialAddr := c.tlsDialAddrs[try%len(c.tlsDialAddrs)]
		return tcpTLSCheck(ctx, c.dialer, tlsDialAddr)
	}
	return withRetries(ctx, tryTimeouts, c.logger, "TCP+TLS dial", check)
}

func tcpTLSCheck(ctx context.Context, dialer *net.Dialer, targetAddress string) error {
	// TODO use mullvad API if current provider is Mullvad

	address, err := makeAddressToDial(targetAddress)
	if err != nil {
		return err
	}

	const dialNetwork = "tcp4"
	connection, err := dialer.DialContext(ctx, dialNetwork, address)
	if err != nil {
		return fmt.Errorf("dialing: %w", err)
	}

	if strings.HasSuffix(address, ":443") {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("splitting host and port: %w", err)
		}
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: host,
		}
		tlsConnection := tls.Client(connection, tlsConfig)
		err = tlsConnection.HandshakeContext(ctx)
		if err != nil {
			return fmt.Errorf("running TLS handshake: %w", err)
		}
	}

	err = connection.Close()
	if err != nil {
		return fmt.Errorf("closing connection: %w", err)
	}

	return nil
}

func makeAddressToDial(address string) (addressToDial string, err error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		addrErr := new(net.AddrError)
		ok := errors.As(err, &addrErr)
		if !ok || addrErr.Err != "missing port in address" {
			return "", fmt.Errorf("splitting host and port from address: %w", err)
		}
		host = address
		const defaultPort = "443"
		port = defaultPort
	}
	address = net.JoinHostPort(host, port)
	return address, nil
}

func withRetries(ctx context.Context, tryTimeouts []time.Duration,
	logger Logger, checkName string, check func(ctx context.Context, try int) error,
) error {
	maxTries := len(tryTimeouts)
	type errData struct {
		err        error
		durationMS int64
	}
	errs := make([]errData, maxTries)
	for i, timeout := range tryTimeouts {
		start := time.Now()
		checkCtx, cancel := context.WithTimeout(ctx, timeout)
		err := check(checkCtx, i)
		cancel()
		switch {
		case err == nil:
			return nil
		case ctx.Err() != nil:
			return fmt.Errorf("%s: %w", checkName, ctx.Err())
		}
		logger.Debugf("%s attempt %d/%d failed: %s", checkName, i+1, maxTries, err)
		errs[i].err = err
		errs[i].durationMS = time.Since(start).Round(time.Millisecond).Milliseconds()
	}

	errStrings := make([]string, len(errs))
	for i, err := range errs {
		errStrings[i] = fmt.Sprintf("attempt %d (%dms): %s", i+1, err.durationMS, err.err)
	}
	return fmt.Errorf("all check tries failed:\n\t%s", strings.Join(errStrings, "\n\t"))
}

func (c *Checker) startupCheck(ctx context.Context) error {
	// connection isn't under load yet when the checker starts, so a short
	// 6 seconds timeout suffices and provides quick enough feedback that
	// the new connection is not working. However, since the addresses to dial
	// may be multiple, we run the check in parallel. If any succeeds, the check passes.
	// This is to prevent false negatives at startup, if one of the addresses is down
	// for external reasons.
	const timeout = 6 * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	errCh := make(chan error)

	for _, address := range c.tlsDialAddrs {
		go func(addr string) {
			err := tcpTLSCheck(ctx, c.dialer, addr)
			errCh <- err
		}(address)
	}

	errs := make([]error, 0, len(c.tlsDialAddrs))
	success := false
	for range c.tlsDialAddrs {
		err := <-errCh
		if err == nil {
			success = true
			cancel()
			continue
		} else if success {
			continue // ignore canceled errors after success
		}

		c.logger.Debugf("startup check parallel attempt failed: %s", err)
		errs = append(errs, err)
	}
	if success {
		return nil
	}

	errStrings := make([]string, len(errs))
	for i, err := range errs {
		errStrings[i] = fmt.Sprintf("parallel attempt %d/%d failed: %s", i+1, len(errs), err)
	}
	return fmt.Errorf("all check tries failed: %s", strings.Join(errStrings, ", "))
}

const (
	smallCheckDNS  = "dns"
	smallCheckICMP = "icmp"
)

func smallCheckTypeToString(smallCheckType string) string {
	switch smallCheckType {
	case smallCheckICMP:
		return "ICMP echo"
	case smallCheckDNS:
		return "plain DNS over UDP"
	default:
		panic("unknown small check type: " + smallCheckType)
	}
}

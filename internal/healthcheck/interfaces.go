package healthcheck

import (
	"context"
	"net/netip"
)

//go:generate mockgen -destination=logger_mock_test.go -package healthcheck . Logger

type Logger interface {
	Debugf(format string, args ...any)
	Info(s string)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Error(s string)
}

//go:generate mockgen -destination=icmp_echoer_mock_test.go -package healthcheck . icmpEchoer

// icmpEchoer is satisfied by *icmp.Echoer. It exists so tests can inject
// a fake echoer, avoiding a dependency on raw socket permissions or
// real network access to exercise Checker's concurrency behavior.
type icmpEchoer interface {
	Reset()
	Echo(ctx context.Context, ip netip.Addr) error
}

//go:generate mockgen -destination=dns_checker_mock_test.go -package healthcheck . dnsChecker

// dnsChecker is satisfied by *dns.Client. It exists so tests can inject
// a fake DNS checker, avoiding a dependency on real network access to
// exercise Checker's concurrency behavior.
type dnsChecker interface {
	Check(ctx context.Context) error
}

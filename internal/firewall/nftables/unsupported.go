//go:build !linux

package nftables

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/qdm12/gluetun/internal/models"
)

var errNotImplemented = errors.New("nftables firewall is only supported on linux")

// Firewall is a stub for platforms other than linux.
// All methods return fmt.Errorf("%w", errNotImplemented).
type Firewall struct{}

// New creates a new stub Firewall for platforms other than linux.
func New(_ CmdRunner, _ Logger) *Firewall {
	return &Firewall{}
}

func (f *Firewall) SaveAndRestore(_ context.Context) (func(context.Context), error) {
	return nil, fmt.Errorf("%w", errNotImplemented)
}

func (f *Firewall) AcceptEstablishedRelatedTraffic(_ context.Context) error {
	return fmt.Errorf("%w", errNotImplemented)
}

func (f *Firewall) AcceptInputThroughInterface(_ context.Context, _ string) error {
	return fmt.Errorf("%w", errNotImplemented)
}

func (f *Firewall) AcceptInputToPort(_ context.Context, _ string, _ uint16, _ bool) error {
	return fmt.Errorf("%w", errNotImplemented)
}

func (f *Firewall) AcceptInputToSubnet(_ context.Context, _ string, _ netip.Prefix) error {
	return fmt.Errorf("%w", errNotImplemented)
}

func (f *Firewall) AcceptIpv6MulticastOutput(_ context.Context, _ string) error {
	return fmt.Errorf("%w", errNotImplemented)
}

func (f *Firewall) AcceptOutput(_ context.Context, _, _ string,
	_ netip.Addr, _ uint16, _ bool,
) error {
	return fmt.Errorf("%w", errNotImplemented)
}

func (f *Firewall) AcceptOutputFromIPPortToIPPort(_ context.Context, _, _ string,
	_, _ netip.AddrPort, _ bool,
) error {
	return fmt.Errorf("%w", errNotImplemented)
}

func (f *Firewall) AcceptOutputFromIPToSubnet(_ context.Context, _ string, _ netip.Addr,
	_ netip.Prefix, _ bool,
) error {
	return fmt.Errorf("%w", errNotImplemented)
}

func (f *Firewall) AcceptOutputThroughInterface(_ context.Context, _ string, _ bool) error {
	return fmt.Errorf("%w", errNotImplemented)
}

func (f *Firewall) AcceptOutputTrafficToVPN(_ context.Context, _ string,
	_ models.Connection, _ bool,
) error {
	return fmt.Errorf("%w", errNotImplemented)
}

func (f *Firewall) RedirectPort(_ context.Context, _ string, _ uint16, _ uint16, _ bool) error {
	return fmt.Errorf("%w", errNotImplemented)
}

func (f *Firewall) RunUserPostRules(_ context.Context, _ string) error {
	return fmt.Errorf("%w", errNotImplemented)
}

func (f *Firewall) SetBaseChainsPolicy(_ context.Context, _ string) error {
	return fmt.Errorf("%w", errNotImplemented)
}

func (f *Firewall) TempDropOutputTCPRST(_ context.Context, _, _ netip.AddrPort, _ int) (
	func(ctx context.Context) error, error,
) {
	return nil, fmt.Errorf("%w", errNotImplemented)
}

func (f *Firewall) Version(_ context.Context) (version string, err error) {
	return "", fmt.Errorf("%w", errNotImplemented)
}

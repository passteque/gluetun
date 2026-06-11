package cli

import (
	"context"
	"net/netip"
)

type noopFirewall struct{}

func (f *noopFirewall) AcceptOutput(_ context.Context, _, _ string, _ netip.Addr,
	_ uint16, _ bool,
) (err error) {
	return nil
}

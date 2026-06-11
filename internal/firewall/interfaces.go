package firewall

import (
	"context"
	"net/netip"
	"os/exec"

	"github.com/qdm12/gluetun/internal/models"
)

type CmdRunner interface {
	Run(cmd *exec.Cmd) (output string, err error)
}

type Logger interface {
	Debug(s string)
	Info(s string)
	Warn(s string)
	Error(s string)
}

type firewallImpl interface { //nolint:interfacebloat
	SaveAndRestore(ctx context.Context) (restore func(context.Context), err error)
	AcceptEstablishedRelatedTraffic(ctx context.Context) error
	AcceptInputThroughInterface(ctx context.Context, intf string) error
	AcceptInputToPort(ctx context.Context, intf string, port uint16, remove bool) error
	AcceptInputToSubnet(ctx context.Context, intf string, subnet netip.Prefix) error
	AcceptIpv6MulticastOutput(ctx context.Context, intf string) error
	AcceptOutput(ctx context.Context, protocol, intf string,
		ip netip.Addr, port uint16, remove bool) error
	AcceptOutputFromIPToSubnet(ctx context.Context, intf string, assignedIP netip.Addr,
		subnet netip.Prefix, remove bool) error
	AcceptOutputThroughInterface(ctx context.Context, intf string, remove bool) error
	AcceptOutputTrafficToVPN(ctx context.Context, intf string,
		connection models.Connection, remove bool) error
	RedirectPort(ctx context.Context, intf string, sourcePort,
		destinationPort uint16, remove bool) error
	RunUserPostRules(ctx context.Context, customRulesPath string) error
	SetIPv4AllPolicies(ctx context.Context, policy string) error
	SetIPv6AllPolicies(ctx context.Context, policy string) error
	TempDropOutputTCPRST(ctx context.Context, src, dst netip.AddrPort, excludeMark int) (
		revert func(ctx context.Context) error, err error)
	Version(ctx context.Context) (version string, err error)
}

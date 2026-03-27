package vpn

import (
	"context"
	"net/netip"
	"os/exec"

	"github.com/qdm12/gluetun/internal/command"
	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/netlink"
	"github.com/qdm12/gluetun/internal/pmtud/tcp"
	portforward "github.com/qdm12/gluetun/internal/portforward"
	"github.com/qdm12/gluetun/internal/provider"
	"github.com/qdm12/gluetun/internal/provider/utils"
)

type Firewall interface {
	SetVPNConnection(ctx context.Context, connection models.Connection, interfaceName string) error
	SetAllowedPort(ctx context.Context, port uint16, interfaceName string) error
	RemoveAllowedPort(ctx context.Context, port uint16) error
	tcp.Firewall
}

type Routing interface {
	VPNLocalGatewayIP(vpnInterface string) (gateway netip.Addr, err error)
	VPNRoutes(vpnIntf string) (route []netlink.Route, err error)
}

type PortForward interface {
	UpdateWith(settings portforward.Settings) (err error)
}

type OpenVPN interface {
	WriteConfig(lines []string) error
	WriteAuthFile(user, password string) error
	WriteAskPassFile(passphrase string) error
}

type Providers interface {
	Get(providerName string) provider.Provider
}

type Provider interface {
	GetConnection(selection settings.ServerSelection, ipv6Supported bool) (connection models.Connection, err error)
	OpenVPNConfig(connection models.Connection, settings settings.OpenVPN, ipv6Supported bool) (lines []string)
	Name() string
	FetchServers(ctx context.Context, minServers int) (
		servers []models.Server, err error)
}

type PortForwarder interface {
	Name() string
	PortForward(ctx context.Context, objects utils.PortForwardObjects) (
		ports []uint16, err error)
	KeepPortForward(ctx context.Context, objects utils.PortForwardObjects) (err error)
}

type Storage interface {
	FilterServers(provider string, selection settings.ServerSelection) (servers []models.Server, err error)
}

type NetLinker interface {
	AddrReplace(linkIndex uint32, addr netip.Prefix) error
	Router
	Ruler
	Linker
	IsWireguardSupported() (ok bool, err error)
}

type Router interface {
	RouteList(family uint8) (routes []netlink.Route, err error)
	RouteAdd(route netlink.Route) error
	RouteReplace(route netlink.Route) error
}

type Ruler interface {
	RuleAdd(rule netlink.Rule) error
	RuleDel(rule netlink.Rule) error
}

type Linker interface {
	LinkList() (links []netlink.Link, err error)
	LinkByName(name string) (link netlink.Link, err error)
	LinkAdd(link netlink.Link) (linkIndex uint32, err error)
	LinkDel(linkIndex uint32) error
	LinkSetUp(linkIndex uint32) error
	LinkSetDown(linkIndex uint32) error
	LinkSetMTU(linkIndex, mtu uint32) error
}

type DNSLoop interface {
	ApplyStatus(ctx context.Context, status models.LoopStatus) (
		outcome string, err error)
	GetSettings() (settings settings.DNS)
}

type PublicIPLoop interface {
	RunOnce(ctx context.Context) (err error)
	ClearData() (err error)
}

type Cmder interface {
	Start(cmd *exec.Cmd) (
		stdoutLines, stderrLines <-chan string,
		waitError <-chan error, startErr error)
	RunAndLog(ctx context.Context, command string,
		logger command.Logger) (err error)
}

type HealthChecker interface {
	SetConfig(tlsDialAddrs []string, icmpTargetIPs []netip.Addr,
		smallCheckType string, startupOnFail bool)
	Start(ctx context.Context) (runError <-chan error, err error)
	Stop() error
}

type HealthServer interface {
	SetError(err error)
}

type Service interface {
	Start() (runError <-chan error, err error)
	Stop() error
}

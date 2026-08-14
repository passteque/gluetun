package customvpn

import (
	"net/netip"
	"os/exec"

	"github.com/qdm12/gluetun/internal/netlink"
)

type CmdStarter interface {
	Start(cmd *exec.Cmd) (
		stdoutLines, stderrLines <-chan string,
		waitError <-chan error, startErr error)
}

type Logger interface {
	Info(s string)
	Error(s string)
}

type NetLinker interface {
	LinkByName(name string) (link netlink.Link, err error)
	AddrList(linkIndex uint32, family uint8) (
		addresses []netip.Prefix, err error)
}

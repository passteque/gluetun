package openvpn

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/qdm12/gluetun/internal/constants/openvpn"
)

const (
	binOpenvpn25 = "openvpn2.5"
	binOpenvpn27 = "openvpn2.7"
)

func start(ctx context.Context, starter CmdStarter, version string, flags []string) (
	stdoutLines, stderrLines <-chan string, waitError <-chan error, err error,
) {
	var bin string
	switch version {
	case openvpn.Openvpn25:
		bin = binOpenvpn25
	case openvpn.Openvpn27:
		bin = binOpenvpn27
	default:
		return nil, nil, nil, fmt.Errorf("OpenVPN version is unknown: %s", version)
	}

	args := make([]string, 0, 2+len(flags)) //nolint:mnd
	args = append(args, "--config", configPath)
	args = append(args, flags...)
	cmd := exec.CommandContext(ctx, bin, args...)
	setCmdSysProcAttr(cmd)

	return starter.Start(cmd)
}

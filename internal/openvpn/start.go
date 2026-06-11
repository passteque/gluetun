package openvpn

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/qdm12/gluetun/internal/constants/openvpn"
)

const (
	binOpenvpn25 = "openvpn2.5"
	binOpenvpn26 = "openvpn2.6"
)

func start(ctx context.Context, starter CmdStarter, version string, flags []string) (
	stdoutLines, stderrLines <-chan string, waitError <-chan error, err error,
) {
	var bin string
	switch version {
	case openvpn.Openvpn25:
		bin = binOpenvpn25
	case openvpn.Openvpn26:
		bin = binOpenvpn26
	default:
		return nil, nil, nil, fmt.Errorf("OpenVPN version is unknown: %s", version)
	}

	args := []string{"--config", configPath}
	args = append(args, flags...)
	cmd := exec.CommandContext(ctx, bin, args...)
	setCmdSysProcAttr(cmd)

	return starter.Start(cmd)
}

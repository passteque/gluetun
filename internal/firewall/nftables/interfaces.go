package nftables

import "os/exec"

type CmdRunner interface {
	Run(cmd *exec.Cmd) (output string, err error)
}

type Logger interface {
	Warnf(format string, args ...any)
}

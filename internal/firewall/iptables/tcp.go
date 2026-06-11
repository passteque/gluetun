package iptables

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
)

type tcpFlags struct {
	mask       []tcpFlag
	comparison []tcpFlag
}

type tcpFlag uint8

const (
	tcpFlagFIN tcpFlag = 1 << iota
	tcpFlagSYN
	tcpFlagRST
	tcpFlagPSH
	tcpFlagACK
	tcpFlagURG
	tcpFlagECE
	tcpFlagCWR
)

func (f tcpFlag) String() string {
	switch f {
	case tcpFlagFIN:
		return "FIN"
	case tcpFlagSYN:
		return "SYN"
	case tcpFlagRST:
		return "RST"
	case tcpFlagPSH:
		return "PSH"
	case tcpFlagACK:
		return "ACK"
	case tcpFlagURG:
		return "URG"
	case tcpFlagECE:
		return "ECE"
	case tcpFlagCWR:
		return "CWR"
	default:
		panic(fmt.Sprintf("unknown TCP flag: %d", f))
	}
}

func parseTCPFlag(s string) (tcpFlag, error) {
	allFlags := []tcpFlag{
		tcpFlagFIN, tcpFlagSYN, tcpFlagRST, tcpFlagPSH,
		tcpFlagACK, tcpFlagURG, tcpFlagECE, tcpFlagCWR,
	}
	for _, flag := range allFlags {
		if s == fmt.Sprintf("%#02x", uint8(flag)) || s == flag.String() {
			return flag, nil
		}
	}
	return 0, fmt.Errorf("unknown TCP flag: %s", s)
}

var ErrMarkMatchModuleMissing = errors.New("kernel is missing the mark module libxt_mark.so")

// TempDropOutputTCPRST temporarily drops outgoing TCP RST packets to the specified address and port,
// for any TCP packets not marked with the excludeMark given.
// This is necessary for TCP path MTU discovery to work, as the kernel will try to terminate the connection
// by sending a TCP RST packet, although we want to handle the connection manually.
func (c *Config) TempDropOutputTCPRST(ctx context.Context,
	src, dst netip.AddrPort, excludeMark int) (
	revert func(ctx context.Context) error, err error,
) {
	_, err = os.Stat("/usr/lib/xtables/libxt_mark.so")
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w", ErrMarkMatchModuleMissing)
	}

	const template = "%s OUTPUT -p tcp -s %s --sport %d -d %s --dport %d " +
		"--tcp-flags RST RST -m mark ! --mark %d -j DROP" //nolint:dupword
	instruction := fmt.Sprintf(template, "--append", src.Addr(), src.Port(), dst.Addr(), dst.Port(), excludeMark)
	revertInstruction := fmt.Sprintf(template, "--delete", src.Addr(), src.Port(), dst.Addr(), dst.Port(), excludeMark)
	run := c.runIptablesInstruction
	if dst.Addr().Is6() {
		run = c.runIP6tablesInstruction
	}
	revert = func(ctx context.Context) error {
		return run(ctx, revertInstruction)
	}
	err = run(ctx, instruction)
	if err != nil {
		return nil, fmt.Errorf("running instruction: %w", err)
	}
	return revert, nil
}

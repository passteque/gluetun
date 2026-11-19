package netlink

import (
	"github.com/qdm12/gluetun/internal/mod"
	"github.com/qdm12/log"
)

type NetLink struct {
	debugLogger DebugLogger

	// Fixed state
	conntrackNetlink bool
}

func New(debugLogger DebugLogger) *NetLink {
	conntrackNetlink := mod.Probe("nf_conntrack_netlink") == nil
	return &NetLink{
		debugLogger:      debugLogger,
		conntrackNetlink: conntrackNetlink,
	}
}

func (n *NetLink) PatchLoggerLevel(level log.Level) {
	n.debugLogger.Patch(log.SetLevel(level))
}

//go:build linux

package netlink

import "golang.org/x/sys/unix"

// Route types from the Linux kernel rtnetlink API, see
// include/uapi/linux/rtnetlink.h.
const (
	routeTypeUnreachable uint8 = unix.RTN_UNREACHABLE
	routeTypeProhibit    uint8 = unix.RTN_PROHIBIT
	routeTypeBlackhole   uint8 = unix.RTN_BLACKHOLE
)

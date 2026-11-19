//go:build !linux

package netlink

import "errors"

var ErrConntrackNetlinkNotSupported = errors.New("error not implemented")

func (n *NetLink) FlushConntrack() error {
	panic("not implemented")
}

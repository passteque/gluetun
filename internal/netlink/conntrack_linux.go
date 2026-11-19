package netlink

import (
	"errors"
	"fmt"

	"github.com/mdlayher/netlink"
	"github.com/ti-mo/netfilter"
	"golang.org/x/sys/unix"
)

var ErrConntrackNetlinkNotSupported = errors.New("nf_conntrack_netlink is not supported by the kernel")

func (n *NetLink) FlushConntrack() error {
	conn, err := netfilter.Dial(nil)
	if err != nil {
		if !n.conntrackNetlink {
			err = fmt.Errorf("%w: %w", err, ErrConntrackNetlinkNotSupported)
		}
		return fmt.Errorf("dialing netfilter: %w", err)
	}
	defer conn.Close()

	const ipCtnlMsgCtDelete = netfilter.MessageType(2)
	header := netfilter.Header{
		SubsystemID: netfilter.NFSubsysCTNetlink,
		MessageType: ipCtnlMsgCtDelete,
		Family:      unix.AF_UNSPEC,
		Flags:       netlink.Request | netlink.Acknowledge,
	}
	request, err := netfilter.MarshalNetlink(header, nil)
	if err != nil {
		return fmt.Errorf("encoding netlink request: %w", err)
	}

	_, err = conn.Query(request)
	if err != nil {
		if !n.conntrackNetlink {
			err = fmt.Errorf("%w: %w", err, ErrConntrackNetlinkNotSupported)
		}
		return fmt.Errorf("querying netlink request: %w", err)
	}
	return nil
}

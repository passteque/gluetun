package icmp

import (
	"golang.org/x/sys/unix"
)

func setDontFragment(fd uintptr, ipv4 bool) (err error) {
	fdInt := int(fd) //nolint:gosec
	if ipv4 {
		return unix.SetsockoptInt(fdInt, unix.IPPROTO_IP,
			unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_PROBE)
	}
	return unix.SetsockoptInt(fdInt, unix.IPPROTO_IPV6,
		unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_PROBE)
}

package amneziawg

import (
	"net/netip"

	"github.com/qdm12/gluetun/internal/netlink"
)

//go:generate mockgen -destination=netlinker_mock_test.go -package amneziawg . NetLinker

type NetLinker interface {
	AddrReplace(linkIndex uint32, addr netip.Prefix) error
	Router
	Ruler
	Linker
	IsWireguardSupported() (ok bool, err error)
}

type Router interface {
	RouteList(family uint8) (routes []netlink.Route, err error)
	RouteAdd(route netlink.Route) error
}

type Ruler interface {
	RuleAdd(rule netlink.Rule) error
	RuleDel(rule netlink.Rule) error
}

type Linker interface {
	LinkAdd(link netlink.Link) (linkIndex uint32, err error)
	LinkList() (links []netlink.Link, err error)
	LinkByName(name string) (link netlink.Link, err error)
	LinkSetUp(linkIndex uint32) error
	LinkSetDown(linkIndex uint32) error
	LinkDel(linkIndex uint32) error
}

package netlink

import (
	"fmt"
	"net/netip"

	"github.com/jsimonetti/rtnetlink"
)

type Route struct {
	LinkIndex uint32
	Dst       netip.Prefix
	Src       netip.Prefix
	Gw        netip.Addr
	Priority  uint32
	Family    uint8
	Table     uint32
	Type      uint8
	Scope     uint8
	Proto     uint8
	AdvMSS    uint32
}

func (r *Route) fromMessage(message rtnetlink.RouteMessage) {
	table := uint32(message.Table)
	if table == 0 || table == rtTableCompat {
		table = message.Attributes.Table
	}
	r.LinkIndex = message.Attributes.OutIface
	r.Dst = ipAndLengthToPrefix(&message.Attributes.Dst, message.DstLength)
	r.Src = ipAndLengthToPrefix(&message.Attributes.Src, message.SrcLength)
	r.Gw = netIPToNetipAddress(message.Attributes.Gateway)
	r.Priority = message.Attributes.Priority
	r.Family = message.Family
	r.Table = table
	r.Type = message.Type
	r.Scope = message.Scope
	r.Proto = message.Protocol
	if metrics := message.Attributes.Metrics; metrics != nil {
		r.AdvMSS = metrics.AdvMSS
	}
}

func (r Route) message() *rtnetlink.RouteMessage {
	dst, dstLength := prefixToIPAndLength(r.Dst)
	src, srcLength := prefixToIPAndLength(r.Src)
	var table uint8
	var extendedTable uint32
	if r.Table <= uint32(^uint8(0)) {
		table = uint8(r.Table)
	} else {
		table = rtTableCompat
		extendedTable = r.Table
	}
	message := &rtnetlink.RouteMessage{
		Family:    r.Family,
		DstLength: dstLength,
		SrcLength: srcLength,
		Table:     table,
		Type:      r.Type,
		Scope:     r.Scope,
		Protocol:  r.Proto,
		Attributes: rtnetlink.RouteAttributes{
			OutIface: r.LinkIndex,
			Gateway:  netipAddrToNetIP(r.Gw),
			Priority: r.Priority,
			Table:    extendedTable,
		},
	}
	if src != nil { // src is optional
		message.Attributes.Src = *src
	}
	if dst != nil {
		message.Attributes.Dst = *dst
	}
	if r.AdvMSS != 0 {
		if message.Attributes.Metrics == nil {
			message.Attributes.Metrics = &rtnetlink.RouteMetrics{}
		}
		message.Attributes.Metrics.AdvMSS = r.AdvMSS
	}
	return message
}

func (n *NetLink) RouteList(family uint8) (routes []Route, err error) {
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("dialing netlink: %w", err)
	}
	defer conn.Close()

	routeMessages, err := conn.Route.List()
	if err != nil {
		return nil, fmt.Errorf("listing interfaces: %w", err)
	}

	routes = make([]Route, 0, len(routeMessages))
	for _, routeMessage := range routeMessages {
		if family != FamilyAll && routeMessage.Family != family {
			continue
		}
		var route Route
		route.fromMessage(routeMessage)
		routes = append(routes, route)
	}
	return routes, nil
}

func (n *NetLink) RouteAdd(route Route) error {
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return fmt.Errorf("dialing netlink: %w", err)
	}
	defer conn.Close()

	return conn.Route.Add(route.message())
}

func (n *NetLink) RouteDel(route Route) error {
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return fmt.Errorf("dialing netlink: %w", err)
	}
	defer conn.Close()

	return conn.Route.Delete(route.message())
}

func (n *NetLink) RouteReplace(route Route) error {
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return fmt.Errorf("dialing netlink: %w", err)
	}
	defer conn.Close()

	return conn.Route.Replace(route.message())
}

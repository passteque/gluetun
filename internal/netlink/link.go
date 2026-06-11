package netlink

import (
	"fmt"

	"github.com/jsimonetti/rtnetlink"
)

type DeviceType uint16

type Link struct {
	Index       uint32
	Name        string
	DeviceType  DeviceType
	VirtualType string
	MTU         uint32
}

func (n *NetLink) LinkList() (links []Link, err error) {
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("dialing netlink: %w", err)
	}
	defer conn.Close()

	linkMessages, err := conn.Link.List()
	if err != nil {
		return nil, fmt.Errorf("listing interfaces: %w", err)
	}

	links = make([]Link, len(linkMessages))
	for i, message := range linkMessages {
		virtualType := ""
		if message.Attributes.Info != nil {
			virtualType = message.Attributes.Info.Kind
		}
		links[i] = Link{
			Index:       message.Index,
			Name:        message.Attributes.Name,
			DeviceType:  DeviceType(message.Type),
			VirtualType: virtualType,
			MTU:         message.Attributes.MTU,
		}
	}

	return links, nil
}

func (n *NetLink) LinkByName(name string) (link Link, err error) {
	links, err := n.LinkList()
	if err != nil {
		return Link{}, fmt.Errorf("listing links: %w", err)
	}

	for _, link := range links {
		if link.Name == name {
			return link, nil
		}
	}

	return Link{}, fmt.Errorf("link not found: for name %s", name)
}

func (n *NetLink) LinkByIndex(index uint32) (link Link, err error) {
	links, err := n.LinkList()
	if err != nil {
		return Link{}, fmt.Errorf("listing links: %w", err)
	}

	for _, link = range links {
		if link.Index == index {
			return link, nil
		}
	}

	return Link{}, fmt.Errorf("link not found: for index %d", index)
}

func (n *NetLink) LinkAdd(link Link) (linkIndex uint32, err error) {
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return 0, fmt.Errorf("dialing netlink: %w", err)
	}
	defer conn.Close()

	tx := &rtnetlink.LinkMessage{
		Type: uint16(link.DeviceType),
		Attributes: &rtnetlink.LinkAttributes{
			MTU:  link.MTU,
			Name: link.Name,
		},
	}
	if link.VirtualType != "" {
		tx.Attributes.Info = &rtnetlink.LinkInfo{
			Kind: link.VirtualType,
		}
	}

	err = conn.Link.New(tx)
	if err != nil {
		return 0, fmt.Errorf("creating new link: %w", err)
	}

	linkMessages, err := conn.Link.List()
	if err != nil {
		return 0, fmt.Errorf("listing links: %w", err)
	}
	for _, linkMessage := range linkMessages {
		if linkMessage.Attributes.Name == link.Name {
			return linkMessage.Index, nil
		}
	}

	return 0, fmt.Errorf("link not found: matching name %s", link.Name)
}

func (n *NetLink) LinkDel(linkIndex uint32) (err error) {
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return fmt.Errorf("dialing netlink: %w", err)
	}
	defer conn.Close()

	return conn.Link.Delete(linkIndex)
}

func (n *NetLink) LinkSetUp(linkIndex uint32) (err error) {
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return fmt.Errorf("dialing netlink: %w", err)
	}
	defer conn.Close()

	rx, err := conn.Link.Get(linkIndex)
	if err != nil {
		return fmt.Errorf("getting link: %w", err)
	}
	tx := &rtnetlink.LinkMessage{
		Type:   rx.Type,
		Index:  linkIndex,
		Flags:  iffUp,
		Change: iffUp,
	}
	return conn.Link.Set(tx)
}

func (n *NetLink) LinkSetDown(linkIndex uint32) (err error) {
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return fmt.Errorf("dialing netlink: %w", err)
	}
	defer conn.Close()

	linkInfo, err := conn.Link.Get(linkIndex)
	if err != nil {
		return fmt.Errorf("getting link: %w", err)
	}
	message := &rtnetlink.LinkMessage{
		Type:   linkInfo.Type,
		Index:  linkIndex,
		Flags:  0,
		Change: iffUp,
	}
	return conn.Link.Set(message)
}

func (n *NetLink) LinkSetMTU(linkIndex, mtu uint32) error {
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return fmt.Errorf("dialing netlink: %w", err)
	}
	defer conn.Close()

	message := &rtnetlink.LinkMessage{
		Index: linkIndex,
		Attributes: &rtnetlink.LinkAttributes{
			MTU: mtu,
		},
	}

	err = conn.Link.Set(message)
	if err != nil {
		return fmt.Errorf("setting MTU to %d for link at index %d: %w",
			mtu, linkIndex, err)
	}

	return nil
}

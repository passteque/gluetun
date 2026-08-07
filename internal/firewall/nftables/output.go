package nftables

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/qdm12/gluetun/internal/models"
)

// cidrMask returns the binary mask for a CIDR prefix length.
//
//nolint:mnd
func cidrMask(bits, addrLen int) []byte {
	result := make([]byte, addrLen)
	fullBytes := bits / 8
	remainingBits := bits % 8
	for i := range fullBytes {
		result[i] = 0xff
	}
	if remainingBits > 0 {
		result[fullBytes] = byte((0xff << (8 - remainingBits)) & 0xff)
	}
	return result
}

func (f *Firewall) AcceptIpv6MulticastOutput(_ context.Context, intf string) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("creating nftables connection: %w", err)
	}

	table, _, _, outputChain := setupFilterWithBaseChains(conn)

	const maxExprsLen = 6
	exprs := make([]expr.Any, 0, maxExprsLen)

	if intf != "" && intf != "*" {
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(intf + "\x00")},
		)
	}

	// ff02::1:ff00:0/104 mask is 13 bytes of 0xff
	mask := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00,
	}
	addr := []byte{
		0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01, 0xff, 0x00, 0x00, 0x00,
	}

	exprs = append(exprs,
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       24, //nolint:mnd // IPv6 Destination Address offset
			Len:          16, //nolint:mnd
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            16, //nolint:mnd
			Mask:           mask,
			Xor:            []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     addr,
		},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)

	rule := &nftables.Rule{
		Table: table,
		Chain: outputChain,
		Exprs: exprs,
	}

	conn.AddRule(rule)

	err = conn.Flush()
	if err != nil {
		return fmt.Errorf("flushing: %w", err)
	}

	return nil
}

func (f *Firewall) AcceptOutputTrafficToVPN(_ context.Context, defaultInterface string,
	connection models.Connection, remove bool,
) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("creating nftables connection: %w", err)
	}

	table, _, _, outputChain := setupFilterWithBaseChains(conn)

	// Prepare the destination IP and port
	const maxExprsLen = 7
	exprs := make([]expr.Any, 0, maxExprsLen)

	// Interface filter
	if defaultInterface != "" && defaultInterface != "*" {
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(defaultInterface + "\x00")},
		)
	}

	// Destination IP address
	if connection.IP.Is4() {
		exprs = append(exprs,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       16, //nolint:mnd // IPv4 destination address offset
				Len:          4,  //nolint:mnd
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     connection.IP.AsSlice(),
			},
		)
	} else { // IPv6
		exprs = append(exprs,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       24, //nolint:mnd// IPv6 destination address offset
				Len:          16, //nolint:mnd
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     connection.IP.AsSlice(),
			},
		)
	}

	// Protocol (tcp or udp)
	var protocolByte uint8
	switch connection.Protocol {
	case "tcp", "tcp-client":
		protocolByte = 6 // TCP
	case "udp":
		protocolByte = 17 // UDP
	default:
		return fmt.Errorf("unsupported protocol: %s", connection.Protocol)
	}

	exprs = append(exprs,
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{protocolByte},
		},
	)

	// Destination port
	portBytes := []byte{byte(connection.Port >> 8), byte(connection.Port)} //nolint:mnd,gosec
	exprs = append(exprs,
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2, //nolint:mnd// destination port offset
			Len:          2, //nolint:mnd
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     portBytes,
		},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)

	rule := &nftables.Rule{
		Table: table,
		Chain: outputChain,
		Exprs: exprs,
	}

	if !remove {
		conn.AddRule(rule)
		f.rules = append(f.rules, rule)
	} else {
		err = f.deleteRule(conn, rule)
		if err != nil {
			return fmt.Errorf("deleting rule: %w", err)
		}
	}

	err = conn.Flush()
	if err != nil {
		if !remove {
			f.rules = f.rules[:len(f.rules)-1]
		}
		return fmt.Errorf("flushing: %w", err)
	}

	return nil
}

func (f *Firewall) AcceptOutput(_ context.Context, protocol, intf string,
	ip netip.Addr, port uint16, remove bool,
) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("creating nftables connection: %w", err)
	}

	table, _, _, outputChain := setupFilterWithBaseChains(conn)

	const maxExprsLen = 7
	exprs := make([]expr.Any, 0, maxExprsLen)

	if intf != "" && intf != "*" {
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(intf + "\x00")},
		)
	}

	if ip.Is4() {
		exprs = append(exprs,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       16, //nolint:mnd
				Len:          4,  //nolint:mnd
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ip.AsSlice(),
			},
		)
	} else {
		exprs = append(exprs,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       24, //nolint:mnd
				Len:          16, //nolint:mnd
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ip.AsSlice(),
			},
		)
	}

	var protocolByte uint8
	switch protocol {
	case "tcp":
		protocolByte = 6
	case "udp":
		protocolByte = 17
	default:
		return fmt.Errorf("unsupported protocol: %s", protocol)
	}

	exprs = append(exprs,
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       3, //nolint:mnd
			Len:          1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{protocolByte},
		},
	)

	portBytes := []byte{byte(port >> 8), byte(port)} //nolint:mnd,gosec
	exprs = append(exprs,
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2, //nolint:mnd
			Len:          2, //nolint:mnd
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     portBytes,
		},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)

	rule := &nftables.Rule{
		Table: table,
		Chain: outputChain,
		Exprs: exprs,
	}

	if !remove {
		conn.AddRule(rule)
		f.rules = append(f.rules, rule)
	} else {
		err = f.deleteRule(conn, rule)
		if err != nil {
			return fmt.Errorf("deleting rule: %w", err)
		}
	}

	err = conn.Flush()
	if err != nil {
		if !remove {
			f.rules = f.rules[:len(f.rules)-1]
		}
		return fmt.Errorf("flushing: %w", err)
	}

	return nil
}

func (f *Firewall) AcceptOutputFromIPPortToIPPort(_ context.Context, protocol, intf string,
	source, destination netip.AddrPort, remove bool,
) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("creating nftables connection: %w", err)
	}

	table, _, _, outputChain := setupFilterWithBaseChains(conn)

	const maxExprsLen = 10
	exprs := make([]expr.Any, 0, maxExprsLen)

	if intf != "" && intf != "*" {
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(intf + "\x00")},
		)
	}

	if source.Addr().Is4() {
		exprs = append(exprs,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12, //nolint:mnd
				Len:          4,  //nolint:mnd
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     source.Addr().AsSlice(),
			},
		)
	} else {
		exprs = append(exprs,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       8,  //nolint:mnd
				Len:          16, //nolint:mnd
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     source.Addr().AsSlice(),
			},
		)
	}

	if destination.Addr().Is4() {
		exprs = append(exprs,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       16, //nolint:mnd
				Len:          4,  //nolint:mnd
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     destination.Addr().AsSlice(),
			},
		)
	} else {
		exprs = append(exprs,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       24, //nolint:mnd
				Len:          16, //nolint:mnd
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     destination.Addr().AsSlice(),
			},
		)
	}

	var protocolByte uint8
	switch protocol {
	case "tcp":
		protocolByte = 6
	case "udp":
		protocolByte = 17
	default:
		return fmt.Errorf("unsupported protocol: %s", protocol)
	}

	exprs = append(exprs,
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{protocolByte},
		},
	)

	sourcePortBytes := []byte{byte(source.Port() >> 8), byte(source.Port())}                //nolint:mnd,gosec
	destinationPortBytes := []byte{byte(destination.Port() >> 8), byte(destination.Port())} //nolint:mnd,gosec
	exprs = append(exprs,
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       0,
			Len:          2, //nolint:mnd
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     sourcePortBytes,
		},
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2, //nolint:mnd
			Len:          2, //nolint:mnd
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     destinationPortBytes,
		},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)

	rule := &nftables.Rule{
		Table: table,
		Chain: outputChain,
		Exprs: exprs,
	}

	if !remove {
		conn.AddRule(rule)
		f.rules = append(f.rules, rule)
	} else {
		err = f.deleteRule(conn, rule)
		if err != nil {
			return fmt.Errorf("deleting rule: %w", err)
		}
	}

	err = conn.Flush()
	if err != nil {
		if !remove {
			f.rules = f.rules[:len(f.rules)-1]
		}
		return fmt.Errorf("flushing: %w", err)
	}

	return nil
}

func (f *Firewall) AcceptOutputFromIPToSubnet(_ context.Context, intf string, assignedIP netip.Addr,
	subnet netip.Prefix, remove bool,
) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("creating nftables connection: %w", err)
	}

	table, _, _, outputChain := setupFilterWithBaseChains(conn)

	const maxExprsLen = 8
	exprs := make([]expr.Any, 0, maxExprsLen)

	if intf != "" && intf != "*" {
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(intf + "\x00")},
		)
	}

	if assignedIP.Is4() {
		exprs = append(exprs,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12, //nolint:mnd
				Len:          4,  //nolint:mnd
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     assignedIP.AsSlice(),
			},
		)
	} else {
		exprs = append(exprs,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       8,  //nolint:mnd
				Len:          16, //nolint:mnd
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     assignedIP.AsSlice(),
			},
		)
	}

	if subnet.Addr().Is4() {
		mask := cidrMask(subnet.Bits(), 4) //nolint:mnd
		networkAddr := subnet.Masked().Addr().AsSlice()
		exprs = append(exprs,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       16, //nolint:mnd
				Len:          4,  //nolint:mnd
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4, //nolint:mnd
				Mask:           mask,
				Xor:            []byte{0, 0, 0, 0},
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     networkAddr,
			},
		)
	} else {
		mask := cidrMask(subnet.Bits(), 16) //nolint:mnd
		networkAddr := subnet.Masked().Addr().AsSlice()
		exprs = append(exprs,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       24, //nolint:mnd
				Len:          16, //nolint:mnd
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            16, //nolint:mnd
				Mask:           mask,
				Xor:            []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     networkAddr,
			},
		)
	}

	exprs = append(exprs,
		&expr.Verdict{Kind: expr.VerdictAccept},
	)

	rule := &nftables.Rule{
		Table: table,
		Chain: outputChain,
		Exprs: exprs,
	}

	if !remove {
		conn.AddRule(rule)
		f.rules = append(f.rules, rule)
	} else {
		err = f.deleteRule(conn, rule)
		if err != nil {
			return fmt.Errorf("deleting rule: %w", err)
		}
	}

	err = conn.Flush()
	if err != nil {
		if !remove {
			f.rules = f.rules[:len(f.rules)-1]
		}
		return fmt.Errorf("flushing: %w", err)
	}

	return nil
}

func (f *Firewall) AcceptOutputThroughInterface(_ context.Context, intf string, remove bool) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("creating nftables connection: %w", err)
	}

	table, _, _, outputChain := setupFilterWithBaseChains(conn)

	const maxExprsLen = 3
	exprs := make([]expr.Any, 0, maxExprsLen)

	if intf != "" && intf != "*" {
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(intf + "\x00")},
		)
	}

	exprs = append(exprs,
		&expr.Verdict{Kind: expr.VerdictAccept},
	)

	rule := &nftables.Rule{
		Table: table,
		Chain: outputChain,
		Exprs: exprs,
	}

	if !remove {
		conn.AddRule(rule)
		f.rules = append(f.rules, rule)
	} else {
		err = f.deleteRule(conn, rule)
		if err != nil {
			return fmt.Errorf("deleting rule: %w", err)
		}
	}

	err = conn.Flush()
	if err != nil {
		if !remove {
			f.rules = f.rules[:len(f.rules)-1]
		}
		return fmt.Errorf("flushing: %w", err)
	}

	return nil
}

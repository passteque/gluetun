package icmp

import (
	"bytes"
	"fmt"

	"golang.org/x/net/icmp"
)

func checkMTU(mtu, minMTU, physicalLinkMTU uint32) (err error) {
	switch {
	case mtu < minMTU:
		return fmt.Errorf("ICMP Next Hop MTU is too low: %d", mtu)
	case mtu > physicalLinkMTU:
		return fmt.Errorf("ICMP Next Hop MTU is too high: %d is larger than physical link MTU %d", mtu, physicalLinkMTU)
	default:
		return nil
	}
}

func checkInvokingReplyIDMatch(icmpProtocol int, received []byte,
	outboundMessage *icmp.Message,
) (match bool, err error) {
	inboundMessage, err := icmp.ParseMessage(icmpProtocol, received)
	if err != nil {
		return false, fmt.Errorf("parsing invoking packet: %w", err)
	}
	inboundBody, ok := inboundMessage.Body.(*icmp.Echo)
	if !ok {
		return false, fmt.Errorf("ICMP body type is not supported: %T", inboundMessage.Body)
	}
	outboundBody := outboundMessage.Body.(*icmp.Echo) //nolint:forcetypeassert
	return inboundBody.ID == outboundBody.ID, nil
}

func checkEchoReply(icmpProtocol int, received []byte,
	outboundMessage *icmp.Message, truncatedBody bool,
) (err error) {
	inboundMessage, err := icmp.ParseMessage(icmpProtocol, received)
	if err != nil {
		return fmt.Errorf("parsing invoking packet: %w", err)
	}
	inboundBody, ok := inboundMessage.Body.(*icmp.Echo)
	if !ok {
		return fmt.Errorf("ICMP body type is not supported: %T", inboundMessage.Body)
	}
	outboundBody := outboundMessage.Body.(*icmp.Echo) //nolint:forcetypeassert
	if inboundBody.ID != outboundBody.ID {
		return fmt.Errorf("ICMP id mismatch: sent id %d and received id %d",
			outboundBody.ID, inboundBody.ID)
	}
	err = checkEchoBodies(outboundBody.Data, inboundBody.Data, truncatedBody)
	if err != nil {
		return fmt.Errorf("checking sent and received bodies: %w", err)
	}
	return nil
}

func checkEchoBodies(sent, received []byte, receivedTruncated bool) (err error) {
	if len(received) > len(sent) {
		return fmt.Errorf("ICMP data mismatch: sent %d bytes and received %d bytes",
			len(sent), len(received))
	}
	if receivedTruncated {
		sent = sent[:len(received)]
	}
	if !bytes.Equal(received, sent) {
		return fmt.Errorf("ICMP data mismatch: sent %x and received %x",
			sent, received)
	}
	return nil
}

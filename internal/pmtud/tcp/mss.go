package tcp

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/qdm12/gluetun/internal/firewall/iptables"
	"github.com/qdm12/gluetun/internal/pmtud/constants"
	"github.com/qdm12/gluetun/internal/pmtud/ip"
)

// findHighestMSSDestination finds the destination with the highest
// MSS amongst the provided destinations.
func findHighestMSSDestination(ctx context.Context, familyToFD map[int]fileDescriptor,
	dsts []netip.AddrPort, excludeMark int, maxPossibleMTU uint32,
	timeout time.Duration, tracker *tracker, fw Firewall, logger Logger) (
	dst netip.AddrPort, mss uint32, err error,
) {
	type result struct {
		dst netip.AddrPort
		mss uint32
		err error
	}
	resultCh := make(chan result)

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for _, dst := range dsts {
		go func(dst netip.AddrPort) {
			fd := familyToFD[ip.GetFamily(dst)]
			mss, err := findMSS(ctx, fd, dst, excludeMark, tracker, fw, logger)
			resultCh <- result{dst: dst, mss: mss, err: err}
		}(dst)
	}

	for range dsts {
		result := <-resultCh
		if result.err != nil {
			switch {
			case err != nil: // error already occurred for another findMSS goroutine
			case errors.Is(result.err, iptables.ErrMarkMatchModuleMissing):
				err = fmt.Errorf("finding MSS for %s: %w", result.dst, result.err)
			default: // another error not due to the match module missing
				logger.Debugf("finding MSS for %s failed: %s", result.dst, result.err)
			}
			continue
		}
		ipHeaderLength := ip.HeaderLength(result.dst.Addr().Is4())
		maxNeededMSS := maxPossibleMTU - ipHeaderLength - constants.BaseTCPHeaderLength
		switch {
		case result.mss >= maxNeededMSS:
			logger.Debugf("%s has an MSS of %d bytes which is equal or higher than "+
				"the maximum needed MSS of %d bytes for the maximum possible MTU of %d bytes",
				result.dst, result.mss, maxNeededMSS, maxPossibleMTU)
			return result.dst, result.mss, nil
		case result.mss > mss:
			mss = result.mss
			dst = result.dst
		}
	}

	if mss == 0 { // no MSS found for any destination
		return netip.AddrPort{}, 0, fmt.Errorf("all %d TCP servers are unreachable", len(dsts))
	}

	maxPossibleMTU = ip.HeaderLength(dst.Addr().Is4()) + constants.BaseTCPHeaderLength + mss
	logger.Debugf("server %s has the highest MSS %d allowing to test the MTU up to %d",
		dst, mss, maxPossibleMTU)
	return dst, mss, nil
}

func findMSS(ctx context.Context, fd fileDescriptor, dst netip.AddrPort,
	excludeMark int, tracker *tracker, firewall Firewall, logger Logger) (
	mss uint32, err error,
) {
	const proto = constants.IPPROTO_TCP
	src, cleanup, err := ip.SrcAddr(dst, proto)
	if err != nil {
		return 0, fmt.Errorf("getting source address: %w", err)
	}
	defer cleanup()

	revert, err := firewall.TempDropOutputTCPRST(ctx, src, dst, excludeMark)
	if err != nil {
		return 0, fmt.Errorf("temporarily dropping outgoing TCP RST packets: %w", err)
	}
	defer func() {
		// we don't want to skip reverting the firewall changes
		// even if the context is already expired, so we use a
		// background context here.
		err := revert(context.Background())
		if err != nil {
			logger.Warnf("reverting firewall changes: %s", err)
		}
	}()

	ch := make(chan []byte)
	abort := make(chan struct{})
	defer close(abort)
	tracker.register(src.Port(), dst.Port(), ch, abort)
	defer tracker.unregister(src.Port(), dst.Port())

	dstSockAddr := makeSockAddr(dst)

	synPacket, synSeq := createSYNPacket(src, dst, 0)
	const sendToFlags = 0
	err = sendTo(fd, synPacket, sendToFlags, dstSockAddr)
	if err != nil {
		return 0, fmt.Errorf("sending SYN packet: %w", err)
	}

	var reply []byte
	select {
	case <-ctx.Done():
		_ = sendRST(fd, src, dst, synSeq+1)
		return 0, ctx.Err()
	case reply = <-ch:
	}

	replyHeader, err := parseTCPHeader(reply)
	switch {
	case err != nil:
		return 0, fmt.Errorf("parsing reply TCP header: %w", err)
	case replyHeader.typ != packetTypeSYNACK:
		return 0, fmt.Errorf("TCP packet is not a SYN-ACK: unexpected packet type %s", replyHeader.typ)
	case replyHeader.ack != synSeq+1:
		return 0, fmt.Errorf("TCP SYN-ACK ACK number %d does not match expected value %d",
			replyHeader.ack, synSeq+1)
	case replyHeader.options.mss == 0:
		return 0, errors.New("MSS option not found in reply")
	}

	err = sendRST(fd, src, dst, replyHeader.ack)
	if err != nil {
		return 0, fmt.Errorf("sending RST packet: %w", err)
	}

	return replyHeader.options.mss, nil
}

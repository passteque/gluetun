package tcp

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/qdm12/gluetun/internal/pmtud/constants"
	"github.com/qdm12/gluetun/internal/pmtud/ip"
	"github.com/qdm12/gluetun/internal/pmtud/test"
)

type testUnit struct {
	mtu uint32
	ok  bool
}

const excludeMark = 4545

// PathMTUDiscover first finds the destination TCP server with the highest
// available MSS, in order to be able to test the highest possible MTU.
// If a server has an MSS larger than maxPossibleMTU, this one is used.
// It then performs a binary search of the MTU between minMTU and maxPossibleMTU,
// by sending IP packets with the Don't Fragment bit set and checking if they
// are received or not, exploiting the stateful nature of TCP to be able to
// correlate replies to the sent packets.
// Note all dsts must be of the same IP family (all IPv4 or all IPv6).
func PathMTUDiscover(ctx context.Context, dsts []netip.AddrPort,
	minMTU, maxPossibleMTU uint32, tryTimeout time.Duration,
	firewall Firewall, logger Logger,
) (mtu uint32, err error) {
	families := ip.GetFamilies(dsts)
	familyToFD, stop, err := startRawSockets(families, excludeMark)
	if err != nil {
		return 0, fmt.Errorf("starting raw sockets: %w", err)
	}
	defer stop()

	tracker := newTracker(familyToFD)

	trackerCtx, trackerCancel := context.WithCancel(ctx)
	defer trackerCancel()
	trackerErrCh := make(chan error)
	go func() {
		trackerErrCh <- tracker.listen(trackerCtx)
	}()

	type mssResult struct {
		dst netip.AddrPort
		mss uint32
		err error
	}
	mssResultCh := make(chan mssResult)

	mssCtx, mssCancel := context.WithTimeout(ctx, tryTimeout)
	defer mssCancel()
	go func() {
		dst, mss, err := findHighestMSSDestination(mssCtx, familyToFD, dsts, excludeMark,
			maxPossibleMTU, tryTimeout, tracker, firewall, logger)
		mssResultCh <- mssResult{dst: dst, mss: mss, err: err}
	}()
	var result mssResult
	select {
	case err = <-trackerErrCh:
		mssCancel()
		<-mssResultCh
		return 0, fmt.Errorf("listening for TCP replies: %w", err)
	case result = <-mssResultCh:
	}
	if result.err != nil {
		trackerCancel()
		<-trackerErrCh
		return 0, fmt.Errorf("finding MSS: %w", result.err)
	}
	ipHeaderLength := ip.HeaderLength(result.dst.Addr().Is4())
	maxPossibleMTU = ipHeaderLength + constants.BaseTCPHeaderLength + result.mss
	if minMTU > maxPossibleMTU {
		// Occasionally, the MSS is a lot smaller than the MTU found using ICMP
		const safetyBuffer = 100
		minMTU = maxPossibleMTU - safetyBuffer
	}

	fd := familyToFD[ip.GetFamily(result.dst)]

	type pmtudResult struct {
		mtu uint32
		err error
	}
	resultCh := make(chan pmtudResult)
	pmtudCtx, pmtudCancel := context.WithCancel(ctx)
	defer pmtudCancel()
	go func() {
		mtu, err := pathMTUDiscover(pmtudCtx, fd, result.dst, minMTU, maxPossibleMTU,
			excludeMark, tryTimeout, tracker, firewall, logger)
		resultCh <- pmtudResult{mtu: mtu, err: err}
	}()

	select {
	case err = <-trackerErrCh:
		pmtudCancel()
		<-resultCh
		return 0, fmt.Errorf("listening for TCP replies: %w", err)
	case result := <-resultCh:
		trackerCancel()
		<-trackerErrCh
		return result.mtu, result.err
	}
}

var errTimedOut = errors.New("timed out")

func pathMTUDiscover(ctx context.Context, fd fileDescriptor,
	dst netip.AddrPort, minMTU, maxPossibleMTU uint32, excludeMark int,
	tryTimeout time.Duration, tracker *tracker, firewall Firewall,
	logger Logger,
) (mtu uint32, err error) {
	mtusToTest := test.MakeMTUsToTest(minMTU, maxPossibleMTU)
	if len(mtusToTest) == 1 { // only minMTU because minMTU == maxPossibleMTU
		return minMTU, nil
	}
	logger.Debugf("TCP testing the following MTUs: %v", mtusToTest)

	tests := make([]testUnit, len(mtusToTest))
	for i := range mtusToTest {
		tests[i] = testUnit{mtu: mtusToTest[i]}
	}

	errCause := fmt.Errorf("%w: after %s", errTimedOut, tryTimeout)
	runCtx, runCancel := context.WithTimeoutCause(ctx, tryTimeout, errCause)
	defer runCancel()
	doneCh := make(chan struct{})
	for i := range tests {
		go func(i int) {
			err := runTest(runCtx, dst, tests[i].mtu, excludeMark,
				fd, tracker, firewall, logger)
			tests[i].ok = err == nil
			doneCh <- struct{}{}
		}(i)
	}

	i := 0
	for i < len(tests) {
		select {
		case <-runCtx.Done(): // timeout or parent context canceled
			err = context.Cause(runCtx)
			// collect remaining done signals
			for i < len(tests) {
				<-doneCh
				i++
			}
		case <-doneCh:
			i++
		}
	}

	if err != nil && !errors.Is(err, errTimedOut) {
		// context is canceled but did not timeout after tryTimeout
		return 0, fmt.Errorf("running MTU tests: %w", err)
	}

	if tests[len(tests)-1].ok {
		return tests[len(tests)-1].mtu, nil
	}

	for i := len(tests) - 2; i >= 0; i-- { //nolint:mnd
		if tests[i].ok {
			runCancel() // just to release resources although runCtx is no longer used
			return pathMTUDiscover(ctx, fd, dst,
				tests[i].mtu, tests[i+1].mtu-1, excludeMark,
				tryTimeout, tracker, firewall, logger)
		}
	}

	return 0, errors.New("MTU not found: your connection might not be working at all")
}

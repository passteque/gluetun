package wireguard

import "sort"

type closer struct {
	operation string
	step      step
	close     func() error
	closed    bool
}

type closers []closer

func (c *closers) add(operation string, step step,
	closeFunc func() error,
) {
	closer := closer{
		operation: operation,
		step:      step,
		close:     closeFunc,
	}
	*c = append(*c, closer)
}

func (c *closers) cleanup(logger Logger) {
	closers := *c

	sort.Slice(closers, func(i, j int) bool {
		return closers[i].step < closers[j].step
	})

	for i, closer := range closers {
		if closer.closed {
			continue
		}
		closers[i].closed = true
		logger.Debug(closer.operation + "...")
		err := closer.close()
		if err != nil {
			logger.Error("failed " + closer.operation + ": " + err.Error())
		}
	}
}

type step int

const (
	// stepOne closes the wireguard controller client.
	stepOne step = iota
	// stepTwo closes the UAPI listener.
	stepTwo
	// stepThree closes the UAPI file.
	stepThree
	// stepFour shuts down the Wireguard link.
	stepFour
	// stepFive removes the Wireguard link.
	stepFive
	// stepSix closes the Wireguard device.
	stepSix
	// stepSeven closes the bind connection and the TUN device file.
	stepSeven
	// stepEight removes the IP rules. It is the last step, since removing a
	// rule before the link and its addresses are gone makes packets of the
	// connections established through the tunnel leave through the default
	// route interface with the tunnel address as source, leaking outside
	// the VPN (the firewall accepts established connections).
	stepEight
)

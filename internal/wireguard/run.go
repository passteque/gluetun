package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/qdm12/gluetun/internal/netlink"
	gtun "github.com/qdm12/gluetun/internal/tun"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
)

var (
	ErrCreateTun         = errors.New("cannot create TUN device")
	ErrAddLink           = errors.New("cannot add Wireguard link")
	ErrFindLink          = errors.New("cannot find link")
	ErrFindDevice        = errors.New("cannot find Wireguard device")
	ErrUAPISocketOpening = errors.New("cannot open UAPI socket")
	ErrWgctrlOpen        = errors.New("cannot open wgctrl")
	ErrUAPIListen        = errors.New("cannot listen on UAPI socket")
	ErrAddAddress        = errors.New("cannot add address to wireguard interface")
	ErrConfigure         = errors.New("cannot configure wireguard interface")
	ErrDeviceInfo        = errors.New("cannot get wireguard device information")
	ErrIfaceUp           = errors.New("cannot set the interface to UP")
	ErrRouteAdd          = errors.New("cannot add route for interface")
	ErrDeviceWaited      = errors.New("device waited for")
	ErrKernelSupport     = errors.New("kernel does not support Wireguard")
)

// See https://git.zx2c4.com/wireguard-go/tree/main.go
func (w *Wireguard) Run(ctx context.Context, waitError chan<- error, ready chan<- struct{}) {
	kernelSupported := w.netlink.IsWireguardSupported()

	setupFunction := setupUserSpace
	userspace := false
	switch w.settings.Implementation {
	case "auto": //nolint:goconst
		if !kernelSupported {
			w.logger.Info("Using userspace implementation since Kernel support does not exist")
			userspace = true
			break
		}
		w.logger.Info("Using available kernelspace implementation")
		setupFunction = setupKernelSpace
	case "userspace":
		userspace = true
	case "kernelspace":
		if !kernelSupported {
			waitError <- fmt.Errorf("%w", ErrKernelSupport)
			return
		}
		setupFunction = setupKernelSpace
	default:
		panic(fmt.Sprintf("unknown implementation %q", w.settings.Implementation))
	}

	if userspace {
		err := gtun.Setup()
		if err != nil {
			waitError <- fmt.Errorf("setting up userspace tun device: %w", err)
			return
		}
	}

	client, err := wgctrl.New()
	if err != nil {
		waitError <- fmt.Errorf("%w: %s", ErrWgctrlOpen, err)
		return
	}

	var closers closers
	closers.add("closing controller client", stepOne, client.Close)

	defer closers.cleanup(w.logger)

	link, waitAndCleanup, err := setupFunction(ctx,
		w.settings.InterfaceName, w.netlink, w.settings.MTU, &closers, w.logger)
	if err != nil {
		waitError <- err
		return
	}

	err = w.addAddresses(link, w.settings.Addresses)
	if err != nil {
		waitError <- fmt.Errorf("%w: %s", ErrAddAddress, err)
		return
	}

	w.logger.Info("Connecting to " + w.settings.Endpoint.String())
	err = configureDevice(client, w.settings)
	if err != nil {
		waitError <- fmt.Errorf("%w: %s", ErrConfigure, err)
		return
	}

	linkIndex, err := w.netlink.LinkSetUp(link)
	if err != nil {
		waitError <- fmt.Errorf("%w: %s", ErrIfaceUp, err)
		return
	}
	link.Index = linkIndex
	closers.add("shutting down link", stepFour, func() error {
		return w.netlink.LinkSetDown(link)
	})

	err = w.addRoutes(link, w.settings.AllowedIPs, w.settings.FirewallMark)
	if err != nil {
		waitError <- fmt.Errorf("%w: %s", ErrRouteAdd, err)
		return
	}

	// The IP rules must be removed last, after the link is deleted
	// together with its addresses. Otherwise, once a rule is removed,
	// packets of connections established through the tunnel would be
	// routed out of the default route interface, with the tunnel
	// address as source, and leak outside the VPN, since the firewall
	// accepts established connections.
	if *w.settings.IPv6 {
		// requires net.ipv6.conf.all.disable_ipv6=0
		ruleCleanup6, err := w.addRule(w.settings.RulePriority,
			w.settings.FirewallMark, unix.AF_INET6)
		if err != nil {
			waitError <- fmt.Errorf("adding IPv6 rule: %w", err)
			return
		}
		closers.add("removing IPv6 rule", stepEight, ruleCleanup6)
	}

	ruleCleanup, err := w.addRule(w.settings.RulePriority,
		w.settings.FirewallMark, unix.AF_INET)
	if err != nil {
		waitError <- fmt.Errorf("adding IPv4 rule: %w", err)
		return
	}

	closers.add("removing IPv4 rule", stepEight, ruleCleanup)
	w.logger.Info("Wireguard setup is complete. " +
		"Note Wireguard is a silent protocol and it may or may not work, without giving any error message. " +
		"Typically i/o timeout errors indicate the Wireguard connection is not working.")
	ready <- struct{}{}

	waitError <- waitAndCleanup()
}

type waitAndCleanupFunc func() error

func setupKernelSpace(ctx context.Context,
	interfaceName string, netLinker NetLinker, mtu uint16,
	closers *closers, logger Logger) (
	link netlink.Link, waitAndCleanup waitAndCleanupFunc, err error,
) {
	link = netlink.Link{
		Type: "wireguard",
		Name: interfaceName,
		MTU:  mtu,
	}
	links, err := netLinker.LinkList()
	if err != nil {
		return link, nil, fmt.Errorf("listing links: %w", err)
	}

	// Cleanup any previous Wireguard interface with the same name
	// See https://github.com/qdm12/gluetun/issues/1669
	for _, link := range links {
		if link.Type == "wireguard" && link.Name == interfaceName {
			err = netLinker.LinkDel(link)
			if err != nil {
				return link, nil, fmt.Errorf("deleting previous Wireguard link %s: %w",
					interfaceName, err)
			}
		}
	}

	linkIndex, err := netLinker.LinkAdd(link)
	if err != nil {
		return link, nil, fmt.Errorf("%w: %s", ErrAddLink, err)
	}
	link.Index = linkIndex
	closers.add("deleting link", stepFive, func() error {
		return netLinker.LinkDel(link)
	})

	waitAndCleanup = func() error {
		<-ctx.Done()
		closers.cleanup(logger)
		return ctx.Err()
	}

	return link, waitAndCleanup, nil
}

func setupUserSpace(ctx context.Context,
	interfaceName string, netLinker NetLinker, mtu uint16,
	closers *closers, logger Logger) (
	link netlink.Link, waitAndCleanup waitAndCleanupFunc, err error,
) {
	tun, err := tun.CreateTUN(interfaceName, int(mtu))
	if err != nil {
		return link, nil, fmt.Errorf("%w: %s", ErrCreateTun, err)
	}

	closers.add("closing TUN device", stepSeven, tun.Close)

	tunName, err := tun.Name()
	if err != nil {
		return link, nil, fmt.Errorf("%w: cannot get TUN name: %s", ErrCreateTun, err)
	} else if tunName != interfaceName {
		return link, nil, fmt.Errorf("%w: names don't match: expected %q and got %q",
			ErrCreateTun, interfaceName, tunName)
	}

	link, err = netLinker.LinkByName(interfaceName)
	if err != nil {
		return link, nil, fmt.Errorf("%w: %s: %s", ErrFindLink, interfaceName, err)
	}
	closers.add("deleting link", stepFive, func() error {
		return netLinker.LinkDel(link)
	})

	bind := conn.NewDefaultBind()

	closers.add("closing bind", stepSeven, bind.Close)

	deviceLogger := makeDeviceLogger(logger)
	device := device.NewDevice(tun, bind, deviceLogger)

	closers.add("closing Wireguard device", stepSix, func() error {
		device.Close()
		return nil
	})

	uapiFile, err := ipc.UAPIOpen(interfaceName)
	if err != nil {
		return link, nil, fmt.Errorf("%w: %s", ErrUAPISocketOpening, err)
	}

	closers.add("closing UAPI file", stepThree, uapiFile.Close)

	uapiListener, err := ipc.UAPIListen(interfaceName, uapiFile)
	if err != nil {
		return link, nil, fmt.Errorf("%w: %s", ErrUAPIListen, err)
	}

	closers.add("closing UAPI listener", stepTwo, uapiListener.Close)

	// acceptAndHandle exits when uapiListener is closed
	uapiAcceptErrorCh := make(chan error)
	go acceptAndHandle(uapiListener, device, uapiAcceptErrorCh)
	waitAndCleanup = func() error {
		select {
		case <-ctx.Done():
			err = ctx.Err()
		case err = <-uapiAcceptErrorCh:
			close(uapiAcceptErrorCh)
		case <-device.Wait():
			err = ErrDeviceWaited
		}

		closers.cleanup(logger)

		<-uapiAcceptErrorCh // wait for acceptAndHandle to exit

		return err
	}

	return link, waitAndCleanup, nil
}

func acceptAndHandle(uapi net.Listener, device *device.Device,
	uapiAcceptErrorCh chan<- error,
) {
	for { // stopped by uapiFile.Close()
		conn, err := uapi.Accept()
		if err != nil {
			uapiAcceptErrorCh <- err
			return
		}
		go device.IpcHandle(conn)
	}
}

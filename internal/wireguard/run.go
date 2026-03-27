package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/qdm12/gluetun/internal/cleanup"
	"github.com/qdm12/gluetun/internal/netlink"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
)

var (
	errKernelSupport   = errors.New("kernel does not support Wireguard")
	errTunNameMismatch = errors.New("TUN device name is mismatching")
	errDeviceWaited    = errors.New("device waited for")
)

// Run runs the wireguard interface and waits until the context is done, then it cleans up the
// interface and returns any error that occurred during setup or waiting. It sends an error to
// waitError if any error occurs during setup or waiting, otherwise it sends nil when the context
// is done. It sends a signal to ready when the setup is complete and the interface is ready to use.
// See https://git.zx2c4.com/wireguard-go/tree/main.go
func (w *Wireguard) Run(ctx context.Context, waitError chan<- error, ready chan<- struct{}) {
	kernelSupported, err := w.netlink.IsWireguardSupported()
	if err != nil {
		waitError <- fmt.Errorf("detecting wireguard kernel support: %w", err)
		return
	}

	setupFunction := setupUserSpace
	switch w.settings.Implementation {
	case "auto": //nolint:goconst
		if !kernelSupported {
			w.logger.Info("Using userspace implementation since Kernel support does not exist")
			break
		}
		w.logger.Info("Using available kernelspace implementation")
		setupFunction = setupKernelSpace
	case "userspace":
	case "kernelspace":
		if !kernelSupported {
			waitError <- fmt.Errorf("%w", errKernelSupport)
			return
		}
		setupFunction = setupKernelSpace
	default:
		panic(fmt.Sprintf("unknown implementation %q", w.settings.Implementation))
	}

	setup := func(ctx context.Context, cleanups *cleanup.Cleanups) (
		linkIndex uint32, waitAndCleanup func() error, err error,
	) {
		return setupFunction(ctx,
			w.settings.InterfaceName, w.netlink, w.settings.MTU, cleanups, w.logger)
	}

	Run(ctx, waitError, ready, setup, w.settings, w.netlink, w.logger)
}

func Run(ctx context.Context, waitError chan<- error, ready chan<- struct{},
	setup func(ctx context.Context, cleanups *cleanup.Cleanups) (
		linkIndex uint32, waitAndCleanup func() error, err error),
	settings Settings, netlinker NetLinker, logger Logger,
) {
	client, err := wgctrl.New()
	if err != nil {
		waitError <- fmt.Errorf("opening wgctrl: %w", err)
		return
	}

	var cleanups cleanup.Cleanups
	cleanups.Add("closing controller client", 1, client.Close)

	defer cleanups.Cleanup(logger)

	linkIndex, waitAndCleanup, err := setup(ctx, &cleanups)
	if err != nil {
		waitError <- err
		return
	}

	err = AddAddresses(linkIndex, settings.Addresses, *settings.IPv6, netlinker)
	if err != nil {
		waitError <- fmt.Errorf("adding addresses to interface: %w", err)
		return
	}

	logger.Info("Connecting to " + settings.Endpoint.String())
	err = ConfigureDevice(client, settings)
	if err != nil {
		waitError <- fmt.Errorf("configuring interface: %w", err)
		return
	}

	err = netlinker.LinkSetUp(linkIndex)
	if err != nil {
		waitError <- fmt.Errorf("setting the interface UP: %w", err)
		return
	}
	cleanups.Add("shutting down link", 4, func() error {
		return netlinker.LinkSetDown(linkIndex)
	})

	err = AddRoutes(linkIndex, settings.AllowedIPs, settings.FirewallMark,
		netlinker, logger)
	if err != nil {
		waitError <- fmt.Errorf("adding routes for interface: %w", err)
		return
	}

	if *settings.IPv6 {
		// requires net.ipv6.conf.all.disable_ipv6=0
		ruleCleanup6, err := AddRule(settings.RulePriority,
			settings.FirewallMark, netlink.FamilyV6,
			netlinker, logger)
		if err != nil {
			waitError <- fmt.Errorf("adding IPv6 rule: %w", err)
			return
		}
		cleanups.Add("removing IPv6 rule", 1, ruleCleanup6)
	}

	ruleCleanup, err := AddRule(settings.RulePriority,
		settings.FirewallMark, netlink.FamilyV4,
		netlinker, logger)
	if err != nil {
		waitError <- fmt.Errorf("adding IPv4 rule: %w", err)
		return
	}

	cleanups.Add("removing IPv4 rule", 1, ruleCleanup)
	ready <- struct{}{}

	waitError <- waitAndCleanup()
}

func setupKernelSpace(ctx context.Context,
	interfaceName string, netLinker NetLinker, mtu uint32,
	cleanups *cleanup.Cleanups, logger Logger) (
	linkIndex uint32, waitAndCleanup func() error, err error,
) {
	links, err := netLinker.LinkList()
	if err != nil {
		return 0, nil, fmt.Errorf("listing links: %w", err)
	}

	// Cleanup any previous Wireguard interface with the same name
	// See https://github.com/qdm12/gluetun/issues/1669
	for _, link := range links {
		if link.VirtualType == "wireguard" && link.Name == interfaceName {
			err = netLinker.LinkDel(link.Index)
			if err != nil {
				return 0, nil, fmt.Errorf("deleting previous Wireguard link %s: %w",
					interfaceName, err)
			}
		}
	}

	link := netlink.Link{
		VirtualType: "wireguard",
		Name:        interfaceName,
		MTU:         mtu,
	}
	linkIndex, err = netLinker.LinkAdd(link)
	if err != nil {
		return 0, nil, fmt.Errorf("adding link: %w", err)
	}
	cleanups.Add("deleting link", 5, func() error {
		return netLinker.LinkDel(linkIndex)
	})

	waitAndCleanup = func() error {
		<-ctx.Done()
		cleanups.Cleanup(logger)
		return ctx.Err()
	}

	return linkIndex, waitAndCleanup, nil
}

func setupUserSpace(ctx context.Context,
	interfaceName string, netLinker NetLinker, mtu uint32,
	cleanups *cleanup.Cleanups, logger Logger) (
	linkIndex uint32, waitAndCleanup func() error, err error,
) {
	tun, err := tun.CreateTUN(interfaceName, int(mtu))
	if err != nil {
		return 0, nil, fmt.Errorf("creating TUN device: %w", err)
	}

	cleanups.Add("closing TUN device", 7, tun.Close)

	tunName, err := tun.Name()
	if err != nil {
		return 0, nil, fmt.Errorf("getting created TUN device name: %w", err)
	} else if tunName != interfaceName {
		return 0, nil, fmt.Errorf("%w: expected %q and got %q",
			errTunNameMismatch, interfaceName, tunName)
	}

	link, err := netLinker.LinkByName(interfaceName)
	if err != nil {
		return 0, nil, fmt.Errorf("finding link %s: %w", interfaceName, err)
	}
	cleanups.Add("deleting link", 5, func() error {
		return netLinker.LinkDel(link.Index)
	})

	bind := conn.NewDefaultBind()

	cleanups.Add("closing bind", 7, bind.Close)

	deviceLogger := makeDeviceLogger(logger)
	device := device.NewDevice(tun, bind, deviceLogger)

	cleanups.Add("closing Wireguard device", 6, func() error {
		device.Close()
		return nil
	})

	uapiFile, err := UAPIOpen(interfaceName)
	if err != nil {
		return 0, nil, fmt.Errorf("opening UAPI socket: %w", err)
	}

	cleanups.Add("closing UAPI file", 3, uapiFile.Close)

	uapiListener, err := UAPIListen(interfaceName, uapiFile)
	if err != nil {
		return 0, nil, fmt.Errorf("listening on UAPI socket: %w", err)
	}

	cleanups.Add("closing UAPI listener", 2, uapiListener.Close)

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
			err = errDeviceWaited
		}

		cleanups.Cleanup(logger)

		<-uapiAcceptErrorCh // wait for acceptAndHandle to exit

		return err
	}

	return link.Index, waitAndCleanup, nil
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

package amneziawg

import (
	"context"
	"errors"
	"fmt"
	"net"

	amneziaconn "github.com/amnezia-vpn/amneziawg-go/conn"
	amneziadevice "github.com/amnezia-vpn/amneziawg-go/device"
	amneziatun "github.com/amnezia-vpn/amneziawg-go/tun"
	"github.com/qdm12/gluetun/internal/cleanup"
	"github.com/qdm12/gluetun/internal/wireguard"
)

var (
	errTunNameMismatch = errors.New("TUN device name is mismatching")
	errDeviceWaited    = errors.New("device waited for")
)

// Run runs the amneziawg interface and waits until the context is done, then it cleans up the
// interface and returns any error that occurred during setup or waiting. It sends an error to
// waitError if any error occurs during setup or waiting, otherwise it sends nil when the context
// is done. It sends a signal to ready when the setup is complete and the interface is ready to use.
// See https://github.com/amnezia-vpn/amneziawg-go/blob/master/main.go
func (a *Amneziawg) Run(ctx context.Context, waitError chan<- error, ready chan<- struct{}) {
	setup := func(ctx context.Context, cleanups *cleanup.Cleanups) (
		linkIndex uint32, waitAndCleanup func() error, err error,
	) {
		return setupUserspace(ctx, a.settings.Wireguard.InterfaceName,
			a.netlink, a.settings.Wireguard.MTU, cleanups, a.logger, a.settings)
	}

	wireguard.Run(ctx, waitError, ready, setup, a.settings.Wireguard, a.netlink, a.logger)
}

func setupUserspace(ctx context.Context,
	interfaceName string, netLinker NetLinker, mtu uint32,
	cleanups *cleanup.Cleanups, logger Logger,
	settings Settings,
) (
	linkIndex uint32, waitAndCleanup func() error, err error,
) {
	tun, err := amneziatun.CreateTUN(interfaceName, int(mtu))
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

	bind := amneziaconn.NewDefaultBind()
	cleanups.Add("closing bind", 7, bind.Close)

	deviceLogger := amneziadevice.Logger{
		Verbosef: logger.Debugf,
		Errorf:   logger.Errorf,
	}
	device := amneziadevice.NewDevice(tun, bind, &deviceLogger)

	cleanups.Add("closing Wireguard device", 6, func() error {
		device.Close()
		return nil
	})

	uapiFile, err := wireguard.UAPIOpen(interfaceName)
	if err != nil {
		return 0, nil, fmt.Errorf("opening UAPI socket: %w", err)
	}
	cleanups.Add("closing UAPI file", 3, uapiFile.Close)

	uapiListener, err := wireguard.UAPIListen(interfaceName, uapiFile)
	if err != nil {
		return 0, nil, fmt.Errorf("listening on UAPI socket: %w", err)
	}
	cleanups.Add("closing UAPI listener", 2, uapiListener.Close)

	uapiConfig := settings.uapiConfig()
	err = device.IpcSet(uapiConfig)
	if err != nil {
		return 0, nil, fmt.Errorf("setting amneziawg uapi config: %w", err)
	}

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

func acceptAndHandle(uapi net.Listener, device *amneziadevice.Device,
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

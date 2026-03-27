package vpn

import (
	"context"

	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/log"
)

func (l *Loop) Run(ctx context.Context, done chan<- struct{}) {
	defer close(done)

	select {
	case <-l.start:
	case <-ctx.Done():
		return
	}

	for ctx.Err() == nil {
		settings := l.state.GetSettings()

		providerConf := l.providers.Get(settings.Provider.Name)

		portForwarder := getPortForwarder(providerConf, l.providers,
			*settings.Provider.PortForwarding.Provider)

		var vpnRunner interface {
			Run(ctx context.Context, waitError chan<- error, tunnelReady chan<- struct{})
		}
		var vpnInterface string
		var connection models.Connection
		var err error
		subLogger := l.logger.New(log.SetComponent(settings.Type))
		switch settings.Type {
		case vpn.AmneziaWg:
			vpnInterface = settings.AmneziaWg.Wireguard.Interface
			vpnRunner, connection, err = setupAmneziaWg(ctx, l.netLinker, l.fw,
				providerConf, settings, l.ipv6Supported, subLogger)
		case vpn.OpenVPN:
			vpnInterface = settings.OpenVPN.Interface
			vpnRunner, connection, err = setupOpenVPN(ctx, l.fw,
				l.openvpnConf, providerConf, settings, l.ipv6Supported, l.cmder, subLogger)
		case vpn.Wireguard:
			vpnInterface = settings.Wireguard.Interface
			vpnRunner, connection, err = setupWireguard(ctx, l.netLinker, l.fw,
				providerConf, settings, l.ipv6Supported, subLogger)
		default:
			panic("vpn type not implemented: " + settings.Type)
		}
		if err != nil {
			l.crashed(ctx, err)
			continue
		}
		tunnelUpData := tunnelUpData{
			upCommand: *settings.UpCommand,
			pmtud: tunnelUpPMTUDData{
				enabled:   settings.Type != vpn.Wireguard || *settings.Wireguard.MTU == 0,
				vpnType:   settings.Type,
				network:   connection.Protocol,
				icmpAddrs: settings.PMTUD.ICMPAddresses,
				tcpAddrs:  settings.PMTUD.TCPAddresses,
			},
			serverIP:       connection.IP,
			serverName:     connection.ServerName,
			canPortForward: connection.PortForward,
			portForwarder:  portForwarder,
			vpnIntf:        vpnInterface,
			username:       settings.Provider.PortForwarding.Username,
			password:       settings.Provider.PortForwarding.Password,
		}

		vpnCtx, vpnCancel := context.WithCancel(context.Background())
		waitError := make(chan error)
		tunnelReady := make(chan struct{})

		go vpnRunner.Run(vpnCtx, waitError, tunnelReady)

		if err := l.waitForError(ctx, waitError); err != nil {
			vpnCancel()
			l.crashed(ctx, err)
			continue
		}

		l.backoffTime = defaultBackoffTime
		l.signalOrSetStatus(constants.Running)

		stayHere := true
		for stayHere {
			select {
			case <-tunnelReady:
				go l.onTunnelUp(vpnCtx, ctx, tunnelUpData)
			case <-ctx.Done():
				l.cleanup()
				vpnCancel()
				<-waitError
				close(waitError)
				return
			case <-l.stop:
				l.userTrigger = true
				l.logger.Info("stopping")
				l.cleanup()
				vpnCancel()
				<-waitError
				// do not close waitError or the waitError
				// select case will trigger
				l.stopped <- struct{}{}
			case <-l.start:
				l.userTrigger = true
				l.logger.Info("starting")
				stayHere = false
			case err := <-waitError: // unexpected error
				l.statusManager.Lock() // prevent SetStatus from running in parallel

				l.cleanup()
				vpnCancel()
				l.statusManager.SetStatus(constants.Crashed)
				l.logAndWait(ctx, err)
				stayHere = false

				l.statusManager.Unlock()
			}
		}
		vpnCancel()
	}
}

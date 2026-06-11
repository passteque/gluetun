package vpn

import (
	"context"
	"fmt"

	"github.com/qdm12/gluetun/internal/portforward"
	"github.com/qdm12/gluetun/internal/portforward/service"
	pfutils "github.com/qdm12/gluetun/internal/provider/utils"
)

func getPortForwarder(provider Provider, providers Providers, //nolint:ireturn
	customPortForwarderName string,
) (portForwarder PortForwarder) {
	if customPortForwarderName != "" {
		provider = providers.Get(customPortForwarderName)
	}
	portForwarder, ok := provider.(PortForwarder)
	if ok {
		return portForwarder
	}
	return newNoPortForwarder(provider.Name())
}

func (l *Loop) startPortForwarding(data tunnelUpData) (err error) {
	partialUpdate := portforward.Settings{
		VPNIsUp: ptrTo(true),
		Service: service.Settings{
			PortForwarder:  data.portForwarder,
			Interface:      data.vpnIntf,
			ServerName:     data.serverName,
			CanPortForward: data.canPortForward,
			Username:       data.username,
			Password:       data.password,
		},
	}
	return l.portForward.UpdateWith(partialUpdate)
}

func (l *Loop) stopPortForwarding() (err error) {
	partialUpdate := portforward.Settings{
		VPNIsUp: ptrTo(false),
	}
	return l.portForward.UpdateWith(partialUpdate)
}

type noPortForwarder struct {
	providerName string
}

func newNoPortForwarder(providerName string) *noPortForwarder {
	return &noPortForwarder{
		providerName: providerName,
	}
}

func (n *noPortForwarder) Name() string {
	return n.providerName
}

func (n *noPortForwarder) PortForward(context.Context, pfutils.PortForwardObjects) (
	internalToExternalPorts map[uint16]uint16, err error,
) {
	return nil, fmt.Errorf("custom port forwarding obtention is not supported: for %s", n.providerName)
}

func (n *noPortForwarder) KeepPortForward(context.Context, pfutils.PortForwardObjects) (err error) {
	return fmt.Errorf("custom port forwarding obtention is not supported: for %s", n.providerName)
}

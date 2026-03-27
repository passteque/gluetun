package dns

import (
	"context"

	"github.com/qdm12/dns/v2/pkg/nameserver"
	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
)

func (l *Loop) Run(ctx context.Context, done chan<- struct{}) {
	defer close(done)

	var err error
	l.localResolvers, err = nameserver.GetPrivateDNSServers()
	if err != nil {
		l.logger.Error("getting private DNS servers: " + err.Error())
		return
	}

	select {
	case <-l.start:
	case <-ctx.Done():
		return
	}

	for ctx.Err() == nil {
		// Upper scope variables for the DNS forwarder server only
		// Their values are to be used if DOT=off
		var runError <-chan error

		var settings settings.DNS
		for {
			settings = l.GetSettings()
			var err error
			runError, err = l.setupServer(ctx, settings)
			if err == nil {
				break
			}

			l.signalOrSetStatus(constants.Crashed)
			if ctx.Err() != nil {
				return
			}
			l.logAndWait(ctx, err)
		}

		l.backoffTime = defaultBackoffTime
		l.logger.Infof("ready and using DNS server with %s upstream resolvers", settings.UpstreamType)

		err = l.updateFiles(ctx, settings)
		if err != nil {
			l.logger.Warn("downloading block lists failed, skipping: " + err.Error())
		}
		l.signalOrSetStatus(constants.Running)

		l.userTrigger = false

		report, err := leakCheck(ctx, l.client)
		if err != nil {
			l.logger.Warnf("running leak check: %s", err)
		} else {
			l.logger.Infof("leak check report: %s", report)
		}

		exitLoop := l.runWait(ctx, runError)
		if exitLoop {
			return
		}
	}
}

func (l *Loop) runWait(ctx context.Context, runError <-chan error) (exitLoop bool) {
	for {
		select {
		case <-ctx.Done():
			l.stopServer()
			// TODO revert OS and Go nameserver when exiting
			return true
		case <-l.stop:
			l.userTrigger = true
			l.logger.Info("stopping")
			l.stopServer()
			l.stopped <- struct{}{}
		case <-l.start:
			l.userTrigger = true
			l.logger.Info("starting")
			return false
		case err := <-runError: // unexpected error
			l.statusManager.SetStatus(constants.Crashed)
			l.logAndWait(ctx, err)
			return false
		}
	}
}

func (l *Loop) stopServer() {
	stopErr := l.server.Stop()
	if stopErr != nil {
		l.logger.Error("stopping server: " + stopErr.Error())
	}
}

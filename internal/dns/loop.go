package dns

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"time"

	"github.com/qdm12/dns/v2/pkg/middlewares/filter/mapfilter"
	"github.com/qdm12/dns/v2/pkg/server"
	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/dns/state"
	"github.com/qdm12/gluetun/internal/loopstate"
	"github.com/qdm12/gluetun/internal/models"
)

type Loop struct {
	statusManager  *loopstate.State
	state          *state.State
	server         *server.Server
	filter         *mapfilter.Filter
	localResolvers []netip.Addr
	localSubnets   []netip.Prefix
	resolvConf     string
	client         *http.Client
	logger         Logger
	userTrigger    bool
	start          <-chan struct{}
	running        chan<- models.LoopStatus
	stop           <-chan struct{}
	stopped        chan<- struct{}
	updateTicker   <-chan struct{}
	backoffTime    time.Duration
	timeNow        func() time.Time
	timeSince      func(time.Time) time.Duration
}

const defaultBackoffTime = 10 * time.Second

func NewLoop(settings settings.DNS,
	client *http.Client, logger Logger, localSubnets []netip.Prefix,
) (loop *Loop, err error) {
	start := make(chan struct{})
	running := make(chan models.LoopStatus)
	stop := make(chan struct{})
	stopped := make(chan struct{})
	updateTicker := make(chan struct{})

	statusManager := loopstate.New(constants.Stopped, start, running, stop, stopped)
	state := state.New(statusManager, settings, updateTicker)

	filter, err := mapfilter.New(mapfilter.Settings{
		Logger: buildFilterLogger(logger),
	})
	if err != nil {
		return nil, fmt.Errorf("creating map filter: %w", err)
	}

	return &Loop{
		statusManager: statusManager,
		state:         state,
		server:        nil,
		filter:        filter,
		localSubnets:  localSubnets,
		resolvConf:    "/etc/resolv.conf",
		client:        client,
		logger:        logger,
		userTrigger:   true,
		start:         start,
		running:       running,
		stop:          stop,
		stopped:       stopped,
		updateTicker:  updateTicker,
		backoffTime:   defaultBackoffTime,
		timeNow:       time.Now,
		timeSince:     time.Since,
	}, nil
}

func (l *Loop) logAndWait(ctx context.Context, err error) {
	if err != nil {
		l.logger.Warn(err.Error())
	}
	l.logger.Info("attempting restart in " + l.backoffTime.String())
	timer := time.NewTimer(l.backoffTime)
	l.backoffTime *= 2
	select {
	case <-timer.C:
	case <-ctx.Done():
		if !timer.Stop() {
			<-timer.C
		}
	}
}

func (l *Loop) signalOrSetStatus(status models.LoopStatus) {
	if l.userTrigger {
		l.userTrigger = false
		select {
		case l.running <- status:
		default: // receiver dropped out - avoid deadlock on events routing when shutting down
		}
	} else {
		l.statusManager.SetStatus(status)
	}
}

type filterLogger struct {
	logger Logger
}

func (l *filterLogger) Log(msg string) {
	l.logger.Debug(msg)
}

func buildFilterLogger(logger Logger) *filterLogger {
	return &filterLogger{logger: logger}
}

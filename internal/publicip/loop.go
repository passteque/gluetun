package publicip

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/publicip/api"
)

type Loop struct {
	// State
	settings      settings.PublicIP
	settingsMutex sync.RWMutex
	ipData        models.PublicIP
	ipDataMutex   sync.RWMutex
	fetcher       *api.ResilientFetcher
	// Fixed injected objects
	httpClient *http.Client
	logger     Logger
	// Fixed parameters
	puid int
	pgid int
	// Internal channels and locks
	// runCtx is used to detect when the loop has exited
	// when performing an update
	runCtx        context.Context //nolint:containedctx
	runCancel     context.CancelFunc
	runTrigger    chan<- context.Context
	runResult     <-chan error
	updateTrigger chan<- settings.PublicIP
	updatedResult <-chan error
	runDone       <-chan struct{}
	// retryStopTrigger tells the run loop to drop the retry it has pending, the
	// VPN connection going down being what pulls it, see [Loop.ClearData]. The
	// channel is unbuffered, so whoever signals waits for the run loop to be back
	// in its select rather than leaving a token to be picked up later.
	retryStopTrigger chan<- struct{}
	// Mock functions
	timeNow  func() time.Time
	newTimer func(duration time.Duration) timer
}

func NewLoop(settings settings.PublicIP, puid, pgid int,
	httpClient *http.Client, logger Logger,
) (loop *Loop, err error) {
	fetchers, err := api.New(makeNameTokenPairs(settings.APIs), httpClient)
	if err != nil {
		return nil, fmt.Errorf("creating fetchers: %w", err)
	}

	return &Loop{
		settings:   settings,
		httpClient: httpClient,
		fetcher:    api.NewResilient(fetchers, logger),
		logger:     logger,
		puid:       puid,
		pgid:       pgid,
		timeNow:    time.Now,
		newTimer: func(duration time.Duration) timer {
			return &timeTimer{timer: time.NewTimer(duration)}
		},
	}, nil
}

func makeNameTokenPairs(apis []settings.PublicIPAPI) (nameTokenPairs []api.NameToken) {
	nameTokenPairs = make([]api.NameToken, len(apis))
	for i := range apis {
		nameTokenPairs[i] = api.NameToken{
			Name:  apis[i].Name,
			Token: apis[i].Token,
		}
	}
	return nameTokenPairs
}

func (l *Loop) String() string {
	return "public ip loop"
}

func (l *Loop) Start(_ context.Context) (_ <-chan error, err error) {
	l.runCtx, l.runCancel = context.WithCancel(context.Background())
	runDone := make(chan struct{})
	l.runDone = runDone
	runTrigger := make(chan context.Context)
	l.runTrigger = runTrigger
	runResult := make(chan error)
	l.runResult = runResult
	updateTrigger := make(chan settings.PublicIP)
	l.updateTrigger = updateTrigger
	updatedResult := make(chan error)
	l.updatedResult = updatedResult
	retryStopTrigger := make(chan struct{})
	l.retryStopTrigger = retryStopTrigger

	go l.run(l.runCtx, runDone, runTrigger, runResult, updateTrigger, updatedResult,
		retryStopTrigger)

	return nil, nil //nolint:nilnil
}

func (l *Loop) run(runCtx context.Context, runDone chan<- struct{},
	runTrigger <-chan context.Context, runResult chan<- error,
	updateTrigger <-chan settings.PublicIP, updatedResult chan<- error,
	retryStop <-chan struct{},
) {
	defer close(runDone)

	retries := newRetryState(l.newTimer)
	// Whatever ends the run, no timer is left armed for a failure the run has
	// already dealt with, since nobody stops it once the run goroutine is gone.
	defer retries.stop()

	for {
		var (
			// fetchCtx bounds the fetch: the tunnel session context when a tunnel up
			// asked for the information, and the run context when the loop fetches
			// for itself, the retry being dropped by [Loop.ClearData].
			fetchCtx context.Context
			// fetchedResult carries the outcome back to whoever asked for it, and is
			// nil when the retry the loop booked for itself woke it up.
			fetchedResult chan<- error
		)

		select {
		case <-runCtx.Done():
			return
		case fetchCtx = <-runTrigger:
			// Note fetchCtx is canceled if runCtx is canceled.
			fetchedResult = runResult
			// The tunnel came up, so the attempt booked for the failure before it is
			// superseded, and a fresh connection is a fresh chance: the delays of the
			// failures to come start over, whether the outage before it ended with a
			// fetch which went through or not.
			retries.stop()
			retries.reset()
		case partialUpdate := <-updateTrigger:
			updatedResult <- l.update(partialUpdate)
			continue
		case <-retryStop:
			// The VPN connection went down: fetching with it down answers nothing but
			// timeouts, and the tunnel up which follows triggers a fetch of its own.
			retries.stop()
			continue
		case <-retries.after:
			// The attempt booked is over, the timer has nothing left to stop.
			retries.timer, retries.after = nil, nil
			fetchCtx = runCtx
		}

		if !*l.settings.Enabled {
			if fetchedResult != nil {
				fetchedResult <- nil
			}
			continue
		}

		err := l.fetchAndStore(fetchCtx)
		if err != nil {
			booked := retries.failure()
			// The delay of the attempt booked belongs to the report, so whoever reads
			// it knows the failure is not the end of the story.
			err = fmt.Errorf("%w - retrying in %s (attempt %d)",
				err, booked.Delay, booked.Attempts)
		}

		if fetchedResult != nil {
			// Whoever asked for this fetch waits for its outcome, whatever the loop
			// does next.
			fetchedResult <- err
			continue
		}
		if err != nil {
			// Nobody asked for this fetch, so nobody else reports its failure.
			l.logger.Error(err.Error())
		}
	}
}

func (l *Loop) fetchAndStore(ctx context.Context) (err error) {
	result, err := l.fetcher.FetchInfo(ctx, netip.Addr{})
	if err != nil {
		return fmt.Errorf("fetching information: %w", err)
	}

	message := "Public IP address is " + result.IP.String()
	message += " (" + result.Country + ", " + result.Region + ", " + result.City +
		" - source: " + l.fetcher.String() + ")"
	l.logger.Info(message)

	l.ipDataMutex.Lock()
	l.ipData = result
	l.ipDataMutex.Unlock()

	filepath := *l.settings.IPFilepath
	err = l.persistPublicIP(filepath, result.IP.String())
	if err != nil {
		return fmt.Errorf("persisting public ip address: %w", err)
	}

	return nil
}

func (l *Loop) RunOnce(ctx context.Context) (err error) {
	singleRunCtx, singleRunCancel := context.WithCancel(ctx)
	select {
	case l.runTrigger <- singleRunCtx:
	case <-ctx.Done(): // in case writing to run trigger is blocking
		singleRunCancel()
		return ctx.Err()
	}

	select {
	case err = <-l.runResult:
		singleRunCancel()
		return err
	case <-l.runCtx.Done():
		singleRunCancel()
		<-l.runResult
		return l.runCtx.Err()
	}
}

func (l *Loop) UpdateWith(partialUpdate settings.PublicIP) (err error) {
	select {
	case l.updateTrigger <- partialUpdate:
		select {
		case err = <-l.updatedResult:
			return err
		case <-l.runCtx.Done():
			return l.runCtx.Err()
		}
	case <-l.runCtx.Done():
		// loop has been stopped, no update can be done
		return l.runCtx.Err()
	}
}

func (l *Loop) Stop() (err error) {
	l.runCancel()
	<-l.runDone
	return l.ClearData()
}

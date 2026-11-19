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
	// Mock functions
	timeNow func() time.Time
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

	go l.run(l.runCtx, runDone, runTrigger, runResult, updateTrigger, updatedResult)

	return nil, nil //nolint:nilnil
}

func (l *Loop) run(runCtx context.Context, runDone chan<- struct{},
	runTrigger <-chan context.Context, runResult chan<- error,
	updateTrigger <-chan settings.PublicIP, updatedResult chan<- error,
) {
	defer close(runDone)

	for {
		var singleRunCtx context.Context
		var singleRunResult chan<- error
		select {
		case <-runCtx.Done():
			return
		case singleRunCtx = <-runTrigger:
			// Note singleRunCtx is canceled if runCtx is canceled.
			singleRunResult = runResult
		case partialUpdate := <-updateTrigger:
			var err error
			err = l.update(partialUpdate)
			updatedResult <- err
			continue
		}

		if !*l.settings.Enabled {
			singleRunResult <- nil
			continue
		}

		result, err := l.fetcher.FetchInfo(singleRunCtx, netip.Addr{})
		if err != nil {
			err = fmt.Errorf("fetching information: %w", err)
			singleRunResult <- err
			continue
		}

		message := "Public IP address is " + result.IP.String()
		message += " (" + result.Country + ", " + result.Region + ", " + result.City +
			" - source: " + l.fetcher.String() + ")"
		l.logger.Info(message)

		l.ipDataMutex.Lock()
		l.ipData = result
		l.ipDataMutex.Unlock()

		filepath := *l.settings.IPFilepath
		err = persistPublicIP(filepath, result.IP.String(), l.puid, l.pgid)
		if err != nil {
			err = fmt.Errorf("persisting public ip address: %w", err)
		}

		singleRunResult <- err
	}
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

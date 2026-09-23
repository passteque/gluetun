package httpproxy

import (
	"context"
	"net/http"
	"sync"
	"time"
)

type Server struct {
	address           string
	handler           http.Handler
	logger            infoErrorer
	internalWG        *sync.WaitGroup
	readHeaderTimeout time.Duration
	readTimeout       time.Duration
}

func New(ctx context.Context, address string, logger Logger,
	stealth, verbose bool, username, password string,
	readHeaderTimeout, readTimeout time.Duration,
) *Server {
	wg := &sync.WaitGroup{}
	return &Server{
		address:           address,
		handler:           newHandler(ctx, wg, logger, stealth, verbose, username, password),
		logger:            logger,
		internalWG:        wg,
		readHeaderTimeout: readHeaderTimeout,
		readTimeout:       readTimeout,
	}
}

func (s *Server) Run(ctx context.Context, errorCh chan<- error) {
	server := http.Server{
		Addr:              s.address,
		Handler:           s.handler,
		ReadHeaderTimeout: s.readHeaderTimeout,
		ReadTimeout:       s.readTimeout,
	}
	go func() { //nolint:gosec
		<-ctx.Done()
		const shutdownGraceDuration = 100 * time.Millisecond
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGraceDuration)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			s.logger.Error("failed shutting down: " + err.Error())
		}
	}()
	s.logger.Info("listening on " + s.address)
	err := server.ListenAndServe()
	s.internalWG.Wait()
	if err != nil && ctx.Err() == nil {
		errorCh <- err
	} else {
		errorCh <- nil
	}
}

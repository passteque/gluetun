package healthcheck

import (
	"context"
	"errors"
	"net/http"
	"time"
)

func (s *Server) Run(ctx context.Context, done chan<- struct{}) {
	defer close(done)

	const readHeaderTimeout = 100 * time.Millisecond
	const readTimeout = 500 * time.Millisecond
	server := http.Server{
		Addr:              s.config.ServerAddress,
		Handler:           s.handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
	}
	serverDone := make(chan struct{})
	go func() { //nolint:gosec
		defer close(serverDone)
		<-ctx.Done()
		const shutdownGraceDuration = 2 * time.Second
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGraceDuration)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			s.logger.Error("failed shutting down: " + err.Error())
		}
	}()

	s.logger.Info("listening on " + s.config.ServerAddress)
	err := server.ListenAndServe()
	if err != nil && !errors.Is(ctx.Err(), context.Canceled) {
		s.logger.Error(err.Error())
	}

	<-serverDone
}

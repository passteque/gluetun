package httpserver

import (
	"context"
	"errors"
	"net"
	"net/http"
)

// Run runs the HTTP server until ctx is canceled.
// The done channel has an error written to when the HTTP server
// is terminated, and can be nil or not nil.
func (s *Server) Run(ctx context.Context, ready chan<- struct{}, done chan<- struct{}) {
	server := http.Server{
		Addr:              s.address,
		Handler:           s.handler,
		ReadHeaderTimeout: s.readHeaderTimeout,
		ReadTimeout:       s.readTimeout,
	}

	crashed := make(chan struct{})
	shutdownDone := make(chan struct{})
	listenCtx, listenCancel := context.WithCancel(ctx)
	go func() { //nolint:gosec
		defer close(shutdownDone)
		defer listenCancel()
		select {
		case <-ctx.Done():
		case <-crashed:
			return
		}

		shutdownCtx, cancel := context.WithTimeout(
			context.Background(), s.shutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			s.logger.Error("http server failed shutting down within " +
				s.shutdownTimeout.String())
		}
	}()

	listenConfig := &net.ListenConfig{}
	listener, err := listenConfig.Listen(listenCtx, "tcp", s.address)
	if err != nil {
		close(s.addressSet)
		close(crashed) // stop shutdown goroutine
		<-shutdownDone
		s.logger.Error(err.Error())
		close(done)
		return
	}

	s.address = listener.Addr().String()
	close(s.addressSet)

	// note: no further write so no need to mutex
	s.logger.Info("http server listening on " + s.address)
	close(ready)

	err = server.Serve(listener)

	if err != nil && !errors.Is(ctx.Err(), context.Canceled) {
		// server crashed
		close(crashed) // stop shutdown goroutine
	} else {
		err = nil
	}
	<-shutdownDone
	if err != nil {
		s.logger.Error(err.Error())
	}
	close(done)
}

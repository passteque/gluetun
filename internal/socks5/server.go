package socks5

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
)

type server struct {
	username string
	password string
	address  string
	logger   Logger

	// internal fields
	tcpListener     net.Listener
	udpRouter       *udpRouter
	listening       atomic.Bool
	socksConnCtx    context.Context //nolint:containedctx
	socksConnCancel context.CancelFunc
	done            <-chan error
	stopCh          chan<- struct{}
}

func newServer(settings Settings) *server {
	return &server{
		username: settings.Username,
		password: settings.Password,
		address:  settings.Address,
		logger:   settings.Logger,
	}
}

func (s *server) String() string {
	return "SOCKS5 server"
}

func (s *server) Start(ctx context.Context) (runErr <-chan error, err error) {
	s.socksConnCtx, s.socksConnCancel = context.WithCancel(context.Background())
	config := &net.ListenConfig{}
	s.tcpListener, err = config.Listen(ctx, "tcp", s.address)
	if err != nil {
		return nil, fmt.Errorf("TCP listening on %s: %w", s.address, err)
	}

	s.udpRouter, err = newUDPRouter(ctx, s.address, s.logger)
	if err != nil {
		_ = s.tcpListener.Close()
		return nil, fmt.Errorf("creating UDP router: %w", err)
	}
	s.listening.Store(true)
	s.logger.Infof("SOCKS5 TCP server listening on %s", s.tcpListener.Addr())
	s.logger.Infof("SOCKS5 UDP server listening on %s", s.udpRouter.localAddress())

	ready := make(chan struct{})
	runErrCh := make(chan error)
	runErr = runErrCh
	done := make(chan error)
	s.done = done
	stop := make(chan struct{})
	s.stopCh = stop
	go s.runServer(ready, runErrCh, stop, done)
	select {
	case <-ready:
	case <-ctx.Done():
		_ = s.Stop()
		return nil, fmt.Errorf("starting server: %w", ctx.Err())
	}
	return runErr, nil
}

func (s *server) runServer(ready chan<- struct{},
	runErrCh chan<- error, stop <-chan struct{}, done chan<- error,
) {
	close(ready)
	defer close(done)

	udpErrCh := make(chan error)
	go func() {
		udpErrCh <- s.udpRouter.run(s.socksConnCtx)
	}()

	tcpErrCh := make(chan error)
	go func() {
		var wg sync.WaitGroup
		defer wg.Wait()

		dialer := &net.Dialer{}
		for {
			connection, err := s.tcpListener.Accept()
			if err != nil {
				s.socksConnCancel() // stop ongoing TCP socks connections - no impact on UDP
				tcpErrCh <- fmt.Errorf("accepting connection: %w", err)
				return
			}
			wg.Go(func() {
				connection := connection // capture loop variable
				socksConn := &socksConn{
					dialer:     dialer,
					username:   s.username,
					password:   s.password,
					clientConn: connection,
					udpRouter:  s.udpRouter,
					logger:     s.logger,
				}
				err := socksConn.run(s.socksConnCtx)
				if err != nil {
					s.logger.Infof("running socks connection: %s", err)
				}
			})
		}
	}()

	select {
	case <-stop:
		s.listening.Store(false)
		var errs []error
		err := s.tcpListener.Close()
		if err != nil {
			errs = append(errs, fmt.Errorf("closing TCP listener: %w", err))
		}
		// stop ongoing TCP socks connections. This impacts the udpRouter run error when it is being closed.
		s.socksConnCancel()
		<-tcpErrCh // wait for TCP server to stop
		err = s.udpRouter.close()
		if err != nil {
			errs = append(errs, fmt.Errorf("closing UDP router: %w", err))
		}
		<-udpErrCh // wait for UDP router to stop
		if len(errs) > 0 {
			// Only write to the done channel if the [server.Stop] method is waiting to read from it
			done <- errors.Join(errs...)
		}
		// If no error, the done channel is closed so the error is effectively `nil`
		// Note: do NOT write an error the runError channel, since we are stopping the server gracefully.
	case err := <-udpErrCh:
		_ = s.tcpListener.Close() // stop accepting new TCP connections
		s.socksConnCancel()       // stop ongoing TCP socks connections
		<-tcpErrCh                // wait for TCP server to stop
		runErrCh <- fmt.Errorf("running UDP router: %w", err)
	case err := <-tcpErrCh:
		s.socksConnCancel()
		_ = s.udpRouter.close() // stop UDP router
		<-udpErrCh              // wait for UDP router to stop
		runErrCh <- fmt.Errorf("running TCP server: %w", err)
	}
}

func (s *server) Stop() (err error) {
	close(s.stopCh)
	return <-s.done
}

func (s *server) listeningAddress() net.Addr {
	if s.listening.Load() {
		return s.tcpListener.Addr()
	}
	return nil
}

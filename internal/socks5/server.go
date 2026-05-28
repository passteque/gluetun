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
	done            <-chan struct{}
	stopping        atomic.Bool
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
	done := make(chan struct{})
	s.done = done
	go s.runServer(ready, runErrCh, done)
	select {
	case <-ready:
	case <-ctx.Done():
		_ = s.Stop()
		return nil, fmt.Errorf("starting server: %w", ctx.Err())
	}
	return runErr, nil
}

func (s *server) runServer(ready chan<- struct{},
	runErrCh chan<- error, done chan<- struct{},
) {
	close(ready)
	defer close(done)
	wg := new(sync.WaitGroup)
	defer wg.Wait()

	wg.Go(func() {
		err := s.udpRouter.run(s.socksConnCtx)
		if err != nil {
			if !s.stopping.Load() {
				_ = s.stop()
				runErrCh <- fmt.Errorf("running UDP router: %w", err)
			}
		}
	})

	dialer := &net.Dialer{}
	for {
		connection, err := s.tcpListener.Accept()
		if err != nil {
			if !s.stopping.Load() {
				_ = s.stop()
				runErrCh <- fmt.Errorf("accepting connection: %w", err)
			}
			return
		}
		wg.Add(1)
		go func(ctx context.Context, connection net.Conn,
			dialer *net.Dialer, wg *sync.WaitGroup,
		) {
			defer wg.Done()
			socksConn := &socksConn{
				dialer:     dialer,
				username:   s.username,
				password:   s.password,
				clientConn: connection,
				udpRouter:  s.udpRouter,
				logger:     s.logger,
			}
			err := socksConn.run(ctx)
			if err != nil {
				s.logger.Infof("running socks connection: %s", err)
			}
		}(s.socksConnCtx, connection, dialer, wg)
	}
}

func (s *server) Stop() (err error) {
	s.stopping.Store(true)
	err = s.stop()
	<-s.done // wait for run goroutine to finish
	s.stopping.Store(false)
	return err
}

func (s *server) stop() error {
	s.listening.Store(false)
	var errs []error
	err := s.tcpListener.Close()
	if err != nil {
		errs = append(errs, fmt.Errorf("closing TCP listener: %w", err))
	}
	err = s.udpRouter.close()
	if err != nil {
		errs = append(errs, fmt.Errorf("closing UDP router: %w", err))
	}
	s.socksConnCancel() // stop ongoing socks connections
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (s *server) listeningAddress() net.Addr {
	if s.listening.Load() {
		return s.tcpListener.Addr()
	}
	return nil
}

package socks5

import (
	"context"
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
	listener        net.Listener
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
	s.listener, err = config.Listen(s.socksConnCtx, "tcp", s.address)
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", s.address, err)
	}
	s.listening.Store(true)

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

	dialer := &net.Dialer{}
	for {
		connection, err := s.listener.Accept()
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
	err := s.listener.Close()
	s.socksConnCancel() // stop ongoing socks connections
	return err
}

func (s *server) listeningAddress() net.Addr {
	if s.listening.Load() {
		return s.listener.Addr()
	}
	return nil
}

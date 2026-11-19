package httpserver

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	gomock "go.uber.org/mock/gomock"
)

func Test_Server_Run_success(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	logger := NewMockLogger(ctrl)
	logger.EXPECT().Info(newRegexMatcher("^http server listening on 127.0.0.1:[1-9][0-9]{0,4}$"))
	const shutdownTimeout = 10 * time.Second

	server := &Server{
		address:         "127.0.0.1:0",
		addressSet:      make(chan struct{}),
		logger:          logger,
		shutdownTimeout: shutdownTimeout,
	}

	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	done := make(chan struct{})

	go server.Run(ctx, ready, done)

	addressRegex := regexp.MustCompile(`^127.0.0.1:[1-9][0-9]{0,4}$`)
	address := server.GetAddress()
	assert.Regexp(t, addressRegex, address)
	address = server.GetAddress()
	assert.Regexp(t, addressRegex, address)

	<-ready

	cancel()
	_, ok := <-done
	assert.False(t, ok)
}

func Test_Server_Run_failure(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	logger := NewMockLogger(ctrl)
	logger.EXPECT().Error("listen tcp: address -1: invalid port")

	server := &Server{
		address:    "127.0.0.1:-1",
		addressSet: make(chan struct{}),
		logger:     logger,
	}

	ready := make(chan struct{})
	done := make(chan struct{})

	go server.Run(context.Background(), ready, done)

	select {
	case <-ready:
		t.Fatal("server should not be ready")
	case _, ok := <-done:
		assert.False(t, ok)
	}
}

// Package noop offers a New function returning a no-op
// metrics service, used when metrics are not needed.
package noop

import "context"

// Service is a no-op metrics service.
type Service struct{}

func (s *Service) String() string {
	return "noop metrics service"
}

func (s *Service) Start(context.Context) (runError <-chan error, startErr error) {
	return nil, nil //nolint:nilnil
}

func (s *Service) Stop() (err error) {
	return nil
}

// New creates a new no-op metrics service.
func New() (service *Service, err error) {
	return &Service{}, nil
}

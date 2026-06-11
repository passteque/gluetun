package icmp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrNotPermitted                            = errors.New("ICMP not permitted")
	errCommunicationAdministrativelyProhibited = errors.New("communication administratively prohibited")
	ErrMTUNotFound                             = errors.New("MTU not found")
	errTimeout                                 = errors.New("operation timed out")
)

func wrapConnErr(err error, timedCtx context.Context, pingTimeout time.Duration) error { //nolint:revive
	switch {
	case strings.HasSuffix(err.Error(), "sendto: operation not permitted"):
		err = fmt.Errorf("%w", ErrNotPermitted)
	case errors.Is(timedCtx.Err(), context.DeadlineExceeded):
		err = fmt.Errorf("%w: after %s", errTimeout, pingTimeout)
	case timedCtx.Err() != nil:
		err = timedCtx.Err()
	}
	return err
}

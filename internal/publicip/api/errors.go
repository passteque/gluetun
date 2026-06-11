package api

import "errors"

var ErrTooManyRequests = errors.New("too many requests sent for this month")

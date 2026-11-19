package unzip

import (
	"context"
	"net/http"
)

type Unzipper struct {
	client *http.Client
}

type contextKey int

const (
	userAgentContextKey contextKey = iota
)

func WithUserAgent(ctx context.Context, userAgent string) context.Context {
	return context.WithValue(ctx, userAgentContextKey, userAgent)
}

func New(client *http.Client) *Unzipper {
	return &Unzipper{
		client: client,
	}
}

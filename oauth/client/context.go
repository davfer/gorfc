package client

import "context"

type contextKey int

const (
	clientContextKey contextKey = iota
)

// WithContext returns a new Context carrying the authenticated Client.
func WithContext(ctx context.Context, c Client) context.Context {
	return context.WithValue(ctx, clientContextKey, c)
}

// FromContext extracts the authenticated Client from Context, if present.
func FromContext(ctx context.Context) (Client, bool) {
	c, ok := ctx.Value(clientContextKey).(Client)
	return c, ok
}

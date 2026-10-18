package identity

import "context"

type contextKey int

const (
	identityContextKey contextKey = iota
)

// WithContext returns a new Context carrying the authenticated Identity.
func WithContext(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityContextKey, id)
}

// FromContext extracts the authenticated Identity from Context, if present.
func FromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityContextKey).(Identity)
	return id, ok
}

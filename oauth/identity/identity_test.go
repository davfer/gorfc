package identity

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIdentityContext(t *testing.T) {
	ctx := context.Background()
	id := SimpleIdentity{Sub: "user123"}

	assert.Equal(t, "user123", id.Subject())

	_, ok := FromContext(ctx)
	assert.False(t, ok)

	ctxWithIdentity := WithContext(ctx, id)
	retrieved, ok := FromContext(ctxWithIdentity)
	assert.True(t, ok)
	assert.Equal(t, id, retrieved)
}

package client

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClientInterfacesAndDefaultClient(t *testing.T) {
	c := &DefaultClient{
		ID:                  "client1",
		AllowedRedirectURIs: []string{"https://example.com/cb"},
		AllowedGrantTypes:   []string{"authorization_code"},
		RequirePKCE:         true,
	}

	assert.Equal(t, "client1", c.ClientID())
	assert.True(t, ValidateGrantType(c, "authorization_code"))
	assert.False(t, ValidateGrantType(c, "password"))
	assert.True(t, ValidateRedirectURI(c, "https://example.com/cb"))
	assert.False(t, ValidateRedirectURI(c, "https://evil.com/cb"))
	assert.True(t, RequiresPKCE(c))
}

func TestClientContext(t *testing.T) {
	ctx := context.Background()
	c := &DefaultClient{ID: "client123"}

	_, ok := FromContext(ctx)
	assert.False(t, ok)

	ctxWithClient := WithContext(ctx, c)
	retrieved, ok := FromContext(ctxWithClient)
	assert.True(t, ok)
	assert.Equal(t, c, retrieved)
}

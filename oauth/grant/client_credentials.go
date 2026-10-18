package grant

import (
	"context"

	"github.com/davfer/gorfc/oauth/client"
	"github.com/davfer/gorfc/rfc6749"
)

// ClientCredentialsGrant handles the client_credentials grant type.
// Reference: RFC 6749 Section 4.4.2
type ClientCredentialsGrant struct {
	tokenIssuer TokenIssuer
}

// NewClientCredentialsGrant creates a new ClientCredentialsGrant instance.
func NewClientCredentialsGrant(tokenIssuer TokenIssuer) *ClientCredentialsGrant {
	return &ClientCredentialsGrant{tokenIssuer: tokenIssuer}
}

// HandleToken processes a client_credentials token request.
func (c *ClientCredentialsGrant) HandleToken(ctx context.Context, req rfc6749.TokenRequest) (*rfc6749.TokenResponse, error) {
	cl, _ := client.FromContext(ctx)
	return c.tokenIssuer.IssueToken(ctx, req, cl)
}

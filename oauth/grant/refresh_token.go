package grant

import (
	"context"

	"github.com/davfer/gorfc/oauth/client"
	"github.com/davfer/gorfc/rfc6749"
)

// TokenRefresher handles refreshing access tokens.
type TokenRefresher interface {
	RefreshToken(ctx context.Context, req rfc6749.TokenRequest, c client.Client) (*rfc6749.TokenResponse, error)
}

// RefreshTokenGrant handles the refresh_token grant type.
// Reference: RFC 6749 Section 6
type RefreshTokenGrant struct {
	tokenRefresher TokenRefresher
}

// NewRefreshTokenGrant creates a new RefreshTokenGrant instance.
func NewRefreshTokenGrant(tokenRefresher TokenRefresher) *RefreshTokenGrant {
	return &RefreshTokenGrant{tokenRefresher: tokenRefresher}
}

// HandleToken processes a refresh_token token request.
func (r *RefreshTokenGrant) HandleToken(ctx context.Context, req rfc6749.TokenRequest) (*rfc6749.TokenResponse, error) {
	c, _ := client.FromContext(ctx)
	refreshToken := req.Get("refresh_token")
	if refreshToken == "" {
		return nil, rfc6749.ProtocolError{Response: rfc6749.ErrorResponse{
			Error: rfc6749.ErrInvalidRequest,
		}}
	}
	return r.tokenRefresher.RefreshToken(ctx, req, c)
}

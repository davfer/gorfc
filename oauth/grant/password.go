package grant

import (
	"context"
	"errors"

	"github.com/davfer/gorfc/oauth/client"
	"github.com/davfer/gorfc/oauth/identity"
	"github.com/davfer/gorfc/rfc6749"
)

// UserCredentialsValidator abstracts validation of resource owner username and password credentials.
// Reference: RFC 6749, Section 4.3.2
type UserCredentialsValidator interface {
	ValidateCredentials(ctx context.Context, username string, password string) (identity.Identity, error)
}

// PasswordGrant handles the Resource Owner Password Credentials grant type.
// Reference: RFC 6749 Section 4.3.2
type PasswordGrant struct {
	validator   UserCredentialsValidator
	tokenIssuer TokenIssuer
}

// NewPasswordGrant creates a new PasswordGrant instance with injected validator and token issuer.
func NewPasswordGrant(validator UserCredentialsValidator, tokenIssuer TokenIssuer) *PasswordGrant {
	return &PasswordGrant{
		validator:   validator,
		tokenIssuer: tokenIssuer,
	}
}

// HandleToken processes a resource owner password credentials token request.
func (p *PasswordGrant) HandleToken(ctx context.Context, req rfc6749.TokenRequest) (*rfc6749.TokenResponse, error) {
	c, _ := client.FromContext(ctx)
	username := req.Get("username")
	password := req.Get("password")
	if username == "" || password == "" {
		return nil, rfc6749.ProtocolError{Response: rfc6749.ErrorResponse{
			Error: rfc6749.ErrInvalidRequest,
		}}
	}

	id, err := p.validator.ValidateCredentials(ctx, username, password)
	if err != nil {
		var protoErr rfc6749.ProtocolError
		if errors.As(err, &protoErr) {
			return nil, protoErr
		}
		return nil, rfc6749.ProtocolError{Response: rfc6749.ErrorResponse{
			Error: rfc6749.ErrInvalidGrant,
		}}
	}
	if id == nil {
		return nil, rfc6749.ProtocolError{Response: rfc6749.ErrorResponse{
			Error: rfc6749.ErrInvalidGrant,
		}}
	}

	ctx = identity.WithContext(ctx, id)

	return p.tokenIssuer.IssueToken(ctx, req, c)
}

package grant

import (
	"context"
	"strconv"

	"github.com/davfer/gorfc/oauth/authorize"
	"github.com/davfer/gorfc/oauth/client"
	"github.com/davfer/gorfc/oauth/identity"
	"github.com/davfer/gorfc/rfc6749"
)

// ImplicitGrant handles the Implicit Grant flow for authorization requests (response_type=token).
// Reference: RFC 6749 Section 4.2
type ImplicitGrant struct {
	tokenIssuer TokenIssuer
}

// NewImplicitGrant creates a new ImplicitGrant instance.
func NewImplicitGrant(tokenIssuer TokenIssuer) *ImplicitGrant {
	return &ImplicitGrant{
		tokenIssuer: tokenIssuer,
	}
}

// HandleAuthorize processes an implicit grant authorization request (response_type=token).
// Reference: RFC 6749 Section 4.2.2
func (g *ImplicitGrant) HandleAuthorize(ctx context.Context, req rfc6749.AuthorizationRequest) (*authorize.AuthorizeResponse, error) {
	if g.tokenIssuer == nil {
		return nil, rfc6749.ProtocolError{Response: rfc6749.ErrorResponse{
			Error: rfc6749.ErrServerError,
			State: req.State,
		}}
	}

	id, ok := identity.FromContext(ctx)
	if !ok || id == nil {
		return nil, rfc6749.ProtocolError{Response: rfc6749.ErrorResponse{
			Error: rfc6749.ErrAccessDenied,
			State: req.State,
		}}
	}

	c, _ := client.FromContext(ctx)

	tokenReq := rfc6749.TokenRequest{
		GrantType: "implicit",
		Scope:     req.Scope,
	}

	tokenResp, err := g.tokenIssuer.IssueToken(ctx, tokenReq, c)
	if err != nil || tokenResp == nil {
		return nil, rfc6749.ProtocolError{Response: rfc6749.ErrorResponse{
			Error: rfc6749.ErrServerError,
			State: req.State,
		}}
	}

	params := map[string]string{
		"access_token": tokenResp.AccessToken,
		"token_type":   tokenResp.TokenType,
	}
	if tokenResp.ExpiresIn > 0 {
		params["expires_in"] = strconv.FormatInt(tokenResp.ExpiresIn, 10)
	}
	if tokenResp.Scope != "" {
		params["scope"] = tokenResp.Scope
	}

	return &authorize.AuthorizeResponse{
		State:       req.State,
		Params:      params,
		UseFragment: true, // RFC 6749 Section 4.2.2 requires parameters in URI fragment
	}, nil
}

package grant

import (
	"context"

	"github.com/davfer/gorfc/oauth/authorize"
	"github.com/davfer/gorfc/oauth/client"
	"github.com/davfer/gorfc/oauth/identity"
	"github.com/davfer/gorfc/rfc6749"
	"github.com/davfer/gorfc/rfc7636"
)

// AuthorizationCode represents a short-lived code generated during the Authorization Code flow.
type AuthorizationCode struct {
	Code                string `json:"code"`
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope"`
	Subject             string `json:"subject"`
	CodeChallenge       string `json:"code_challenge,omitempty"`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`
	ExpiresAt           int64  `json:"expires_at"`
	Used                bool   `json:"used"`
}

// CodeExchanger abstracts exchanging an authorization code for authorization details.
type CodeExchanger interface {
	ExchangeCode(ctx context.Context, code string, clientID string, redirectURI string) (*AuthorizationCode, error)
}

// CodeCreator abstracts creating an authorization code.
type CodeCreator interface {
	CreateCode(ctx context.Context, req rfc6749.AuthorizationRequest, subject string) (*AuthorizationCode, error)
}

// TokenIssuer handles issuing access tokens.
type TokenIssuer interface {
	IssueToken(ctx context.Context, req rfc6749.TokenRequest, c client.Client) (*rfc6749.TokenResponse, error)
}

// AuthorizationCodeGrant handles the authorization_code grant type with optional or enforced PKCE support.
// Reference: RFC 6749 Section 4.1.3 & RFC 7636 Section 4.6
type AuthorizationCodeGrant struct {
	codeExchanger CodeExchanger
	tokenIssuer   TokenIssuer
	codeCreator   CodeCreator
}

// NewAuthorizationCodeGrant creates a new AuthorizationCodeGrant instance.
func NewAuthorizationCodeGrant(codeExchanger CodeExchanger, tokenIssuer TokenIssuer) *AuthorizationCodeGrant {
	return &AuthorizationCodeGrant{
		codeExchanger: codeExchanger,
		tokenIssuer:   tokenIssuer,
	}
}

// NewAuthorizationCodeGrantFull creates an AuthorizationCodeGrant instance supporting both authorization and token endpoints.
func NewAuthorizationCodeGrantFull(
	codeExchanger CodeExchanger,
	tokenIssuer TokenIssuer,
	codeCreator CodeCreator,
) *AuthorizationCodeGrant {
	return &AuthorizationCodeGrant{
		codeExchanger: codeExchanger,
		tokenIssuer:   tokenIssuer,
		codeCreator:   codeCreator,
	}
}

// HandleAuthorize processes an authorization_code authorization request (response_type=code).
// Reference: RFC 6749 Section 4.1.1 & 4.1.2
func (a *AuthorizationCodeGrant) HandleAuthorize(ctx context.Context, req rfc6749.AuthorizationRequest) (*authorize.AuthorizeResponse, error) {
	if a.codeCreator == nil {
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
	code, err := a.codeCreator.CreateCode(ctx, req, id.Subject())
	if err != nil || code == nil {
		return nil, rfc6749.ProtocolError{Response: rfc6749.ErrorResponse{
			Error: rfc6749.ErrServerError,
			State: req.State,
		}}
	}
	return &authorize.AuthorizeResponse{
		Code:  code.Code,
		State: req.State,
	}, nil
}

// HandleToken processes an authorization_code token request.
func (a *AuthorizationCodeGrant) HandleToken(ctx context.Context, req rfc6749.TokenRequest) (*rfc6749.TokenResponse, error) {
	if a.codeExchanger == nil || a.tokenIssuer == nil {
		return nil, rfc6749.ProtocolError{Response: rfc6749.ErrorResponse{
			Error: rfc6749.ErrServerError,
		}}
	}
	c, _ := client.FromContext(ctx)
	code := req.Get("code")
	if code == "" || !rfc6749.IsValidCode(code) {
		return nil, rfc6749.ProtocolError{Response: rfc6749.ErrorResponse{
			Error: rfc6749.ErrInvalidRequest,
		}}
	}
	var clientID string
	if c != nil {
		clientID = c.ClientID()
	}
	authCode, err := a.codeExchanger.ExchangeCode(ctx, code, clientID, req.Get("redirect_uri"))
	if err != nil || authCode == nil {
		return nil, rfc6749.ProtocolError{Response: rfc6749.ErrorResponse{
			Error: rfc6749.ErrInvalidGrant,
		}}
	}

	if authCode.Subject != "" {
		ctx = identity.WithContext(ctx, identity.SimpleIdentity{Sub: authCode.Subject})
	}

	// PKCE Verification (RFC 7636 Section 4.6)
	// PKCE is enforced if client implements PKCEClient and RequiresPKCE() returns true,
	// OR if code_challenge was recorded on the authorization code.
	requiresPKCE := c != nil && client.RequiresPKCE(c)
	if requiresPKCE || authCode.CodeChallenge != "" {
		verifier := req.Get(rfc7636.ParamCodeVerifier)
		if verifier == "" || !rfc7636.IsValidCodeVerifier(verifier) {
			return nil, rfc6749.ProtocolError{Response: rfc6749.ErrorResponse{
				Error:            rfc6749.ErrInvalidGrant,
				ErrorDescription: "code_verifier is required and must be valid",
			}}
		}
		if !rfc7636.VerifyCodeVerifier(verifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
			return nil, rfc6749.ProtocolError{Response: rfc6749.ErrorResponse{
				Error:            rfc6749.ErrInvalidGrant,
				ErrorDescription: "code_verifier verification failed",
			}}
		}
	}

	return a.tokenIssuer.IssueToken(ctx, req, c)
}

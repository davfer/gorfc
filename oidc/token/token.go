package token

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/davfer/gorfc/oauth/client"
	oauthIdentity "github.com/davfer/gorfc/oauth/identity"
	oauthToken "github.com/davfer/gorfc/oauth/token"
	"github.com/davfer/gorfc/oidc/authorize"
	"github.com/davfer/gorfc/oidc/identity"
	"github.com/davfer/gorfc/oidc/idtoken"
	"github.com/davfer/gorfc/rfc6749"
)

// TokenRequest represents an OpenID Connect Token Request.
// Reference: OpenID Connect Core 1.0, Section 3.1.3.1
type TokenRequest struct {
	GrantType    string `json:"grant_type"`             // REQUIRED
	Code         string `json:"code,omitempty"`         // REQUIRED for authorization_code
	RedirectURI  string `json:"redirect_uri,omitempty"` // REQUIRED for authorization_code
	ClientID     string `json:"client_id,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// TokenResponse represents an OpenID Connect Token Response.
// Reference: OpenID Connect Core 1.0, Section 3.1.3.3
type TokenResponse struct {
	AccessToken  string `json:"access_token"` // REQUIRED
	TokenType    string `json:"token_type"`   // REQUIRED
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	IDToken      string `json:"id_token"` // REQUIRED
}

// TokenService abstracts executing an OAuth 2.0 token grant.
type TokenService interface {
	HandleToken(ctx context.Context, c client.Client, req rfc6749.TokenRequest) (*rfc6749.TokenResponse, error)
}

// TokenHandler handles OpenID Connect Token Endpoint requests.
// It executes underlying OAuth 2.0 grants via TokenService and appends OpenID Connect ID Tokens.
// Reference: OpenID Connect Core 1.0, Section 3.1.3.3
type TokenHandler struct {
	tokenService     TokenService
	clientAuth       oauthToken.ClientAuthenticator
	errHandler       oauthToken.ErrorHandler
	idTokenIssuer    idtoken.IDTokenIssuer
	identityProvider identity.IdentityProvider
}

// NewTokenHandler creates a new OIDC TokenHandler wrapping an OAuth token.TokenHandler.
func NewTokenHandler(oauthHandler *oauthToken.TokenHandler, idTokenIssuer idtoken.IDTokenIssuer, identityProvider identity.IdentityProvider) *TokenHandler {
	var tokenService TokenService
	var clientAuth oauthToken.ClientAuthenticator
	var errHandler oauthToken.ErrorHandler
	if oauthHandler != nil {
		tokenService = oauthHandler.Service()
		clientAuth = oauthHandler.ClientAuthenticator()
		errHandler = oauthHandler.ErrorHandler()
	}
	return NewTokenHandlerFromService(tokenService, clientAuth, errHandler, idTokenIssuer, identityProvider)
}

// NewTokenHandlerFromService creates a new OIDC TokenHandler wrapping a TokenService.
func NewTokenHandlerFromService(
	tokenService TokenService,
	clientAuth oauthToken.ClientAuthenticator,
	errHandler oauthToken.ErrorHandler,
	idTokenIssuer idtoken.IDTokenIssuer,
	identityProvider identity.IdentityProvider,
) *TokenHandler {
	return &TokenHandler{
		tokenService:     tokenService,
		clientAuth:       clientAuth,
		errHandler:       errHandler,
		idTokenIssuer:    idTokenIssuer,
		identityProvider: identityProvider,
	}
}

// ServeHTTP implements http.Handler for the OIDC Token Endpoint.
func (h *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.tokenService == nil {
		http.Error(w, "Token Handler Unavailable", http.StatusInternalServerError)
		return
	}

	// 1. Parse Token Request DTO (RFC 6749 Section 3.2)
	req, err := rfc6749.ParseTokenRequest(r)
	if err != nil {
		var protoErr rfc6749.ProtocolError
		if errors.As(err, &protoErr) {
			h.writeError(w, r, protoErr.Response)
		} else {
			h.writeError(w, r, rfc6749.ErrorResponse{
				Error: rfc6749.ErrInvalidRequest,
			})
		}
		return
	}

	// 2. Authenticate Client (RFC 6749 Section 3.2.1)
	var c client.Client
	if h.clientAuth != nil {
		authClient, err := h.clientAuth.AuthenticateClient(r.Context(), r)
		if err != nil || authClient == nil {
			h.writeError(w, r, rfc6749.ErrorResponse{
				Error: rfc6749.ErrInvalidClient,
			})
			return
		}
		c = authClient
	}

	// 3. Execute OAuth 2.0 grant via TokenService
	tokenResp, err := h.tokenService.HandleToken(r.Context(), c, req)
	if err != nil {
		var protoErr rfc6749.ProtocolError
		var oauthErr oauthToken.OAuthError
		if errors.As(err, &protoErr) {
			h.writeError(w, r, protoErr.Response)
		} else if errors.As(err, &oauthErr) {
			h.writeError(w, r, oauthErr.Response)
		} else {
			h.writeError(w, r, rfc6749.ErrorResponse{
				Error: rfc6749.ErrInvalidGrant,
			})
		}
		return
	}

	// 4. Check if scope includes "openid"
	hasOpenID := false
	for _, s := range strings.Split(tokenResp.Scope, " ") {
		if s == authorize.ScopeOpenID {
			hasOpenID = true
			break
		}
	}

	// If openid scope is not present or no IDTokenIssuer configured, return standard OAuth response
	if !hasOpenID || h.idTokenIssuer == nil {
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(tokenResp)
		return
	}

	// 5. Retrieve identity session for ID Token
	var session identity.Session
	if id, ok := oauthIdentity.FromContext(r.Context()); ok && id != nil && id.Subject() != "" {
		session = &identity.DefaultSession{Sub: id.Subject()}
	}
	if session == nil && h.identityProvider != nil {
		sess, err := h.identityProvider.GetSession(r.Context(), r)
		if err == nil && sess != nil {
			session = sess
		}
	}
	if session == nil {
		session = &identity.DefaultSession{Sub: "unknown_identity"}
	}

	clientID := ""
	if c != nil {
		clientID = c.ClientID()
	}
	if clientID == "" {
		clientID = r.FormValue("client_id")
	}

	idTokenStr, err := h.idTokenIssuer.IssueIDToken(r.Context(), session, clientID, "", tokenResp.AccessToken, "")
	if err != nil || idTokenStr == "" {
		h.writeError(w, r, rfc6749.ErrorResponse{
			Error:            rfc6749.ErrServerError,
			ErrorDescription: "failed to issue ID token",
		})
		return
	}

	oidcResp := TokenResponse{
		AccessToken:  tokenResp.AccessToken,
		TokenType:    tokenResp.TokenType,
		RefreshToken: tokenResp.RefreshToken,
		ExpiresIn:    int(tokenResp.ExpiresIn),
		IDToken:      idTokenStr,
	}

	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(oidcResp)
}

func (h *TokenHandler) writeError(w http.ResponseWriter, r *http.Request, errResp rfc6749.ErrorResponse) {
	if h.errHandler != nil {
		h.errHandler.WriteTokenError(w, r, errResp)
		return
	}
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(errResp)
}

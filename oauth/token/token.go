package token

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/davfer/gorfc/oauth/client"
	"github.com/davfer/gorfc/rfc6749"
)

// Standard HTTP headers and media types used by the Token endpoint.
// Reference: RFC 6749, Section 3.2 & Section 5.1
const (
	HeaderContentType         = rfc6749.HeaderContentType
	HeaderCacheControl        = rfc6749.HeaderCacheControl
	HeaderPragma              = rfc6749.HeaderPragma
	ContentTypeJSON           = rfc6749.ContentTypeJSON
	ContentTypeFormUrlEncoded = rfc6749.ContentTypeFormUrlEncoded
	CacheControlNoStore       = rfc6749.CacheControlNoStore
	PragmaNoCache             = rfc6749.PragmaNoCache
)

// OAuthError wraps an rfc6749.ErrorResponse to satisfy Go's standard error interface.
type OAuthError struct {
	Response rfc6749.ErrorResponse
}

func (e OAuthError) Error() string {
	if e.Response.ErrorDescription != "" {
		return e.Response.Error + ": " + e.Response.ErrorDescription
	}
	return e.Response.Error
}

// GrantHandler abstracts processing for a specific OAuth 2.0 grant type.
// The authenticated Client is implicitly available via context.Context using client.FromContext.
// Reference: RFC 6749, Sections 4 & 6
type GrantHandler interface {
	HandleToken(ctx context.Context, req rfc6749.TokenRequest) (*rfc6749.TokenResponse, error)
}

// GrantHandlerFunc adapter allows standard functions to satisfy the GrantHandler interface.
type GrantHandlerFunc func(ctx context.Context, req rfc6749.TokenRequest) (*rfc6749.TokenResponse, error)

// HandleToken calls the underlying function.
func (f GrantHandlerFunc) HandleToken(ctx context.Context, req rfc6749.TokenRequest) (*rfc6749.TokenResponse, error) {
	return f(ctx, req)
}

// TokenService executes OAuth 2.0 token grants without HTTP transport dependencies.
// Reference: RFC 6749, Sections 4, 5, and 6
type TokenService struct {
	handlers map[string]GrantHandler
}

// NewTokenService creates a new TokenService with the given grant type handlers.
func NewTokenService(handlers map[string]GrantHandler) *TokenService {
	if handlers == nil {
		handlers = make(map[string]GrantHandler)
	}
	return &TokenService{
		handlers: handlers,
	}
}

// RegisterGrantHandler registers or replaces a handler for a given grant_type.
func (s *TokenService) RegisterGrantHandler(grantType string, handler GrantHandler) {
	if s.handlers == nil {
		s.handlers = make(map[string]GrantHandler)
	}
	s.handlers[grantType] = handler
}

// HandleToken executes the token grant for an authenticated client and token request DTO.
// Returns rfc6749.TokenResponse or an error (such as rfc6749.ProtocolError or OAuthError).
// Reference: RFC 6749 Sections 4, 5, and 6
func (s *TokenService) HandleToken(ctx context.Context, c client.Client, req rfc6749.TokenRequest) (*rfc6749.TokenResponse, error) {
	if c == nil {
		return nil, rfc6749.ProtocolError{Response: rfc6749.ErrorResponse{
			Error: rfc6749.ErrInvalidClient,
		}}
	}

	// 1. Verify client is authorized for this grant type (RFC 6749 Section 5.2)
	if !client.ValidateGrantType(c, req.GrantType) {
		return nil, rfc6749.ProtocolError{Response: rfc6749.ErrorResponse{
			Error: rfc6749.ErrUnauthorizedClient,
		}}
	}

	// 2. Lookup Grant Handler (RFC 6749 Section 5.2)
	handler, ok := s.handlers[req.GrantType]
	if !ok {
		return nil, rfc6749.ProtocolError{Response: rfc6749.ErrorResponse{
			Error: rfc6749.ErrUnsupportedGrantType,
		}}
	}

	// 3. Inject Client into Context
	grantCtx := client.WithContext(ctx, c)

	// 4. Execute Grant Handler
	tokenResp, err := handler.HandleToken(grantCtx, req)
	if err != nil {
		return nil, err
	}
	if tokenResp == nil {
		return nil, rfc6749.ProtocolError{Response: rfc6749.ErrorResponse{
			Error: rfc6749.ErrInvalidGrant,
		}}
	}

	return tokenResp, nil
}

// TokenHandler handles OAuth 2.0 Token Endpoint HTTP requests.
// It complies with RFC 6749 Section 3.2 and 5.1.
type TokenHandler struct {
	service    *TokenService
	clientAuth ClientAuthenticator
	errHandler ErrorHandler
}

// NewTokenHandler creates a new TokenHandler with injected dependencies and grant type handlers map.
func NewTokenHandler(
	clientAuth ClientAuthenticator,
	errHandler ErrorHandler,
	handlers map[string]GrantHandler,
) *TokenHandler {
	return NewTokenHandlerFromService(NewTokenService(handlers), clientAuth, errHandler)
}

// NewTokenHandlerFromService creates a new TokenHandler wrapping a TokenService.
func NewTokenHandlerFromService(
	service *TokenService,
	clientAuth ClientAuthenticator,
	errHandler ErrorHandler,
) *TokenHandler {
	if service == nil {
		service = NewTokenService(nil)
	}
	return &TokenHandler{
		service:    service,
		clientAuth: clientAuth,
		errHandler: errHandler,
	}
}

// Service returns the underlying TokenService.
func (h *TokenHandler) Service() *TokenService {
	return h.service
}

// ClientAuthenticator returns the underlying ClientAuthenticator.
func (h *TokenHandler) ClientAuthenticator() ClientAuthenticator {
	return h.clientAuth
}

// ErrorHandler returns the underlying ErrorHandler.
func (h *TokenHandler) ErrorHandler() ErrorHandler {
	return h.errHandler
}

// RegisterGrantHandler registers or replaces a handler for a given grant_type.
func (h *TokenHandler) RegisterGrantHandler(grantType string, handler GrantHandler) {
	h.service.RegisterGrantHandler(grantType, handler)
}

// ServeHTTP implements the http.Handler interface for the token endpoint.
func (h *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Parse & Validate Token Request (RFC 6749 Section 3.2)
	req, err := rfc6749.ParseTokenRequest(r)
	if err != nil {
		var protoErr rfc6749.ProtocolError
		if errors.As(err, &protoErr) {
			h.errHandler.WriteTokenError(w, r, protoErr.Response)
		} else {
			h.errHandler.WriteTokenError(w, r, rfc6749.ErrorResponse{
				Error: rfc6749.ErrInvalidRequest,
			})
		}
		return
	}

	// 2. Authenticate Client (RFC 6749 Section 3.2.1)
	c, err := h.clientAuth.AuthenticateClient(r.Context(), r)
	if err != nil || c == nil {
		h.errHandler.WriteTokenError(w, r, rfc6749.ErrorResponse{
			Error: rfc6749.ErrInvalidClient,
		})
		return
	}

	// 3. Execute Grant via TokenService
	tokenResp, err := h.service.HandleToken(r.Context(), c, req)
	if err != nil {
		var protoErr rfc6749.ProtocolError
		var oauthErr OAuthError
		if errors.As(err, &protoErr) {
			h.errHandler.WriteTokenError(w, r, protoErr.Response)
		} else if errors.As(err, &oauthErr) {
			h.errHandler.WriteTokenError(w, r, oauthErr.Response)
		} else {
			h.errHandler.WriteTokenError(w, r, rfc6749.ErrorResponse{
				Error: rfc6749.ErrInvalidGrant,
			})
		}
		return
	}

	// 4. Write Response (RFC 6749 Section 5.1)
	w.Header().Set(HeaderContentType, ContentTypeJSON)
	w.Header().Set(HeaderCacheControl, CacheControlNoStore)
	w.Header().Set(HeaderPragma, PragmaNoCache)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(tokenResp)
}

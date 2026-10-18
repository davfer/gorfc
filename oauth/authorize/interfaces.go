package authorize

import (
	"context"
	"net/http"

	"github.com/davfer/gorfc/oauth/client"
	"github.com/davfer/gorfc/oauth/identity"
	"github.com/davfer/gorfc/rfc6749"
)

// ClientStore abstracts the lookup of OAuth 2.0 clients.
type ClientStore interface {
	GetClient(ctx context.Context, clientID string) (client.Client, error)
}

// CodeGrantStore manages the lifecycle of authorization codes for the authorize endpoint.
type CodeGrantStore interface {
	CreateCode(ctx context.Context, req rfc6749.AuthorizationRequest, subject string) (code string, err error)
}

// UserConsentDecider abstracts authenticating a resource owner and determining consent.
type UserConsentDecider interface {
	AuthenticateUser(ctx context.Context, r *http.Request) (identity.Identity, error)
}

// HumanInteractionHandler handles requests that require user interaction (e.g., rendering login or consent UI).
type HumanInteractionHandler interface {
	HandleInteraction(w http.ResponseWriter, r *http.Request, req rfc6749.AuthorizationRequest)
}

// HumanInteractionHandlerFunc adapter allows standard functions to satisfy the HumanInteractionHandler interface.
type HumanInteractionHandlerFunc func(w http.ResponseWriter, r *http.Request, req rfc6749.AuthorizationRequest)

// HandleInteraction calls the underlying function.
func (f HumanInteractionHandlerFunc) HandleInteraction(w http.ResponseWriter, r *http.Request, req rfc6749.AuthorizationRequest) {
	f(w, r, req)
}

// AuthorizeResponse represents the output parameters of a successful authorization endpoint handler.
type AuthorizeResponse struct {
	Code        string            `json:"code,omitempty"`
	State       string            `json:"state,omitempty"`
	Params      map[string]string `json:"params,omitempty"`
	UseFragment bool              `json:"use_fragment,omitempty"`
}

// AuthorizeGrantHandler abstracts processing for a specific OAuth 2.0 response_type (e.g., "code", "token").
type AuthorizeGrantHandler interface {
	HandleAuthorize(ctx context.Context, req rfc6749.AuthorizationRequest) (*AuthorizeResponse, error)
}

// AuthorizeGrantHandlerFunc adapter allows standard functions to satisfy the AuthorizeGrantHandler interface.
type AuthorizeGrantHandlerFunc func(ctx context.Context, req rfc6749.AuthorizationRequest) (*AuthorizeResponse, error)

// HandleAuthorize calls the underlying function.
func (f AuthorizeGrantHandlerFunc) HandleAuthorize(ctx context.Context, req rfc6749.AuthorizationRequest) (*AuthorizeResponse, error) {
	return f(ctx, req)
}

// ErrorHandler manages authorization error responses conforming to RFC 6749.
type ErrorHandler interface {
	WriteAuthorizationError(w http.ResponseWriter, r *http.Request, redirectURI string, errResp rfc6749.ErrorResponse)
}

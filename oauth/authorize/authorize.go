package authorize

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/davfer/gorfc/oauth/client"
	"github.com/davfer/gorfc/oauth/identity"
	"github.com/davfer/gorfc/oauth/token"
	"github.com/davfer/gorfc/rfc6749"
)

// ErrNeedsHumanInteraction indicates that the authorization request requires user interaction
// (e.g., displaying a login screen or consent prompt) before it can proceed.
var ErrNeedsHumanInteraction = errors.New("oauth: human interaction required")

// AuthorizeHandler handles OAuth 2.0 Authorization Endpoint requests.
// It complies with RFC 6749 Section 4.1.1 and 4.2.1.
type AuthorizeHandler struct {
	clientStore        ClientStore
	userDecider        UserConsentDecider
	interactionHandler HumanInteractionHandler
	errHandler         ErrorHandler
	handlers           map[string]AuthorizeGrantHandler
}

// NewAuthorizeHandler creates a new AuthorizeHandler with injected dependencies and response type handlers map.
func NewAuthorizeHandler(
	clientStore ClientStore,
	userDecider UserConsentDecider,
	errHandler ErrorHandler,
	handlers map[string]AuthorizeGrantHandler,
) *AuthorizeHandler {
	if handlers == nil {
		handlers = make(map[string]AuthorizeGrantHandler)
	}
	return &AuthorizeHandler{
		clientStore: clientStore,
		userDecider: userDecider,
		errHandler:  errHandler,
		handlers:    handlers,
	}
}

// SetHumanInteractionHandler sets the handler called when user authentication requires human interaction.
func (h *AuthorizeHandler) SetHumanInteractionHandler(handler HumanInteractionHandler) {
	h.interactionHandler = handler
}

// RegisterAuthorizeHandler registers or replaces a handler for a given response_type.
func (h *AuthorizeHandler) RegisterAuthorizeHandler(responseType string, handler AuthorizeGrantHandler) {
	if h.handlers == nil {
		h.handlers = make(map[string]AuthorizeGrantHandler)
	}
	h.handlers[responseType] = handler
}

// ServeHTTP implements the http.Handler interface for the authorization endpoint.
func (h *AuthorizeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Parse parameters from query (GET) or form body (POST)
	if err := r.ParseForm(); err != nil {
		h.errHandler.WriteAuthorizationError(w, r, "", rfc6749.ErrorResponse{
			Error:            rfc6749.ErrInvalidRequest,
			ErrorDescription: "Failed to parse request parameters",
		})
		return
	}

	req := rfc6749.AuthorizationRequest{
		ResponseType: r.FormValue("response_type"),
		ClientID:     r.FormValue("client_id"),
		RedirectURI:  r.FormValue("redirect_uri"),
		Scope:        r.FormValue("scope"),
		State:        r.FormValue("state"),
	}

	// 2. Validate client_id parameter syntax
	if req.ClientID == "" || !rfc6749.IsValidClientID(req.ClientID) {
		h.errHandler.WriteAuthorizationError(w, r, req.RedirectURI, rfc6749.ErrorResponse{
			Error: rfc6749.ErrInvalidRequest,
			State: req.State,
		})
		return
	}

	// 3. Fetch client and validate redirect_uri
	c, err := h.clientStore.GetClient(r.Context(), req.ClientID)
	if err != nil || c == nil {
		h.errHandler.WriteAuthorizationError(w, r, req.RedirectURI, rfc6749.ErrorResponse{
			Error: rfc6749.ErrUnauthorizedClient,
			State: req.State,
		})
		return
	}

	if !client.ValidateRedirectURI(c, req.RedirectURI) {
		// If redirect URI is invalid, we MUST NOT redirect (RFC 6749 Section 4.1.2.1)
		h.errHandler.WriteAuthorizationError(w, r, "", rfc6749.ErrorResponse{
			Error: rfc6749.ErrInvalidRequest,
			State: req.State,
		})
		return
	}

	// 4. Validate other request parameters (scope)
	if req.Scope != "" && !rfc6749.IsValidScope(req.Scope) {
		h.errHandler.WriteAuthorizationError(w, r, req.RedirectURI, rfc6749.ErrorResponse{
			Error: rfc6749.ErrInvalidScope,
			State: req.State,
		})
		return
	}

	ctx := client.WithContext(r.Context(), c)

	// 5. Authenticate Resource Owner & Obtain Consent
	if h.userDecider != nil {
		id, err := h.userDecider.AuthenticateUser(ctx, r)
		if err != nil {
			if errors.Is(err, ErrNeedsHumanInteraction) {
				if h.interactionHandler != nil {
					h.interactionHandler.HandleInteraction(w, r, req)
				} else {
					h.errHandler.WriteAuthorizationError(w, r, req.RedirectURI, rfc6749.ErrorResponse{
						Error: rfc6749.ErrAccessDenied,
						State: req.State,
					})
				}
				return
			}
			h.errHandler.WriteAuthorizationError(w, r, req.RedirectURI, rfc6749.ErrorResponse{
				Error: rfc6749.ErrAccessDenied,
				State: req.State,
			})
			return
		}
		if id != nil {
			ctx = identity.WithContext(ctx, id)
		}
	}

	// 6. Lookup Response Type Handler (RFC 6749 Section 4.1.1)
	handler, ok := h.handlers[req.ResponseType]
	if !ok {
		h.errHandler.WriteAuthorizationError(w, r, req.RedirectURI, rfc6749.ErrorResponse{
			Error: rfc6749.ErrUnsupportedResponseType,
			State: req.State,
		})
		return
	}

	// 7. Execute Response Type Handler
	authResp, err := handler.HandleAuthorize(ctx, req)
	if err != nil || authResp == nil {
		var protoErr rfc6749.ProtocolError
		var oauthErr token.OAuthError
		if errors.As(err, &protoErr) {
			h.errHandler.WriteAuthorizationError(w, r, req.RedirectURI, protoErr.Response)
		} else if errors.As(err, &oauthErr) {
			h.errHandler.WriteAuthorizationError(w, r, req.RedirectURI, oauthErr.Response)
		} else {
			h.errHandler.WriteAuthorizationError(w, r, req.RedirectURI, rfc6749.ErrorResponse{
				Error: rfc6749.ErrAccessDenied,
				State: req.State,
			})
		}
		return
	}

	// 8. Redirect back to client with response parameters (RFC 6749 Section 4.1.2 & 4.2.2)
	redirectURL, err := url.Parse(req.RedirectURI)
	if err != nil {
		h.errHandler.WriteAuthorizationError(w, r, req.RedirectURI, rfc6749.ErrorResponse{
			Error: rfc6749.ErrServerError,
			State: req.State,
		})
		return
	}

	params := url.Values{}
	if authResp.Code != "" {
		params.Set("code", authResp.Code)
	}
	state := authResp.State
	if state == "" {
		state = req.State
	}
	if state != "" {
		params.Set("state", state)
	}
	if authResp.Params != nil {
		for k, v := range authResp.Params {
			params.Set(k, v)
		}
	}

	if authResp.UseFragment {
		redirectURL.Fragment = params.Encode()
	} else {
		redirectURL.RawQuery = params.Encode()
	}

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

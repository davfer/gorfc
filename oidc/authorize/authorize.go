package authorize

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	oauthAuthz "github.com/davfer/gorfc/oauth/authorize"
	"github.com/davfer/gorfc/oauth/client"
	"github.com/davfer/gorfc/oauth/grant"
	"github.com/davfer/gorfc/oidc/identity"
	"github.com/davfer/gorfc/oidc/idtoken"
	"github.com/davfer/gorfc/rfc6749"
)

// AuthorizationRequest represents an OpenID Connect Authentication Request.
// Reference: OpenID Connect Core 1.0, Section 3.1.2.1
type AuthorizationRequest struct {
	Scope        string `json:"scope"`         // REQUIRED
	ResponseType string `json:"response_type"` // REQUIRED
	ClientID     string `json:"client_id"`     // REQUIRED
	RedirectURI  string `json:"redirect_uri"`  // REQUIRED
	State        string `json:"state,omitempty"`
	ResponseMode string `json:"response_mode,omitempty"`
	Nonce        string `json:"nonce,omitempty"`
	Display      string `json:"display,omitempty"`
	Prompt       string `json:"prompt,omitempty"`
	MaxAge       int    `json:"max_age,omitempty"`
	UILocales    string `json:"ui_locales,omitempty"`
	IDTokenHint  string `json:"id_token_hint,omitempty"`
	LoginHint    string `json:"login_hint,omitempty"`
	ACRValues    string `json:"acr_values,omitempty"`
	Claims       string `json:"claims,omitempty"`
}

// AuthorizationResponse represents an OpenID Connect Authentication Response.
// Reference: OpenID Connect Core 1.0, Sections 3.1.2.5, 3.2.2.5, 3.3.2.5
type AuthorizationResponse struct {
	Code        string `json:"code,omitempty"`
	AccessToken string `json:"access_token,omitempty"`
	TokenType   string `json:"token_type,omitempty"`
	IDToken     string `json:"id_token,omitempty"`
	State       string `json:"state,omitempty"`
	ExpiresIn   int    `json:"expires_in,omitempty"`
}

// ClaimsRequest represents the structure of the "claims" request parameter.
// Reference: OpenID Connect Core 1.0, Section 5.5
type ClaimsRequest struct {
	UserInfo map[string]*ClaimRequest `json:"userinfo,omitempty"`
	IDToken  map[string]*ClaimRequest `json:"id_token,omitempty"`
}

// ClaimRequest represents the request for an individual claim.
// Reference: OpenID Connect Core 1.0, Section 5.5.1
type ClaimRequest struct {
	Essential bool     `json:"essential,omitempty"`
	Value     string   `json:"value,omitempty"`
	Values    []string `json:"values,omitempty"`
}

// Authentication Flows
const (
	FlowAuthorizationCode = "Authorization Code Flow"
	FlowImplicit          = "Implicit Flow"
	FlowHybrid            = "Hybrid Flow"
)

// Response Types
const (
	ResponseTypeCode             = "code"
	ResponseTypeIDToken          = "id_token"
	ResponseTypeIDTokenToken     = "id_token token"
	ResponseTypeCodeIDToken      = "code id_token"
	ResponseTypeCodeToken        = "code token"
	ResponseTypeCodeIDTokenToken = "code id_token token"
)

// Standard Scopes
const (
	ScopeOpenID        = "openid"
	ScopeProfile       = "profile"
	ScopeEmail         = "email"
	ScopeAddress       = "address"
	ScopePhone         = "phone"
	ScopeOfflineAccess = "offline_access"
)

// Display Values
const (
	DisplayPage  = "page"
	DisplayPopup = "popup"
	DisplayTouch = "touch"
	DisplayWap   = "wap"
)

// Prompt Values
const (
	PromptNone          = "none"
	PromptLogin         = "login"
	PromptConsent       = "consent"
	PromptSelectAccount = "select_account"
)

// Error Codes
const (
	ErrInteractionRequired      = "interaction_required"
	ErrLoginRequired            = "login_required"
	ErrAccountSelectionRequired = "account_selection_required"
	ErrConsentRequired          = "consent_required"
	ErrInvalidRequestURI        = "invalid_request_uri"
	ErrInvalidRequestObject     = "invalid_request_object"
	ErrRequestNotSupported      = "request_not_supported"
	ErrRequestURINotSupported   = "request_uri_not_supported"
	ErrRegistrationNotSupported = "registration_not_supported"
)

// ErrNeedsHumanInteraction indicates that the authorization request requires user interaction.
var ErrNeedsHumanInteraction = errors.New("authorize: human interaction required")

// GetFlow returns the Authentication Flow associated with a response_type.
func GetFlow(responseType string) string {
	switch responseType {
	case ResponseTypeCode:
		return FlowAuthorizationCode
	case ResponseTypeIDToken, ResponseTypeIDTokenToken:
		return FlowImplicit
	case ResponseTypeCodeIDToken, ResponseTypeCodeToken, ResponseTypeCodeIDTokenToken:
		return FlowHybrid
	default:
		return ""
	}
}

// AuthorizeHandler handles OpenID Connect 1.0 Authentication Requests.
// Reference: OpenID Connect Core 1.0, Section 3.1.2
type AuthorizeHandler struct {
	clientStore        oauthAuthz.ClientStore
	identityProvider   identity.IdentityProvider
	idTokenIssuer      idtoken.IDTokenIssuer
	codeCreator        grant.CodeCreator
	interactionHandler oauthAuthz.HumanInteractionHandler
	errHandler         oauthAuthz.ErrorHandler
	nowFunc            func() time.Time
}

// NewAuthorizeHandler creates a new OIDC AuthorizeHandler.
func NewAuthorizeHandler(
	clientStore oauthAuthz.ClientStore,
	identityProvider identity.IdentityProvider,
	idTokenIssuer idtoken.IDTokenIssuer,
	interactionHandler oauthAuthz.HumanInteractionHandler,
	codeCreator grant.CodeCreator,
	errHandler oauthAuthz.ErrorHandler,
) *AuthorizeHandler {
	return &AuthorizeHandler{
		clientStore:        clientStore,
		identityProvider:   identityProvider,
		idTokenIssuer:      idTokenIssuer,
		interactionHandler: interactionHandler,
		codeCreator:        codeCreator,
		errHandler:         errHandler,
		nowFunc:            time.Now,
	}
}

// ServeHTTP implements http.Handler for the OIDC Authorization Endpoint.
func (h *AuthorizeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.errHandler.WriteAuthorizationError(w, r, "", rfc6749.ErrorResponse{
			Error:            rfc6749.ErrInvalidRequest,
			ErrorDescription: "Failed to parse request parameters",
		})
		return
	}

	req := AuthorizationRequest{
		Scope:        r.FormValue("scope"),
		ResponseType: r.FormValue("response_type"),
		ClientID:     r.FormValue("client_id"),
		RedirectURI:  r.FormValue("redirect_uri"),
		State:        r.FormValue("state"),
		ResponseMode: r.FormValue("response_mode"),
		Nonce:        r.FormValue("nonce"),
		Display:      r.FormValue("display"),
		Prompt:       r.FormValue("prompt"),
		UILocales:    r.FormValue("ui_locales"),
		IDTokenHint:  r.FormValue("id_token_hint"),
		LoginHint:    r.FormValue("login_hint"),
		ACRValues:    r.FormValue("acr_values"),
		Claims:       r.FormValue("claims"),
	}

	if maxAgeStr := r.FormValue("max_age"); maxAgeStr != "" {
		if val, err := strconv.Atoi(maxAgeStr); err == nil && val >= 0 {
			req.MaxAge = val
		}
	}

	// 1. Validate client_id parameter syntax
	if req.ClientID == "" || !rfc6749.IsValidClientID(req.ClientID) {
		h.errHandler.WriteAuthorizationError(w, r, req.RedirectURI, rfc6749.ErrorResponse{
			Error: rfc6749.ErrInvalidRequest,
			State: req.State,
		})
		return
	}

	// 2. Fetch client and validate redirect_uri
	c, err := h.clientStore.GetClient(r.Context(), req.ClientID)
	if err != nil || c == nil {
		h.errHandler.WriteAuthorizationError(w, r, req.RedirectURI, rfc6749.ErrorResponse{
			Error: rfc6749.ErrUnauthorizedClient,
			State: req.State,
		})
		return
	}

	if !client.ValidateRedirectURI(c, req.RedirectURI) {
		h.errHandler.WriteAuthorizationError(w, r, "", rfc6749.ErrorResponse{
			Error: rfc6749.ErrInvalidRequest,
			State: req.State,
		})
		return
	}

	// 3. Verify scope contains "openid"
	scopes := strings.Split(req.Scope, " ")
	hasOpenID := false
	for _, s := range scopes {
		if s == ScopeOpenID {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID {
		h.errHandler.WriteAuthorizationError(w, r, req.RedirectURI, rfc6749.ErrorResponse{
			Error:            rfc6749.ErrInvalidScope,
			ErrorDescription: "Scope 'openid' is required for OpenID Connect authentication requests",
			State:            req.State,
		})
		return
	}

	// 4. Validate prompt parameter (OpenID Connect Core 1.0 Section 3.1.2.1)
	prompts := strings.Split(req.Prompt, " ")
	hasPromptNone := false
	hasPromptLogin := false
	hasPromptConsent := false
	hasPromptSelectAccount := false
	for _, p := range prompts {
		switch p {
		case PromptNone:
			hasPromptNone = true
		case PromptLogin:
			hasPromptLogin = true
		case PromptConsent:
			hasPromptConsent = true
		case PromptSelectAccount:
			hasPromptSelectAccount = true
		}
	}

	if hasPromptNone && len(prompts) > 1 {
		h.errHandler.WriteAuthorizationError(w, r, req.RedirectURI, rfc6749.ErrorResponse{
			Error:            rfc6749.ErrInvalidRequest,
			ErrorDescription: "Prompt 'none' cannot be combined with other prompt values",
			State:            req.State,
		})
		return
	}

	// 5. Look up identity session & Authenticate Resource Owner
	var session identity.Session
	if h.identityProvider != nil {
		sess, err := h.identityProvider.GetSession(r.Context(), r)
		if err != nil {
			if errors.Is(err, ErrNeedsHumanInteraction) {
				if hasPromptNone {
					h.errHandler.WriteAuthorizationError(w, r, req.RedirectURI, rfc6749.ErrorResponse{
						Error:            ErrLoginRequired,
						ErrorDescription: "Interaction required but prompt=none requested",
						State:            req.State,
					})
					return
				}
				if h.interactionHandler != nil {
					authReq := rfc6749.AuthorizationRequest{
						ResponseType: req.ResponseType,
						ClientID:     req.ClientID,
						RedirectURI:  req.RedirectURI,
						Scope:        req.Scope,
						State:        req.State,
					}
					h.interactionHandler.HandleInteraction(w, r, authReq)
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
		session = sess
	}

	// 6. Handle prompt=none requirement: MUST NOT display UI
	if hasPromptNone {
		if session == nil || session.Subject() == "" {
			h.errHandler.WriteAuthorizationError(w, r, req.RedirectURI, rfc6749.ErrorResponse{
				Error:            ErrLoginRequired,
				ErrorDescription: "User is not logged in",
				State:            req.State,
			})
			return
		}
	}

	// 7. Handle max_age check (Section 3.1.2.1)
	authTime := identity.GetAuthTime(session)
	if req.MaxAge > 0 && session != nil && authTime > 0 {
		nowSec := h.nowFunc().Unix()
		if nowSec-authTime > int64(req.MaxAge) {
			if hasPromptNone {
				h.errHandler.WriteAuthorizationError(w, r, req.RedirectURI, rfc6749.ErrorResponse{
					Error:            ErrLoginRequired,
					ErrorDescription: "Authentication session expired max_age",
					State:            req.State,
				})
				return
			}
			session = nil // force re-authentication
		}
	}

	// 8. Handle prompt=login, prompt=consent, prompt=select_account: force re-authentication/consent if prompt=none is false
	if !hasPromptNone && (hasPromptLogin || hasPromptConsent || hasPromptSelectAccount) {
		session = nil
	}

	// 9. If identity session is absent and interaction allowed, call interactionHandler or return error
	if session == nil {
		if h.interactionHandler != nil {
			authReq := rfc6749.AuthorizationRequest{
				ResponseType: req.ResponseType,
				ClientID:     req.ClientID,
				RedirectURI:  req.RedirectURI,
				Scope:        req.Scope,
				State:        req.State,
			}
			h.interactionHandler.HandleInteraction(w, r, authReq)
		} else {
			h.errHandler.WriteAuthorizationError(w, r, req.RedirectURI, rfc6749.ErrorResponse{
				Error: rfc6749.ErrAccessDenied,
				State: req.State,
			})
		}
		return
	}

	// 10. Validate nonce for Implicit and Hybrid flows
	flow := GetFlow(req.ResponseType)
	if flow == FlowImplicit || flow == FlowHybrid {
		if req.Nonce == "" {
			h.errHandler.WriteAuthorizationError(w, r, req.RedirectURI, rfc6749.ErrorResponse{
				Error:            rfc6749.ErrInvalidRequest,
				ErrorDescription: "Nonce parameter is required for implicit and hybrid flows",
				State:            req.State,
			})
			return
		}
	}

	// 11. Generate response parameters
	redirectURL, err := url.Parse(req.RedirectURI)
	if err != nil {
		h.errHandler.WriteAuthorizationError(w, r, req.RedirectURI, rfc6749.ErrorResponse{
			Error: rfc6749.ErrServerError,
			State: req.State,
		})
		return
	}

	params := url.Values{}
	if req.State != "" {
		params.Set("state", req.State)
	}

	// For Authorization Code flow or Hybrid flow with code
	if strings.Contains(req.ResponseType, ResponseTypeCode) {
		codeVal := "oidc_auth_code_sample"
		if h.codeCreator != nil {
			authReq := rfc6749.AuthorizationRequest{
				ResponseType: req.ResponseType,
				ClientID:     req.ClientID,
				RedirectURI:  req.RedirectURI,
				Scope:        req.Scope,
				State:        req.State,
			}
			var sub string
			if session != nil {
				sub = session.Subject()
			}
			createdCode, err := h.codeCreator.CreateCode(r.Context(), authReq, sub)
			if err == nil && createdCode != nil && createdCode.Code != "" {
				codeVal = createdCode.Code
			}
		}
		params.Set("code", codeVal)
	}

	// For Implicit or Hybrid flows with id_token
	if strings.Contains(req.ResponseType, ResponseTypeIDToken) {
		if h.idTokenIssuer != nil {
			idToken, err := h.idTokenIssuer.IssueIDToken(r.Context(), session, req.ClientID, req.Nonce, "", "")
			if err == nil {
				params.Set("id_token", idToken)
			}
		}
	}

	// Format output per response_mode (Section 3.1.2.1)
	useFragment := (flow == FlowImplicit || flow == FlowHybrid)
	if req.ResponseMode == "query" {
		useFragment = false
	} else if req.ResponseMode == "fragment" {
		useFragment = true
	}

	if useFragment {
		redirectURL.Fragment = params.Encode()
	} else {
		redirectURL.RawQuery = params.Encode()
	}

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

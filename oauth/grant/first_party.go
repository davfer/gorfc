package grant

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/davfer/gorfc/oauth/client"
	"github.com/davfer/gorfc/oauth/identity"
	"github.com/davfer/gorfc/oauth/token"
	"github.com/davfer/gorfc/rfc6749"
	"github.com/davfer/gorfc/rfc7636"
)

// Specification Constants for OAuth 2.0 for First-Party Applications.
// Reference: draft-ietf-oauth-first-party-apps-04
const (
	// GrantTypeFirstParty is an identifier for first-party application flows.
	// Reference: draft-ietf-oauth-first-party-apps-04
	GrantTypeFirstParty = "first_party"

	// ErrInsufficientAuthorization indicates that the presented authorization is insufficient,
	// and the authorization server is requesting the client to take additional steps to complete the authorization.
	// The authorization server MUST respond with HTTP 403 (Forbidden).
	// Reference: draft-ietf-oauth-first-party-apps-04, Section 5.2.2.1
	ErrInsufficientAuthorization = "insufficient_authorization"

	// ErrRedirectToWeb indicates that the request cannot be fulfilled with direct interaction and
	// the client should initiate a new authorization code flow so that the user interacts with the AS in a web browser.
	// The authorization server MUST respond with HTTP 403 (Forbidden).
	// Reference: draft-ietf-oauth-first-party-apps-04, Section 5.2.2.1 & Section 5.2.2.1.1
	ErrRedirectToWeb = "redirect_to_web"

	// ErrInvalidSession indicates that the provided auth_session is invalid, expired, revoked, or otherwise not acceptable.
	// Reference: draft-ietf-oauth-first-party-apps-04, Section 5.2.2.1
	ErrInvalidSession = "invalid_session"

	// ParamAuthSession is the parameter name for the auth session identifier.
	// Reference: draft-ietf-oauth-first-party-apps-04, Section 5.1, Section 5.3.1, Section 6.1 & Section 10.1
	ParamAuthSession = "auth_session"

	// ParamAuthorizationCode is the parameter name for the issued authorization code in the challenge response.
	// Reference: draft-ietf-oauth-first-party-apps-04, Section 5.2.1
	ParamAuthorizationCode = "authorization_code"

	// ParamAuthorizationChallengeEndpoint is the metadata parameter name for the authorization challenge endpoint URL.
	// Reference: draft-ietf-oauth-first-party-apps-04, Section 8 & Section 10.2
	ParamAuthorizationChallengeEndpoint = "authorization_challenge_endpoint"
)

// AuthorizationChallengeRequest represents the parameters for an Authorization Challenge Request.
// Reference: draft-ietf-oauth-first-party-apps-04, Section 5.1
type AuthorizationChallengeRequest struct {
	ClientID            string            `json:"client_id,omitempty"`
	ResponseType        string            `json:"response_type"`
	Scope               string            `json:"scope,omitempty"`
	AuthSession         string            `json:"auth_session,omitempty"`
	CodeChallenge       string            `json:"code_challenge,omitempty"`
	CodeChallengeMethod string            `json:"code_challenge_method,omitempty"`
	State               string            `json:"state,omitempty"`
	Extra               map[string]string `json:"extra,omitempty"`
}

// Get returns the value of a parameter from standard fields or Extra parameters.
func (r AuthorizationChallengeRequest) Get(key string) string {
	switch key {
	case "client_id":
		return r.ClientID
	case "response_type":
		return r.ResponseType
	case "scope":
		return r.Scope
	case "auth_session":
		return r.AuthSession
	case "code_challenge":
		return r.CodeChallenge
	case "code_challenge_method":
		return r.CodeChallengeMethod
	case "state":
		return r.State
	default:
		if r.Extra != nil {
			return r.Extra[key]
		}
		return ""
	}
}

// Unmarshal converts the AuthorizationChallengeRequest parameters into a target struct or map pointer.
func (r AuthorizationChallengeRequest) Unmarshal(v interface{}) error {
	m := make(map[string]string)
	if r.Extra != nil {
		for k, val := range r.Extra {
			m[k] = val
		}
	}
	if r.ClientID != "" {
		m["client_id"] = r.ClientID
	}
	if r.ResponseType != "" {
		m["response_type"] = r.ResponseType
	}
	if r.Scope != "" {
		m["scope"] = r.Scope
	}
	if r.AuthSession != "" {
		m["auth_session"] = r.AuthSession
	}
	if r.CodeChallenge != "" {
		m["code_challenge"] = r.CodeChallenge
	}
	if r.CodeChallengeMethod != "" {
		m["code_challenge_method"] = r.CodeChallengeMethod
	}
	if r.State != "" {
		m["state"] = r.State
	}

	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// ToAuthorizationRequest converts the challenge request to a standard RFC 6749 AuthorizationRequest.
func (r AuthorizationChallengeRequest) ToAuthorizationRequest() rfc6749.AuthorizationRequest {
	return rfc6749.AuthorizationRequest{
		ResponseType: r.ResponseType,
		ClientID:     r.ClientID,
		Scope:        r.Scope,
		State:        r.State,
	}
}

// ParseAuthorizationChallengeRequest parses an HTTP POST request with application/x-www-form-urlencoded
// body into an AuthorizationChallengeRequest.
// Reference: draft-ietf-oauth-first-party-apps-04, Section 4.1.2 & Section 5.1
func ParseAuthorizationChallengeRequest(r *http.Request) (AuthorizationChallengeRequest, error) {
	if r.Method != http.MethodPost {
		return AuthorizationChallengeRequest{}, rfc6749.ProtocolError{
			Response: rfc6749.ErrorResponse{
				Error:            rfc6749.ErrInvalidRequest,
				ErrorDescription: "Authorization challenge requests must use HTTP POST",
			},
		}
	}

	contentType := r.Header.Get(rfc6749.HeaderContentType)
	if !strings.HasPrefix(contentType, rfc6749.ContentTypeFormUrlEncoded) {
		return AuthorizationChallengeRequest{}, rfc6749.ProtocolError{
			Response: rfc6749.ErrorResponse{
				Error:            rfc6749.ErrInvalidRequest,
				ErrorDescription: "Content-Type must be " + rfc6749.ContentTypeFormUrlEncoded,
			},
		}
	}

	if err := r.ParseForm(); err != nil {
		return AuthorizationChallengeRequest{}, rfc6749.ProtocolError{
			Response: rfc6749.ErrorResponse{
				Error:            rfc6749.ErrInvalidRequest,
				ErrorDescription: "Failed to parse form body",
			},
		}
	}

	extra := make(map[string]string)
	for key, values := range r.Form {
		if len(values) > 0 {
			extra[key] = values[0]
		}
	}

	return AuthorizationChallengeRequest{
		ClientID:            r.FormValue("client_id"),
		ResponseType:        r.FormValue("response_type"),
		Scope:               r.FormValue("scope"),
		AuthSession:         r.FormValue("auth_session"),
		CodeChallenge:       r.FormValue("code_challenge"),
		CodeChallengeMethod: r.FormValue("code_challenge_method"),
		State:               r.FormValue("state"),
		Extra:               extra,
	}, nil
}

// AuthorizationChallengeResponse represents a successful response from the Authorization Challenge Endpoint.
// Reference: draft-ietf-oauth-first-party-apps-04, Section 5.2.1
type AuthorizationChallengeResponse struct {
	AuthorizationCode string         `json:"authorization_code"`
	AuthSession       string         `json:"auth_session,omitempty"`
	Parameters        map[string]any `json:"-"`
}

// MarshalJSON serializes the response and flattens additional parameters at the highest JSON structure level.
// Reference: draft-ietf-oauth-first-party-apps-04, Section 5.2.1 & Section 5.2.2-5
func (r AuthorizationChallengeResponse) MarshalJSON() ([]byte, error) {
	m := make(map[string]any)
	if r.Parameters != nil {
		for k, v := range r.Parameters {
			m[k] = v
		}
	}
	m["authorization_code"] = r.AuthorizationCode
	if r.AuthSession != "" {
		m["auth_session"] = r.AuthSession
	}
	return json.Marshal(m)
}

// UnmarshalJSON unmarshals the response, capturing custom parameters into Parameters.
func (r *AuthorizationChallengeResponse) UnmarshalJSON(data []byte) error {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if code, ok := raw["authorization_code"].(string); ok {
		r.AuthorizationCode = code
		delete(raw, "authorization_code")
	}
	if session, ok := raw["auth_session"].(string); ok {
		r.AuthSession = session
		delete(raw, "auth_session")
	}
	if len(raw) > 0 {
		r.Parameters = raw
	}
	return nil
}

// AuthorizationChallengeError represents an error response from the Authorization Challenge Endpoint.
// Reference: draft-ietf-oauth-first-party-apps-04, Section 5.2.2 & Section 5.2.2.1
type AuthorizationChallengeError struct {
	ErrorCode        string         `json:"error"`
	ErrorDescription string         `json:"error_description,omitempty"`
	ErrorURI         string         `json:"error_uri,omitempty"`
	AuthSession      string         `json:"auth_session,omitempty"`
	RequestURI       string         `json:"request_uri,omitempty"`
	ExpiresIn        int64          `json:"expires_in,omitempty"`
	Parameters       map[string]any `json:"-"`
}

// Error implements Go's error interface.
func (e AuthorizationChallengeError) Error() string {
	if e.ErrorDescription != "" {
		return e.ErrorCode + ": " + e.ErrorDescription
	}
	return e.ErrorCode
}

// StatusCode returns the corresponding HTTP status code for this error.
// Reference: draft-ietf-oauth-first-party-apps-04, Section 5.2.2.1
func (e AuthorizationChallengeError) StatusCode() int {
	if e.ErrorCode == ErrInsufficientAuthorization || e.ErrorCode == ErrRedirectToWeb {
		return http.StatusForbidden
	}
	return http.StatusBadRequest
}

// MarshalJSON serializes the error and flattens additional parameters at the highest JSON structure level.
// Reference: draft-ietf-oauth-first-party-apps-04, Section 5.2.2-5
func (e AuthorizationChallengeError) MarshalJSON() ([]byte, error) {
	m := make(map[string]any)
	if e.Parameters != nil {
		for k, v := range e.Parameters {
			m[k] = v
		}
	}
	m["error"] = e.ErrorCode
	if e.ErrorDescription != "" {
		m["error_description"] = e.ErrorDescription
	}
	if e.ErrorURI != "" {
		m["error_uri"] = e.ErrorURI
	}
	if e.AuthSession != "" {
		m["auth_session"] = e.AuthSession
	}
	if e.RequestURI != "" {
		m["request_uri"] = e.RequestURI
	}
	if e.ExpiresIn > 0 {
		m["expires_in"] = e.ExpiresIn
	}
	return json.Marshal(m)
}

// UnmarshalJSON unmarshals the error, capturing custom parameters into Parameters.
func (e *AuthorizationChallengeError) UnmarshalJSON(data []byte) error {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if errVal, ok := raw["error"].(string); ok {
		e.ErrorCode = errVal
		delete(raw, "error")
	}
	if desc, ok := raw["error_description"].(string); ok {
		e.ErrorDescription = desc
		delete(raw, "error_description")
	}
	if uri, ok := raw["error_uri"].(string); ok {
		e.ErrorURI = uri
		delete(raw, "error_uri")
	}
	if session, ok := raw["auth_session"].(string); ok {
		e.AuthSession = session
		delete(raw, "auth_session")
	}
	if reqURI, ok := raw["request_uri"].(string); ok {
		e.RequestURI = reqURI
		delete(raw, "request_uri")
	}
	if exp, ok := raw["expires_in"].(float64); ok {
		e.ExpiresIn = int64(exp)
		delete(raw, "expires_in")
	}
	if len(raw) > 0 {
		e.Parameters = raw
	}
	return nil
}

// Challenger abstracts challenging the client until authentication is complete.
// Implementations evaluate the client's credentials, passkey assertions, OTPs, or auth_session.
// If further client interaction or authentication factors are needed, Challenge returns an error
// (such as AuthorizationChallengeError with ErrInsufficientAuthorization or ErrRedirectToWeb).
// The authorization flow MUST NOT proceed to issue an authorization code until Challenge returns err == nil.
// Reference: draft-ietf-oauth-first-party-apps-04, Section 5.1, 5.2 & 5.3
type Challenger interface {
	Challenge(ctx context.Context, req AuthorizationChallengeRequest) (identity.Identity, error)
}

// ChallengerFunc allows ordinary functions to satisfy the Challenger interface.
type ChallengerFunc func(ctx context.Context, req AuthorizationChallengeRequest) (identity.Identity, error)

// Challenge calls the underlying function.
func (f ChallengerFunc) Challenge(ctx context.Context, req AuthorizationChallengeRequest) (identity.Identity, error) {
	return f(ctx, req)
}

// SimpleChallengerFunc creates a Challenger from a function returning only error.
// If err == nil, the identity is resolved from context via identity.FromContext.
func SimpleChallengerFunc(fn func(ctx context.Context, req AuthorizationChallengeRequest) error) Challenger {
	return ChallengerFunc(func(ctx context.Context, req AuthorizationChallengeRequest) (identity.Identity, error) {
		if err := fn(ctx, req); err != nil {
			return nil, err
		}
		id, _ := identity.FromContext(ctx)
		return id, nil
	})
}

// ChallengeCodeCreator abstracts creating an authorization code from an AuthorizationChallengeRequest.
// Reference: draft-ietf-oauth-first-party-apps-04, Section 5.2.1
type ChallengeCodeCreator interface {
	CreateChallengeCode(ctx context.Context, req AuthorizationChallengeRequest, subject string) (*AuthorizationCode, error)
}

// FirstPartyAppGrant handles OAuth 2.0 for First-Party Applications.
// It manages the Authorization Challenge Endpoint flow (Section 5) and the Token Endpoint flow (Section 6).
// Reference: draft-ietf-oauth-first-party-apps-04
type FirstPartyAppGrant struct {
	challenger           Challenger
	codeCreator          CodeCreator
	challengeCodeCreator ChallengeCodeCreator
	codeExchanger        CodeExchanger
	tokenIssuer          TokenIssuer
}

// FirstPartyApplicationGrant is an alias for FirstPartyAppGrant.
type FirstPartyApplicationGrant = FirstPartyAppGrant

// NewFirstPartyAppGrant creates a new FirstPartyAppGrant instance for handling authorization challenges.
func NewFirstPartyAppGrant(challenger Challenger, codeCreator CodeCreator) *FirstPartyAppGrant {
	return &FirstPartyAppGrant{
		challenger:  challenger,
		codeCreator: codeCreator,
	}
}

// NewFirstPartyAppGrantWithChallengeCreator creates a new FirstPartyAppGrant with a dedicated ChallengeCodeCreator.
func NewFirstPartyAppGrantWithChallengeCreator(challenger Challenger, codeCreator ChallengeCodeCreator) *FirstPartyAppGrant {
	return &FirstPartyAppGrant{
		challenger:           challenger,
		challengeCodeCreator: codeCreator,
	}
}

// NewFirstPartyAppGrantFull creates a FirstPartyAppGrant instance supporting both challenge and token endpoints.
func NewFirstPartyAppGrantFull(
	challenger Challenger,
	codeCreator CodeCreator,
	codeExchanger CodeExchanger,
	tokenIssuer TokenIssuer,
) *FirstPartyAppGrant {
	return &FirstPartyAppGrant{
		challenger:    challenger,
		codeCreator:   codeCreator,
		codeExchanger: codeExchanger,
		tokenIssuer:   tokenIssuer,
	}
}

// SetChallengeCodeCreator sets a dedicated ChallengeCodeCreator.
func (g *FirstPartyAppGrant) SetChallengeCodeCreator(creator ChallengeCodeCreator) {
	g.challengeCodeCreator = creator
}

// HandleChallenge processes an authorization challenge request.
// It enforces spec rules from Section 5.1, delegates to Challenger, and does not proceed to issue an
// authorization code until Challenger returns err == nil.
// Reference: draft-ietf-oauth-first-party-apps-04, Section 5.1 & Section 5.2
func (g *FirstPartyAppGrant) HandleChallenge(ctx context.Context, req AuthorizationChallengeRequest) (*AuthorizationChallengeResponse, error) {
	if g.challenger == nil {
		return nil, rfc6749.ProtocolError{Response: rfc6749.ErrorResponse{
			Error: rfc6749.ErrServerError,
			State: req.State,
		}}
	}

	// 1. Verify response_type is REQUIRED and MUST contain "code" (Section 5.1)
	if req.ResponseType != rfc6749.ResponseTypeCode {
		return nil, rfc6749.ProtocolError{Response: rfc6749.ErrorResponse{
			Error:            rfc6749.ErrUnsupportedResponseType,
			ErrorDescription: "response_type must be code",
			State:            req.State,
		}}
	}

	// 2. Validate client_id parameter syntax & identity matching (Section 5.1)
	c, _ := client.FromContext(ctx)
	clientID := req.ClientID
	if c != nil {
		if clientID != "" && clientID != c.ClientID() {
			return nil, rfc6749.ProtocolError{Response: rfc6749.ErrorResponse{
				Error:            rfc6749.ErrInvalidClient,
				ErrorDescription: "client_id does not match authenticated client",
				State:            req.State,
			}}
		}
		if clientID == "" {
			clientID = c.ClientID()
		}
	} else if clientID == "" && req.AuthSession == "" {
		return nil, rfc6749.ProtocolError{Response: rfc6749.ErrorResponse{
			Error:            rfc6749.ErrInvalidRequest,
			ErrorDescription: "client_id is required",
			State:            req.State,
		}}
	}

	if clientID != "" && !rfc6749.IsValidClientID(clientID) {
		return nil, rfc6749.ProtocolError{Response: rfc6749.ErrorResponse{
			Error:            rfc6749.ErrInvalidRequest,
			ErrorDescription: "invalid client_id syntax",
			State:            req.State,
		}}
	}

	// 3. Validate Scope (RFC 6749 Section 3.3)
	if req.Scope != "" && !rfc6749.IsValidScope(req.Scope) {
		return nil, rfc6749.ProtocolError{Response: rfc6749.ErrorResponse{
			Error:            rfc6749.ErrInvalidScope,
			ErrorDescription: "invalid scope syntax",
			State:            req.State,
		}}
	}

	// 4. Validate PKCE code_challenge / method if provided (RFC 7636 Section 4.3 & draft Section 5.1)
	if req.CodeChallenge != "" {
		if !rfc7636.IsValidCodeChallenge(req.CodeChallenge) {
			return nil, rfc6749.ProtocolError{Response: rfc6749.ErrorResponse{
				Error:            rfc6749.ErrInvalidRequest,
				ErrorDescription: "invalid code_challenge syntax",
				State:            req.State,
			}}
		}
		method := req.CodeChallengeMethod
		if method == "" {
			method = rfc7636.CodeChallengeMethodPlain
		}
		if !rfc7636.IsValidCodeChallengeMethod(method) {
			return nil, rfc6749.ProtocolError{Response: rfc6749.ErrorResponse{
				Error:            rfc6749.ErrInvalidRequest,
				ErrorDescription: "unsupported code_challenge_method",
				State:            req.State,
			}}
		}
	}

	// 5. Execute Challenge - does NOT proceed until err == nil
	id, err := g.challenger.Challenge(ctx, req)
	if err != nil {
		return nil, err
	}

	// 6. Resolve Subject Identity
	var subject string
	if id != nil {
		subject = id.Subject()
	} else if ctxID, ok := identity.FromContext(ctx); ok && ctxID != nil {
		subject = ctxID.Subject()
	}
	if subject == "" {
		return nil, rfc6749.ProtocolError{Response: rfc6749.ErrorResponse{
			Error:            rfc6749.ErrAccessDenied,
			ErrorDescription: "user identity could not be established",
			State:            req.State,
		}}
	}

	// 7. Issue Authorization Code (Section 5.2.1)
	var authCode *AuthorizationCode
	if g.challengeCodeCreator != nil {
		authCode, err = g.challengeCodeCreator.CreateChallengeCode(ctx, req, subject)
	} else if g.codeCreator != nil {
		authReq := rfc6749.AuthorizationRequest{
			ResponseType: req.ResponseType,
			ClientID:     clientID,
			Scope:        req.Scope,
			State:        req.State,
		}
		authCode, err = g.codeCreator.CreateCode(ctx, authReq, subject)
		if authCode != nil && req.CodeChallenge != "" {
			if authCode.CodeChallenge == "" {
				authCode.CodeChallenge = req.CodeChallenge
				authCode.CodeChallengeMethod = req.CodeChallengeMethod
			}
		}
	} else {
		return nil, rfc6749.ProtocolError{Response: rfc6749.ErrorResponse{
			Error: rfc6749.ErrServerError,
			State: req.State,
		}}
	}

	if err != nil || authCode == nil {
		return nil, rfc6749.ProtocolError{Response: rfc6749.ErrorResponse{
			Error: rfc6749.ErrServerError,
			State: req.State,
		}}
	}

	return &AuthorizationChallengeResponse{
		AuthorizationCode: authCode.Code,
		AuthSession:       req.AuthSession,
	}, nil
}

// HandleToken processes an authorization_code token request for first-party applications.
// Notably, the redirect_uri parameter is not required for first-party applications.
// Reference: draft-ietf-oauth-first-party-apps-04, Section 6
func (g *FirstPartyAppGrant) HandleToken(ctx context.Context, req rfc6749.TokenRequest) (*rfc6749.TokenResponse, error) {
	if g.codeExchanger == nil || g.tokenIssuer == nil {
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

	// Section 6: notably, redirect_uri will not be included in this request
	redirectURI := req.Get("redirect_uri")
	authCode, err := g.codeExchanger.ExchangeCode(ctx, code, clientID, redirectURI)
	if err != nil || authCode == nil {
		return nil, rfc6749.ProtocolError{Response: rfc6749.ErrorResponse{
			Error: rfc6749.ErrInvalidGrant,
		}}
	}

	if authCode.Subject != "" {
		ctx = identity.WithContext(ctx, identity.SimpleIdentity{Sub: authCode.Subject})
	}

	// PKCE Verification (RFC 7636 Section 4.6 & draft Section 6)
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

	return g.tokenIssuer.IssueToken(ctx, req, c)
}

// ServeHTTP implements http.Handler for the Authorization Challenge Endpoint.
// Reference: draft-ietf-oauth-first-party-apps-04, Section 4.1 & Section 5
func (g *FirstPartyAppGrant) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	req, err := ParseAuthorizationChallengeRequest(r)
	if err != nil {
		g.writeError(w, err)
		return
	}

	resp, err := g.HandleChallenge(r.Context(), req)
	if err != nil {
		g.writeError(w, err)
		return
	}

	w.Header().Set(rfc6749.HeaderContentType, rfc8259MediaTypeJSON())
	w.Header().Set(rfc6749.HeaderCacheControl, rfc6749.CacheControlNoStore)
	w.Header().Set(rfc6749.HeaderPragma, rfc6749.PragmaNoCache)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (g *FirstPartyAppGrant) writeError(w http.ResponseWriter, err error) {
	w.Header().Set(rfc6749.HeaderContentType, rfc8259MediaTypeJSON())
	w.Header().Set(rfc6749.HeaderCacheControl, rfc6749.CacheControlNoStore)
	w.Header().Set(rfc6749.HeaderPragma, rfc6749.PragmaNoCache)

	var challengeErr AuthorizationChallengeError
	if errors.As(err, &challengeErr) {
		w.WriteHeader(challengeErr.StatusCode())
		_ = json.NewEncoder(w).Encode(challengeErr)
		return
	}

	var protoErr rfc6749.ProtocolError
	if errors.As(err, &protoErr) {
		statusCode := http.StatusBadRequest
		if protoErr.Response.Error == rfc6749.ErrServerError {
			statusCode = http.StatusInternalServerError
		} else if protoErr.Response.Error == rfc6749.ErrAccessDenied {
			statusCode = http.StatusForbidden
		}
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(protoErr.Response)
		return
	}

	var oauthErr token.OAuthError
	if errors.As(err, &oauthErr) {
		statusCode := http.StatusBadRequest
		if oauthErr.Response.Error == rfc6749.ErrServerError {
			statusCode = http.StatusInternalServerError
		} else if oauthErr.Response.Error == rfc6749.ErrAccessDenied {
			statusCode = http.StatusForbidden
		}
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(oauthErr.Response)
		return
	}

	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(rfc6749.ErrorResponse{
		Error:            rfc6749.ErrInvalidRequest,
		ErrorDescription: err.Error(),
	})
}

func rfc8259MediaTypeJSON() string {
	return "application/json"
}

// GenerateAuthSession generates a cryptographically secure auth_session value
// with at least 256 bits (32 bytes) of entropy.
// Reference: draft-ietf-oauth-first-party-apps-04, Section 5.3.1 & Section 9.6
func GenerateAuthSession() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

package rfc6749

import (
	"encoding/json"
	"net/http"
	"strings"
)

// AuthorizationRequest represents the parameters for an OAuth 2.0 Authorization Request.
// Reference: RFC 6749, Sections 4.1.1 and 4.2.1
type AuthorizationRequest struct {
	ResponseType string `json:"response_type"` // REQUIRED
	ClientID     string `json:"client_id"`     // REQUIRED
	RedirectURI  string `json:"redirect_uri,omitempty"`
	Scope        string `json:"scope,omitempty"`
	State        string `json:"state,omitempty"`
}

// AuthorizationCodeResponse represents the successful response for an Authorization Code grant.
// Reference: RFC 6749, Section 4.1.2
type AuthorizationCodeResponse struct {
	Code  string `json:"code"`
	State string `json:"state,omitempty"`
}

// TokenRequest represents the parameters for an OAuth 2.0 Token Request.
// Reference: RFC 6749, Section 3.2
type TokenRequest struct {
	GrantType string            `json:"grant_type"` // REQUIRED
	Scope     string            `json:"scope,omitempty"`
	Extra     map[string]string `json:"extra,omitempty"`
}

// Get returns the value of a parameter from standard fields or Extra parameters.
func (tr TokenRequest) Get(key string) string {
	switch key {
	case "grant_type":
		return tr.GrantType
	case "scope":
		return tr.Scope
	default:
		if tr.Extra != nil {
			return tr.Extra[key]
		}
		return ""
	}
}

// Unmarshal converts the TokenRequest parameters into a target struct or map pointer.
func (tr TokenRequest) Unmarshal(v interface{}) error {
	m := make(map[string]string)
	if tr.Extra != nil {
		for k, val := range tr.Extra {
			m[k] = val
		}
	}
	if tr.GrantType != "" {
		m["grant_type"] = tr.GrantType
	}
	if tr.Scope != "" {
		m["scope"] = tr.Scope
	}

	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// ProtocolError represents an RFC 6749 protocol error wrapping an ErrorResponse.
type ProtocolError struct {
	Response ErrorResponse
}

func (e ProtocolError) Error() string {
	if e.Response.ErrorDescription != "" {
		return e.Response.Error + ": " + e.Response.ErrorDescription
	}
	return e.Response.Error
}

// ParseTokenRequest parses an HTTP request into a TokenRequest conforming to RFC 6749 Section 3.2.
func ParseTokenRequest(r *http.Request) (TokenRequest, error) {
	contentType := r.Header.Get(HeaderContentType)
	if !strings.HasPrefix(contentType, ContentTypeFormUrlEncoded) {
		return TokenRequest{}, ProtocolError{
			Response: ErrorResponse{
				Error:            ErrInvalidRequest,
				ErrorDescription: "Content-Type must be " + ContentTypeFormUrlEncoded,
			},
		}
	}

	if err := r.ParseForm(); err != nil {
		return TokenRequest{}, ProtocolError{
			Response: ErrorResponse{
				Error:            ErrInvalidRequest,
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

	return TokenRequest{
		GrantType: r.FormValue("grant_type"),
		Scope:     r.FormValue("scope"),
		Extra:     extra,
	}, nil
}

// AuthorizationCodeTokenRequest represents parameters for authorization_code grant type.
// Reference: RFC 6749 Section 4.1.3
type AuthorizationCodeTokenRequest struct {
	GrantType   string `json:"grant_type"`   // REQUIRED ("authorization_code")
	Code        string `json:"code"`         // REQUIRED
	RedirectURI string `json:"redirect_uri"` // REQUIRED if redirect_uri was in auth request
	ClientID    string `json:"client_id,omitempty"`
}

// RefreshTokenRequest represents parameters for refresh_token grant type.
// Reference: RFC 6749 Section 6
type RefreshTokenRequest struct {
	GrantType    string `json:"grant_type"`    // REQUIRED ("refresh_token")
	RefreshToken string `json:"refresh_token"` // REQUIRED
	Scope        string `json:"scope,omitempty"`
}

// PasswordTokenRequest represents parameters for password grant type.
// Reference: RFC 6749 Section 4.3.2
type PasswordTokenRequest struct {
	GrantType string `json:"grant_type"` // REQUIRED ("password")
	Username  string `json:"username"`   // REQUIRED
	Password  string `json:"password"`   // REQUIRED
	Scope     string `json:"scope,omitempty"`
}

// ClientCredentialsTokenRequest represents parameters for client_credentials grant type.
// Reference: RFC 6749 Section 4.4.2
type ClientCredentialsTokenRequest struct {
	GrantType string `json:"grant_type"` // REQUIRED ("client_credentials")
	Scope     string `json:"scope,omitempty"`
}

// TokenResponse represents a successful OAuth 2.0 Token Response.
// Reference: RFC 6749, Section 5.1 & draft-ietf-oauth-first-party-apps-04, Section 6.1
type TokenResponse struct {
	AccessToken  string `json:"access_token"` // REQUIRED
	TokenType    string `json:"token_type"`   // REQUIRED
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	AuthSession  string `json:"auth_session,omitempty"`
}

// ErrorResponse represents an OAuth 2.0 Error Response.
// Reference: RFC 6749, Sections 4.1.2.1 and 5.2
type ErrorResponse struct {
	Error            string `json:"error"` // REQUIRED
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
	State            string `json:"state,omitempty"`
}

// Response Types
const (
	ResponseTypeCode  = "code"
	ResponseTypeToken = "token"
)

// Grant Types
const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypePassword          = "password"
	GrantTypeClientCredentials = "client_credentials"
	GrantTypeRefreshToken      = "refresh_token"
)

// Token Types
const (
	TokenTypeBearer = "Bearer"
)

// Error Codes
const (
	// Authorization Request Errors (Section 4.1.2.1)
	ErrInvalidRequest          = "invalid_request"
	ErrUnauthorizedClient      = "unauthorized_client"
	ErrAccessDenied            = "access_denied"
	ErrUnsupportedResponseType = "unsupported_response_type"
	ErrInvalidScope            = "invalid_scope"
	ErrServerError             = "server_error"
	ErrTemporarilyUnavailable  = "temporarily_unavailable"

	// Token Request Errors (Section 5.2)
	ErrInvalidClient        = "invalid_client"
	ErrInvalidGrant         = "invalid_grant"
	ErrUnsupportedGrantType = "unsupported_grant_type"
)

// IsAuthorizationCodeRequest returns true if the request is an Authorization Code request.
func (r *AuthorizationRequest) IsAuthorizationCodeRequest() bool {
	return r.ResponseType == ResponseTypeCode
}

// IsImplicitRequest returns true if the request is an Implicit request.
func (r *AuthorizationRequest) IsImplicitRequest() bool {
	return r.ResponseType == ResponseTypeToken
}

// IsValidGrantType returns true if the grant type is supported by RFC 6749.
func IsValidGrantType(gt string) bool {
	switch gt {
	case GrantTypeAuthorizationCode, GrantTypePassword, GrantTypeClientCredentials, GrantTypeRefreshToken:
		return true
	default:
		return false
	}
}

// Validation Functions based on ABNF definitions (RFC 6749, Appendix A)

// IsValidScope checks if the scope string conforms to the ABNF:
// scope = scope-token *( SP scope-token )
// scope-token = 1*NQCHAR
func IsValidScope(scope string) bool {
	if scope == "" {
		return false
	}
	tokens := strings.Split(scope, " ")
	for _, token := range tokens {
		if !IsValidScopeToken(token) {
			return false
		}
	}
	return true
}

// IsValidScopeToken checks if the scope token conforms to 1*NQCHAR.
func IsValidScopeToken(token string) bool {
	if token == "" {
		return false
	}
	for i := 0; i < len(token); i++ {
		if !isNQCHAR(token[i]) {
			return false
		}
	}
	return true
}

// IsValidClientID checks if the client-id conforms to *VSCHAR.
func IsValidClientID(id string) bool {
	for i := 0; i < len(id); i++ {
		if !isVSCHAR(id[i]) {
			return false
		}
	}
	return true
}

// IsValidState checks if the state conforms to 1*VSCHAR.
func IsValidState(state string) bool {
	if state == "" {
		return false
	}
	for i := 0; i < len(state); i++ {
		if !isVSCHAR(state[i]) {
			return false
		}
	}
	return true
}

// IsValidCode checks if the code conforms to 1*VSCHAR.
func IsValidCode(code string) bool {
	if code == "" {
		return false
	}
	for i := 0; i < len(code); i++ {
		if !isVSCHAR(code[i]) {
			return false
		}
	}
	return true
}

// IsValidError checks if the error conforms to 1*NQSCHAR.
func IsValidError(err string) bool {
	if err == "" {
		return false
	}
	for i := 0; i < len(err); i++ {
		if !isNQSCHAR(err[i]) {
			return false
		}
	}
	return true
}

// ABNF character check helpers

// isVSCHAR checks if a character is %x20-7E (Visible characters + Space).
func isVSCHAR(c byte) bool {
	return c >= 0x20 && c <= 0x7E
}

// isNQCHAR checks if a character is %x21 / %x23-5B / %x5D-7E (No Quote or Backslash or Space).
func isNQCHAR(c byte) bool {
	return c == 0x21 || (c >= 0x23 && c <= 0x5B) || (c >= 0x5D && c <= 0x7E)
}

// isNQSCHAR checks if a character is %x20-21 / %x23-5B / %x5D-7E (No Quote or Backslash, Space allowed).
func isNQSCHAR(c byte) bool {
	return c == 0x20 || c == 0x21 || (c >= 0x23 && c <= 0x5B) || (c >= 0x5D && c <= 0x7E)
}

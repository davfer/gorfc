package oidc

import (
	"github.com/davfer/gorfc/oidc/authorize"
	"github.com/davfer/gorfc/oidc/identity"
	"github.com/davfer/gorfc/oidc/idtoken"
	"github.com/davfer/gorfc/oidc/token"
	"github.com/davfer/gorfc/oidc/userinfo"
)

// Type aliases for top-level model convenience
type (
	IDTokenClaims         = idtoken.IDTokenClaims
	StandardClaims        = identity.StandardClaims
	AddressClaim          = identity.AddressClaim
	AuthorizationRequest  = authorize.AuthorizationRequest
	AuthorizationResponse = authorize.AuthorizationResponse
	ClaimsRequest         = authorize.ClaimsRequest
	ClaimRequest          = authorize.ClaimRequest
	TokenRequest          = token.TokenRequest
	TokenResponse         = token.TokenResponse
	TokenService          = token.TokenService
	UserInfoRequest       = userinfo.UserInfoRequest
)

// Authentication Flows re-exported from authorize subpackage
const (
	FlowAuthorizationCode = authorize.FlowAuthorizationCode
	FlowImplicit          = authorize.FlowImplicit
	FlowHybrid            = authorize.FlowHybrid
)

// Response Types re-exported from authorize subpackage
const (
	ResponseTypeCode             = authorize.ResponseTypeCode
	ResponseTypeIDToken          = authorize.ResponseTypeIDToken
	ResponseTypeIDTokenToken     = authorize.ResponseTypeIDTokenToken
	ResponseTypeCodeIDToken      = authorize.ResponseTypeCodeIDToken
	ResponseTypeCodeToken        = authorize.ResponseTypeCodeToken
	ResponseTypeCodeIDTokenToken = authorize.ResponseTypeCodeIDTokenToken
)

// Standard Scopes re-exported from authorize subpackage
const (
	ScopeOpenID        = authorize.ScopeOpenID
	ScopeProfile       = authorize.ScopeProfile
	ScopeEmail         = authorize.ScopeEmail
	ScopeAddress       = authorize.ScopeAddress
	ScopePhone         = authorize.ScopePhone
	ScopeOfflineAccess = authorize.ScopeOfflineAccess
)

// Display Values re-exported from authorize subpackage
const (
	DisplayPage  = authorize.DisplayPage
	DisplayPopup = authorize.DisplayPopup
	DisplayTouch = authorize.DisplayTouch
	DisplayWap   = authorize.DisplayWap
)

// Prompt Values re-exported from authorize subpackage
const (
	PromptNone          = authorize.PromptNone
	PromptLogin         = authorize.PromptLogin
	PromptConsent       = authorize.PromptConsent
	PromptSelectAccount = authorize.PromptSelectAccount
)

// Error Codes re-exported from authorize subpackage
const (
	ErrInteractionRequired      = authorize.ErrInteractionRequired
	ErrLoginRequired            = authorize.ErrLoginRequired
	ErrAccountSelectionRequired = authorize.ErrAccountSelectionRequired
	ErrConsentRequired          = authorize.ErrConsentRequired
	ErrInvalidRequestURI        = authorize.ErrInvalidRequestURI
	ErrInvalidRequestObject     = authorize.ErrInvalidRequestObject
	ErrRequestNotSupported      = authorize.ErrRequestNotSupported
	ErrRequestURINotSupported   = authorize.ErrRequestURINotSupported
	ErrRegistrationNotSupported = authorize.ErrRegistrationNotSupported
)

// GetFlow returns the Authentication Flow associated with a response_type.
func GetFlow(responseType string) string {
	return authorize.GetFlow(responseType)
}

// OpenID Connect Discovery 1.0
// Reference: https://openid.net/specs/openid-connect-discovery-1_0.html

const (
	// DiscoveryPath is the well-known path for OpenID Provider configuration.
	DiscoveryPath = "/.well-known/openid-configuration"

	// WebFingerPath is the well-known path for WebFinger discovery.
	WebFingerPath = "/.well-known/webfinger"

	// IssuerRel is the relation type URI for OpenID Connect Issuer discovery.
	IssuerRel = "http://openid.net/specs/connect/1.0/issuer"
)

// ProviderMetadata represents the OpenID Provider Metadata.
// Reference: OpenID Connect Discovery 1.0, Section 3
type ProviderMetadata struct {
	Issuer                                     string   `json:"issuer"`                 // REQUIRED
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"` // REQUIRED
	TokenEndpoint                              string   `json:"token_endpoint,omitempty"`
	UserinfoEndpoint                           string   `json:"userinfo_endpoint,omitempty"`
	JwksURI                                    string   `json:"jwks_uri"` // REQUIRED
	RegistrationEndpoint                       string   `json:"registration_endpoint,omitempty"`
	ScopesSupported                            []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported                     []string `json:"response_types_supported"` // REQUIRED
	ResponseModesSupported                     []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported                        []string `json:"grant_types_supported,omitempty"`
	AcrValuesSupported                         []string `json:"acr_values_supported,omitempty"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`               // REQUIRED
	IDTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"` // REQUIRED
	IDTokenEncryptionAlgValuesSupported        []string `json:"id_token_encryption_alg_values_supported,omitempty"`
	IDTokenEncryptionEncValuesSupported        []string `json:"id_token_encryption_enc_values_supported,omitempty"`
	UserinfoSigningAlgValuesSupported          []string `json:"userinfo_signing_alg_values_supported,omitempty"`
	UserinfoEncryptionAlgValuesSupported       []string `json:"userinfo_encryption_alg_values_supported,omitempty"`
	UserinfoEncryptionEncValuesSupported       []string `json:"userinfo_encryption_enc_values_supported,omitempty"`
	RequestObjectSigningAlgValuesSupported     []string `json:"request_object_signing_alg_values_supported,omitempty"`
	RequestObjectEncryptionAlgValuesSupported  []string `json:"request_object_encryption_alg_values_supported,omitempty"`
	RequestObjectEncryptionEncValuesSupported  []string `json:"request_object_encryption_enc_values_supported,omitempty"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	DisplayValuesSupported                     []string `json:"display_values_supported,omitempty"`
	ClaimTypesSupported                        []string `json:"claim_types_supported,omitempty"`
	ClaimsSupported                            []string `json:"claims_supported,omitempty"`
	ServiceDocumentation                       string   `json:"service_documentation,omitempty"`
	ClaimsLocalesSupported                     []string `json:"claims_locales_supported,omitempty"`
	UILocalesSupported                         []string `json:"ui_locales_supported,omitempty"`
	ClaimsParameterSupported                   bool     `json:"claims_parameter_supported,omitempty"`
	RequestParameterSupported                  bool     `json:"request_parameter_supported,omitempty"`
	RequestURIParameterSupported               bool     `json:"request_uri_parameter_supported,omitempty"`
	RequireRequestURIRegistration              bool     `json:"require_request_uri_registration,omitempty"`
	OpPolicyURI                                string   `json:"op_policy_uri,omitempty"`
	OpTosURI                                   string   `json:"op_tos_uri,omitempty"`
}

// SupportsScope checks if the provider supports the given scope.
func (m *ProviderMetadata) SupportsScope(scope string) bool {
	for _, s := range m.ScopesSupported {
		if s == scope {
			return true
		}
	}
	return false
}

// SupportsResponseType checks if the provider supports the given response type.
func (m *ProviderMetadata) SupportsResponseType(rt string) bool {
	for _, r := range m.ResponseTypesSupported {
		if r == rt {
			return true
		}
	}
	return false
}

// SupportsGrantType checks if the provider supports the given grant type.
func (m *ProviderMetadata) SupportsGrantType(gt string) bool {
	for _, g := range m.GrantTypesSupported {
		if g == gt {
			return true
		}
	}
	return false
}

// WebFingerResponse represents the JSON Resource Descriptor (JRD) returned by WebFinger.
// Reference: OpenID Connect Discovery 1.0, Section 2
type WebFingerResponse struct {
	Subject string          `json:"subject"`
	Links   []WebFingerLink `json:"links"`
}

// WebFingerLink represents a link element in the WebFinger response.
type WebFingerLink struct {
	Rel  string `json:"rel"`
	Href string `json:"href,omitempty"`
}

// GetIssuer returns the issuer URL from the WebFinger response if present.
func (r *WebFingerResponse) GetIssuer() string {
	for _, link := range r.Links {
		if link.Rel == IssuerRel {
			return link.Href
		}
	}
	return ""
}

package rfc7636

import "sync"

// RFC 7636 Parameter Names registered in the IANA OAuth Parameters Registry.
// Reference: RFC 7636, Sections 4.1, 4.2, 4.3, 4.5 & 6.1
const (
	// ParamCodeVerifier is the parameter name for the PKCE code verifier sent to the Token Endpoint.
	// Reference: RFC 7636, Sections 4.1 & 4.5
	ParamCodeVerifier = "code_verifier"

	// ParamCodeChallenge is the parameter name for the PKCE code challenge sent to the Authorization Endpoint.
	// Reference: RFC 7636, Sections 4.2 & 4.3
	ParamCodeChallenge = "code_challenge"

	// ParamCodeChallengeMethod is the parameter name for the PKCE transform method sent to the Authorization Endpoint.
	// Reference: RFC 7636, Section 4.3
	ParamCodeChallengeMethod = "code_challenge_method"
)

// RFC 7636 Code Challenge Methods registered in the IANA PKCE Code Challenge Methods Registry.
// Reference: RFC 7636, Sections 4.2, 4.3 & 6.2
const (
	// CodeChallengeMethodPlain indicates that code_challenge == code_verifier.
	// Reference: RFC 7636, Sections 4.2 & 4.3
	CodeChallengeMethodPlain = "plain"

	// CodeChallengeMethodS256 indicates that code_challenge == BASE64URL-ENCODE(SHA256(ASCII(code_verifier))).
	// Reference: RFC 7636, Sections 4.2 & 4.3
	CodeChallengeMethodS256 = "S256"

	// DefaultCodeChallengeMethod is the default method assumed if code_challenge_method is omitted.
	// Reference: RFC 7636, Section 4.3
	DefaultCodeChallengeMethod = CodeChallengeMethodPlain
)

// RFC 7636 Code Verifier length & entropy bounds.
// Reference: RFC 7636, Section 4.1
const (
	// MinCodeVerifierLength is the minimum allowed length of a code_verifier in characters (43 octets).
	// Reference: RFC 7636, Section 4.1
	MinCodeVerifierLength = 43

	// MaxCodeVerifierLength is the maximum allowed length of a code_verifier in characters (128 octets).
	// Reference: RFC 7636, Section 4.1
	MaxCodeVerifierLength = 128

	// DefaultCodeVerifierOctets is the recommended number of random octets (32 bytes -> 43 base64url chars).
	// Reference: RFC 7636, Section 4.1
	DefaultCodeVerifierOctets = 32
)

// AuthorizationRequest represents the PKCE parameters for an OAuth 2.0 Authorization Request.
// Reference: RFC 7636, Section 4.3
type AuthorizationRequest struct {
	CodeChallenge       string `json:"code_challenge"`                  // REQUIRED
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"` // OPTIONAL, defaults to "plain" if not present
}

// EffectiveMethod returns the code_challenge_method, defaulting to "plain" if empty.
// Reference: RFC 7636, Section 4.3 & Section 4.4
func (r AuthorizationRequest) EffectiveMethod() string {
	if r.CodeChallengeMethod == "" {
		return DefaultCodeChallengeMethod
	}
	return r.CodeChallengeMethod
}

// TokenRequest represents the PKCE parameters for an OAuth 2.0 Access Token Request.
// Reference: RFC 7636, Section 4.5
type TokenRequest struct {
	CodeVerifier string `json:"code_verifier"` // REQUIRED
}

// MethodVerifier defines the contract for a PKCE code_challenge_method implementation.
// Custom challenge transform methods can implement this interface and be injected into PKCE.
// Reference: RFC 7636, Sections 4.2, 4.6 & 6.2
type MethodVerifier interface {
	// ComputeChallenge derives a code_challenge from a valid code_verifier.
	ComputeChallenge(verifier string) (string, error)
	// Verify checks whether the provided code_verifier matches the expected code_challenge.
	Verify(verifier string, expectedChallenge string) bool
}

// TransformFunc is a function adapter that transforms a valid code_verifier into a code_challenge.
// It implements MethodVerifier using constant-time comparison for Verify (RFC 7636, Section 4.6).
type TransformFunc func(verifier string) (string, error)

// VerifierFunc is a function adapter that directly verifies a code_verifier against an expectedChallenge.
type VerifierFunc func(verifier string, expectedChallenge string) bool

// PKCE is an extendable Proof Key for Code Exchange (RFC 7636) validator and challenge manager.
// It allows injecting custom MethodVerifier implementations beyond the standard "plain" and "S256" methods,
// or restricting allowed methods (e.g., disabling "plain" per RFC 7636 Section 7.2).
// Reference: RFC 7636, Sections 4.2, 4.3, 4.6 & 6.2
type PKCE struct {
	mu        sync.RWMutex
	verifiers map[string]MethodVerifier
}

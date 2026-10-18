package rfc7519

import (
	"encoding/json"
	"fmt"
)

// Media Types specified by RFC 7519.
const (
	// MediaTypeJWT is the MIME media type for JSON Web Tokens.
	// Reference: RFC 7519, Section 10.3
	MediaTypeJWT = "application/jwt"
)

// ============================================================================
// 1. JWT Claims Set (RFC 7519, Section 4)
// ============================================================================

// Claims represent the standard Registered Claim Names defined in RFC 7519.
// Note: "NumericDate" values (exp, nbf, iat) are represented as int64
// containing the number of seconds from 1970-01-01T00:00:00Z UTC.
type Claims struct {
	// Iss (Issuer) identifies the principal that issued the JWT. (Section 4.1.1)
	Issuer string `json:"iss,omitempty"`

	// Sub (Subject) identifies the principal that is the subject of the JWT. (Section 4.1.2)
	Subject string `json:"sub,omitempty"`

	// Aud (Audience) identifies the recipients that the JWT is intended for. (Section 4.1.3)
	// Handled via a custom type to support both `string` and `[]string` JSON formats.
	Audience Audience `json:"aud,omitempty"`

	// Exp (Expiration Time) identifies the expiration time on or after which the JWT
	// MUST NOT be accepted for processing. (Section 4.1.4)
	ExpiresAt int64 `json:"exp,omitempty"`

	// Nbf (Not Before) identifies the time before which the JWT MUST NOT be accepted
	// for processing. (Section 4.1.5)
	NotBefore int64 `json:"nbf,omitempty"`

	// Iat (Issued At) identifies the time at which the JWT was issued. (Section 4.1.6)
	IssuedAt int64 `json:"iat,omitempty"`

	// Jti (JWT ID) provides a unique identifier for the JWT. (Section 4.1.7)
	ID string `json:"jti,omitempty"`
}

// Audience is a custom type to safely handle the "aud" claim.
// RFC 7519 dictates this can be a single string OR an array of strings.
type Audience []string

// UnmarshalJSON ensures that whether the JSON is `"aud": "api1"` or
// `"aud": ["api1", "api2"]`, it safely parses into a Go slice of strings.
func (a *Audience) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = []string{single}
		return nil
	}

	var multiple []string
	if err := json.Unmarshal(data, &multiple); err != nil {
		return fmt.Errorf("jwt: aud claim is neither string nor array of strings")
	}

	*a = multiple
	return nil
}

// MarshalJSON ensures that a single audience is serialized as a string,
// and multiple audiences are serialized as an array, optimizing the payload.
func (a Audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	// Note: an empty slice will marshal to `[]` unless `omitempty` catches it on the parent struct.
	return json.Marshal([]string(a))
}

// ============================================================================
// 2. JOSE Header (RFC 7519, Section 5 / RFC 7515)
// ============================================================================

// Header represents the JOSE Header of the JWT.
// It encompasses the typing claims from RFC 7519 and the cryptographic
// parameters from RFC 7515 (JWS) and RFC 7516 (JWE).
type Header struct {
	// --- RFC 7519 Specific ---

	// Typ (Type) is used by JWT applications to declare the media type.
	// Typically "JWT" or "application/jwt". (Section 5.1)
	Typ string `json:"typ,omitempty"`

	// Cty (Content Type) is used to declare the structural makeup of the JWT.
	// Normally used when creating Nested JWTs (a JWT inside a JWT). (Section 5.2)
	Cty string `json:"cty,omitempty"`

	// --- Standard Cryptographic Parameters (from RFC 7515) ---

	// Alg (Algorithm) used to secure the token (e.g., "RS256", "HS256", "none"). (Required)
	Alg string `json:"alg,omitempty"`

	// Kid (Key ID) is a hint indicating which key was used to secure the JWS.
	Kid string `json:"kid,omitempty"`

	// Jku (JWK Set URL) is a URI that refers to a resource for a set of JSON-encoded public keys.
	Jku string `json:"jku,omitempty"`

	// Jwk (JSON Web Key) is the public key that corresponds to the key used to digitally sign the JWS.
	// Note: You can replace `any` with the `JWK` struct from your previous implementation.
	Jwk any `json:"jwk,omitempty"`

	// X5u (X.509 URL) is a URI that refers to a resource for the X.509 public key certificate.
	X5u string `json:"x5u,omitempty"`

	// X5c (X.509 Certificate Chain) contains the X.509 public key certificate or certificate chain.
	X5c []string `json:"x5c,omitempty"`

	// X5t (X.509 Certificate SHA-1 Thumbprint)
	X5t string `json:"x5t,omitempty"`

	// X5tS256 (X.509 Certificate SHA-256 Thumbprint)
	X5tS256 string `json:"x5t#S256,omitempty"`

	// Crit (Critical) indicates that extensions to the JWS/JWE specifications are being used
	// that MUST be understood and processed.
	Crit []string `json:"crit,omitempty"`
}

// ============================================================================
// 3. Unsecured JWT (Optional, for context)
// ============================================================================

// UnsecuredJWT is an optional wrapper for representing a token explicitly
// marked with `{"alg": "none"}` before signature validation occurs.
type UnsecuredJWT struct {
	Header Header `json:"header"`
	Claims Claims `json:"claims"`
}

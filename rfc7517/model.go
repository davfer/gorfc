package rfc7517

// Media Types specified by RFC 7517.
// Reference: RFC 7517, Section 8 & IANA Media Types Registry
const (
	// MediaTypeJWKSetJSON is the MIME media type for JWK Sets.
	// Reference: RFC 7517, Section 8.5
	MediaTypeJWKSetJSON = "application/jwk-set+json"

	// MediaTypeJWKJSON is the MIME media type for a single JWK.
	// Reference: RFC 7517, Section 8.1
	MediaTypeJWKJSON = "application/jwk+json"

	// ContentTypeJWKSetJSON is an alias for MediaTypeJWKSetJSON.
	ContentTypeJWKSetJSON = MediaTypeJWKSetJSON

	// ContentTypeJWKJSON is an alias for MediaTypeJWKJSON.
	ContentTypeJWKJSON = MediaTypeJWKJSON
)

// JWKS represents a JSON Web Key Set (RFC 7517, Section 5).
// It acts as a container for an array of JSON Web Keys.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a single JSON Web Key (RFC 7517 and RFC 7518).
// It includes common parameters as well as RSA, EC, and Symmetric key parameters.
type JWK struct {
	// --- Common JWK Parameters (RFC 7517, Section 4) ---

	// Kty (Key Type) identifies the cryptographic algorithm family.
	// e.g., "RSA", "EC", or "oct". (Required)
	Kty string `json:"kty"`

	// Use (Public Key Use) identifies the intended use of the public key.
	// e.g., "sig" (signature) or "enc" (encryption).
	Use string `json:"use,omitempty"`

	// KeyOps (Key Operations) identifies the operation(s) for which the key is intended.
	// e.g., ["sign", "verify", "encrypt", "decrypt"].
	KeyOps []string `json:"key_ops,omitempty"`

	// Alg (Algorithm) intended for use with the key. e.g., "RS256" or "ES256".
	Alg string `json:"alg,omitempty"`

	// Kid (Key ID) is used to match a specific key.
	Kid string `json:"kid,omitempty"`

	// X5u is a URI that refers to a resource for an X.509 public key certificate.
	X5u string `json:"x5u,omitempty"`

	// X5c contains a chain of one or more base64-encoded X.509 certificates.
	X5c []string `json:"x5c,omitempty"`

	// X5t is a base64url-encoded SHA-1 thumbprint of the DER encoding of an X.509 certificate.
	X5t string `json:"x5t,omitempty"`

	// X5tS256 is the SHA-256 thumbprint version of x5t.
	X5tS256 string `json:"x5t#S256,omitempty"`

	// --- RSA Public & Private Key Parameters (RFC 7518, Section 6.3) ---

	N   string `json:"n,omitempty"`   // RSA modulus (Base64urlUInt-encoded)
	E   string `json:"e,omitempty"`   // RSA public exponent (Base64urlUInt-encoded)
	D   string `json:"d,omitempty"`   // RSA private exponent / EC private key
	P   string `json:"p,omitempty"`   // RSA first prime factor
	Q   string `json:"q,omitempty"`   // RSA second prime factor
	Dp  string `json:"dp,omitempty"`  // RSA first factor CRT exponent
	Dq  string `json:"dq,omitempty"`  // RSA second factor CRT exponent
	Qi  string `json:"qi,omitempty"`  // RSA first CRT coefficient
	Oth []Oth  `json:"oth,omitempty"` // RSA other prime info (for multi-prime RSA keys)

	// --- Elliptic Curve (EC) Public Key Parameters (RFC 7518, Section 6.2) ---

	Crv string `json:"crv,omitempty"` // EC Curve (e.g., "P-256", "P-384", "P-521")
	X   string `json:"x,omitempty"`   // EC X Coordinate (Base64url-encoded)
	Y   string `json:"y,omitempty"`   // EC Y Coordinate (Base64url-encoded)

	// --- Symmetric Key Parameters (RFC 7518, Section 6.4) ---

	K string `json:"k,omitempty"` // Symmetric key value (Base64url-encoded)
}

// Oth represents additional primes for RSA multi-prime keys.
type Oth struct {
	R string `json:"r,omitempty"` // Prime factor
	D string `json:"d,omitempty"` // Factor CRT exponent
	T string `json:"t,omitempty"` // Factor CRT coefficient
}

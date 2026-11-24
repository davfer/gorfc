package rfc7636

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sort"
)

// Standard errors returned during PKCE processing.
// Reference: RFC 7636, Sections 4.1, 4.2, 4.4.1 & 4.6
var (
	ErrInvalidCodeVerifier            = errors.New("invalid code_verifier format")
	ErrInvalidCodeChallenge           = errors.New("invalid code_challenge format")
	ErrUnsupportedCodeChallengeMethod = errors.New("unsupported code_challenge_method")
	ErrCodeVerifierMismatch           = errors.New("code_verifier verification failed")
)

// ComputeChallenge calls the underlying TransformFunc after validating the code_verifier format.
// Reference: RFC 7636, Section 4.2
func (f TransformFunc) ComputeChallenge(verifier string) (string, error) {
	if !IsValidCodeVerifier(verifier) {
		return "", ErrInvalidCodeVerifier
	}
	return f(verifier)
}

// Verify derives the challenge using TransformFunc and performs a constant-time comparison
// against expectedChallenge to prevent timing side-channel attacks.
// Reference: RFC 7636, Section 4.6
func (f TransformFunc) Verify(verifier string, expectedChallenge string) bool {
	if expectedChallenge == "" || !IsValidCodeVerifier(verifier) {
		return false
	}
	computed, err := f(verifier)
	if err != nil {
		return false
	}
	if len(computed) != len(expectedChallenge) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(computed), []byte(expectedChallenge)) == 1
}

// ComputeChallenge returns ErrUnsupportedCodeChallengeMethod when only a VerifierFunc is registered.
func (f VerifierFunc) ComputeChallenge(_ string) (string, error) {
	return "", ErrUnsupportedCodeChallengeMethod
}

// Verify validates the code_verifier syntax and invokes the underlying VerifierFunc.
// Reference: RFC 7636, Section 4.6
func (f VerifierFunc) Verify(verifier string, expectedChallenge string) bool {
	if expectedChallenge == "" || !IsValidCodeVerifier(verifier) {
		return false
	}
	return f(verifier, expectedChallenge)
}

// PlainVerifier implements the "plain" PKCE code challenge method:
// code_challenge = code_verifier
// Reference: RFC 7636, Sections 4.2 & 4.6
var PlainVerifier MethodVerifier = TransformFunc(func(verifier string) (string, error) {
	return verifier, nil
})

// S256Verifier implements the "S256" PKCE code challenge method:
// code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
// Reference: RFC 7636, Sections 4.2 & 4.6
var S256Verifier MethodVerifier = TransformFunc(func(verifier string) (string, error) {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:]), nil
})

// DefaultPKCE is the default PKCE instance configured with the standard "plain" and "S256" verifiers.
// Reference: RFC 7636, Section 4.2
var DefaultPKCE = NewDefaultPKCE()

// NewPKCE creates a new PKCE instance with the provided map of method verifiers.
// If verifiers is nil, an empty verifier registry is initialized.
func NewPKCE(verifiers map[string]MethodVerifier) *PKCE {
	m := make(map[string]MethodVerifier, len(verifiers))
	for k, v := range verifiers {
		if v != nil {
			m[k] = v
		}
	}
	return &PKCE{
		verifiers: m,
	}
}

// NewDefaultPKCE creates a new PKCE instance pre-configured with "plain" and "S256" verifiers.
// Reference: RFC 7636, Section 4.2
func NewDefaultPKCE() *PKCE {
	return NewPKCE(map[string]MethodVerifier{
		CodeChallengeMethodPlain: PlainVerifier,
		CodeChallengeMethodS256:  S256Verifier,
	})
}

// RegisterMethod registers or replaces a MethodVerifier for the given code_challenge_method name.
// Reference: RFC 7636, Section 6.2
func (p *PKCE) RegisterMethod(method string, verifier MethodVerifier) {
	if method == "" || verifier == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.verifiers == nil {
		p.verifiers = make(map[string]MethodVerifier)
	}
	p.verifiers[method] = verifier
}

// RegisterTransform registers a TransformFunc for the given code_challenge_method name.
// Reference: RFC 7636, Section 6.2
func (p *PKCE) RegisterTransform(method string, fn TransformFunc) {
	if fn == nil {
		return
	}
	p.RegisterMethod(method, fn)
}

// RegisterVerifierFunc registers a VerifierFunc for the given code_challenge_method name.
// Reference: RFC 7636, Section 6.2
func (p *PKCE) RegisterVerifierFunc(method string, fn VerifierFunc) {
	if fn == nil {
		return
	}
	p.RegisterMethod(method, fn)
}

// RemoveMethod removes a code_challenge_method from the supported verifiers
// (for example, to disable "plain" per RFC 7636 Section 7.2).
func (p *PKCE) RemoveMethod(method string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.verifiers, method)
}

// SupportedMethods returns a sorted list of registered code_challenge_method names.
// Suitable for populating OAuth 2.0 Authorization Server Metadata "code_challenge_methods_supported".
// Reference: RFC 7636, Section 6.2 & RFC 8414, Section 2
func (p *PKCE) SupportedMethods() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	methods := make([]string, 0, len(p.verifiers))
	for m := range p.verifiers {
		methods = append(methods, m)
	}
	sort.Strings(methods)
	return methods
}

// IsValidCodeChallengeMethod checks if method is supported by this PKCE instance.
// Per RFC 7636 Section 4.3, an empty method defaults to "plain".
// Reference: RFC 7636, Sections 4.2, 4.3 & 4.4.1
func (p *PKCE) IsValidCodeChallengeMethod(method string) bool {
	if method == "" {
		method = DefaultCodeChallengeMethod
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.verifiers[method]
	return ok
}

// ComputeCodeChallenge derives a code_challenge from a code_verifier using the specified method.
// Per RFC 7636 Section 4.3, an empty method defaults to "plain".
// Reference: RFC 7636, Section 4.2
func (p *PKCE) ComputeCodeChallenge(verifier string, method string) (string, error) {
	if !IsValidCodeVerifier(verifier) {
		return "", ErrInvalidCodeVerifier
	}
	if method == "" {
		method = DefaultCodeChallengeMethod
	}
	p.mu.RLock()
	v, ok := p.verifiers[method]
	p.mu.RUnlock()
	if !ok {
		return "", ErrUnsupportedCodeChallengeMethod
	}
	return v.ComputeChallenge(verifier)
}

// VerifyCodeVerifier verifies a code_verifier against an expected code_challenge and method.
// Per RFC 7636 Section 4.3, an empty method defaults to "plain".
// Reference: RFC 7636, Section 4.6
func (p *PKCE) VerifyCodeVerifier(verifier string, expectedChallenge string, method string) bool {
	if expectedChallenge == "" || !IsValidCodeChallenge(expectedChallenge) || !IsValidCodeVerifier(verifier) {
		return false
	}
	if method == "" {
		method = DefaultCodeChallengeMethod
	}
	p.mu.RLock()
	v, ok := p.verifiers[method]
	p.mu.RUnlock()
	if !ok {
		return false
	}
	return v.Verify(verifier, expectedChallenge)
}

// ValidateAuthorizationRequest validates the PKCE parameters of an Authorization Request.
// Reference: RFC 7636, Sections 4.3 & 4.4.1
func (p *PKCE) ValidateAuthorizationRequest(req AuthorizationRequest) error {
	if !IsValidCodeChallenge(req.CodeChallenge) {
		return ErrInvalidCodeChallenge
	}
	if !p.IsValidCodeChallengeMethod(req.EffectiveMethod()) {
		return ErrUnsupportedCodeChallengeMethod
	}
	return nil
}

// ValidateTokenRequest validates the PKCE TokenRequest against an expected challenge and method.
// Reference: RFC 7636, Sections 4.5 & 4.6
func (p *PKCE) ValidateTokenRequest(req TokenRequest, expectedChallenge string, method string) error {
	if !IsValidCodeVerifier(req.CodeVerifier) {
		return ErrInvalidCodeVerifier
	}
	if !p.VerifyCodeVerifier(req.CodeVerifier, expectedChallenge, method) {
		return ErrCodeVerifierMismatch
	}
	return nil
}

// GenerateCodeVerifier generates a cryptographically random code_verifier using 32 octets (256 bits)
// of entropy encoded as a 43-character base64url string without padding.
// Reference: RFC 7636, Section 4.1
func GenerateCodeVerifier() (string, error) {
	return GenerateCodeVerifierWithOctets(DefaultCodeVerifierOctets)
}

// GenerateCodeVerifierWithOctets generates a cryptographically random code_verifier with the specified
// number of random octets (must produce between 43 and 128 base64url characters, i.e., 32 to 96 octets).
// Reference: RFC 7636, Section 4.1
func GenerateCodeVerifierWithOctets(numOctets int) (string, error) {
	if numOctets < 32 || numOctets > 96 {
		return "", ErrInvalidCodeVerifier
	}
	b := make([]byte, numOctets)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// IsValidCodeVerifier checks whether the given string conforms to RFC 7636 Section 4.1 ABNF:
// code-verifier = 43*128unreserved
// unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
// Reference: RFC 7636, Section 4.1
func IsValidCodeVerifier(verifier string) bool {
	if len(verifier) < MinCodeVerifierLength || len(verifier) > MaxCodeVerifierLength {
		return false
	}
	for i := 0; i < len(verifier); i++ {
		if !isUnreservedChar(verifier[i]) {
			return false
		}
	}
	return true
}

// IsValidCodeChallenge checks whether code_challenge conforms to RFC 7636 Section 4.2 ABNF:
// code-challenge = 43*128unreserved
// Note: allows any non-empty unreserved string up to MaxCodeVerifierLength to support custom challenge transforms,
// while ensuring strict unreserved character syntax.
// Reference: RFC 7636, Section 4.2
func IsValidCodeChallenge(challenge string) bool {
	if len(challenge) == 0 {
		return false
	}
	for i := 0; i < len(challenge); i++ {
		if !isUnreservedChar(challenge[i]) {
			return false
		}
	}
	return true
}

// IsValidCodeChallengeMethod checks if method is a supported transform method in DefaultPKCE ("plain" or "S256").
// Reference: RFC 7636, Sections 4.2 & 4.3
func IsValidCodeChallengeMethod(method string) bool {
	return DefaultPKCE.IsValidCodeChallengeMethod(method)
}

// ComputeCodeChallenge derives a code_challenge from a code_verifier using DefaultPKCE.
// Reference: RFC 7636, Section 4.2
func ComputeCodeChallenge(verifier string, method string) (string, error) {
	return DefaultPKCE.ComputeCodeChallenge(verifier, method)
}

// VerifyCodeVerifier verifies a code_verifier against an expected code_challenge and method using DefaultPKCE.
// Uses constant-time comparison to prevent timing attacks.
// Reference: RFC 7636, Section 4.6
func VerifyCodeVerifier(verifier string, expectedChallenge string, method string) bool {
	return DefaultPKCE.VerifyCodeVerifier(verifier, expectedChallenge, method)
}

func isUnreservedChar(c byte) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

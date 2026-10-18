package rfc7636

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
)

// IsValidCodeVerifier checks whether the given string conforms to RFC 7636 Section 4.1 ABNF:
// code-verifier = 43*128unreserved
// unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
func IsValidCodeVerifier(verifier string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	for i := 0; i < len(verifier); i++ {
		if !isUnreservedChar(verifier[i]) {
			return false
		}
	}
	return true
}

// IsValidCodeChallenge checks whether code_challenge contains valid unreserved characters.
// Reference: RFC 7636 Section 4.2
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

// IsValidCodeChallengeMethod checks if method is a supported transform method ("plain" or "S256").
// Reference: RFC 7636 Section 4.2 & 4.3
func IsValidCodeChallengeMethod(method string) bool {
	return method == CodeChallengeMethodPlain || method == CodeChallengeMethodS256 || method == ""
}

// ComputeCodeChallenge derives a code_challenge from a code_verifier using the specified method.
// Reference: RFC 7636 Section 4.2
func ComputeCodeChallenge(verifier string, method string) (string, error) {
	if !IsValidCodeVerifier(verifier) {
		return "", errors.New("invalid code_verifier format")
	}
	switch method {
	case CodeChallengeMethodPlain, "":
		return verifier, nil
	case CodeChallengeMethodS256:
		h := sha256.Sum256([]byte(verifier))
		return base64.RawURLEncoding.EncodeToString(h[:]), nil
	default:
		return "", errors.New("unsupported code_challenge_method")
	}
}

// VerifyCodeVerifier verifies a code_verifier against an expected code_challenge and method.
// Uses constant-time comparison to prevent timing attacks.
// Reference: RFC 7636 Section 4.6
func VerifyCodeVerifier(verifier string, expectedChallenge string, method string) bool {
	if expectedChallenge == "" {
		return false
	}
	computed, err := ComputeCodeChallenge(verifier, method)
	if err != nil {
		return false
	}
	if len(computed) != len(expectedChallenge) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(computed), []byte(expectedChallenge)) == 1
}

func isUnreservedChar(c byte) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

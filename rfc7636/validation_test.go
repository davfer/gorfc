package rfc7636

import (
	"crypto/sha512"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCodeVerifierValidation(t *testing.T) {
	// 43 character valid verifier (RFC 7636 Appendix B)
	appendixBVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	assert.True(t, IsValidCodeVerifier(appendixBVerifier))

	// Too short (<43)
	shortVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjX"
	assert.False(t, IsValidCodeVerifier(shortVerifier))

	// Invalid character ('@')
	invalidCharVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk@"
	assert.False(t, IsValidCodeVerifier(invalidCharVerifier))

	// Max length (128 unreserved chars)
	maxVerifier := strings.Repeat("a", 128)
	assert.Equal(t, 128, len(maxVerifier))
	assert.True(t, IsValidCodeVerifier(maxVerifier))

	// Exceeds max length (129)
	tooLongVerifier := strings.Repeat("a", 129)
	assert.False(t, IsValidCodeVerifier(tooLongVerifier))
}

func TestComputeCodeChallenge_AppendixB(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	expectedChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	// S256 method
	challenge, err := ComputeCodeChallenge(verifier, CodeChallengeMethodS256)
	require.NoError(t, err)
	assert.Equal(t, expectedChallenge, challenge)

	// VerifyCodeVerifier check
	assert.True(t, VerifyCodeVerifier(verifier, expectedChallenge, CodeChallengeMethodS256))

	// Plain method
	plainChallenge, err := ComputeCodeChallenge(verifier, CodeChallengeMethodPlain)
	require.NoError(t, err)
	assert.Equal(t, verifier, plainChallenge)
	assert.True(t, VerifyCodeVerifier(verifier, verifier, CodeChallengeMethodPlain))

	// Default method ("") defaults to plain
	defaultChallenge, err := ComputeCodeChallenge(verifier, "")
	require.NoError(t, err)
	assert.Equal(t, verifier, defaultChallenge)
	assert.True(t, VerifyCodeVerifier(verifier, verifier, ""))
}

func TestVerifyCodeVerifier_Mismatches(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	expectedChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	// Wrong verifier
	assert.False(t, VerifyCodeVerifier("wrong_verifier_123456789012345678901234567890123456", expectedChallenge, CodeChallengeMethodS256))

	// Empty challenge
	assert.False(t, VerifyCodeVerifier(verifier, "", CodeChallengeMethodS256))

	// Invalid challenge characters
	assert.False(t, VerifyCodeVerifier(verifier, "invalid@challenge", CodeChallengeMethodS256))

	// Unsupported method
	assert.False(t, VerifyCodeVerifier(verifier, expectedChallenge, "INVALID_METHOD"))
}

func TestIsValidCodeChallengeMethod(t *testing.T) {
	assert.True(t, IsValidCodeChallengeMethod("S256"))
	assert.True(t, IsValidCodeChallengeMethod("plain"))
	assert.True(t, IsValidCodeChallengeMethod(""))
	assert.False(t, IsValidCodeChallengeMethod("RS256"))
}

func TestGenerateCodeVerifier(t *testing.T) {
	v, err := GenerateCodeVerifier()
	require.NoError(t, err)
	assert.Len(t, v, MinCodeVerifierLength)
	assert.True(t, IsValidCodeVerifier(v))

	v96, err := GenerateCodeVerifierWithOctets(96)
	require.NoError(t, err)
	assert.Len(t, v96, MaxCodeVerifierLength)
	assert.True(t, IsValidCodeVerifier(v96))

	_, err = GenerateCodeVerifierWithOctets(16)
	assert.ErrorIs(t, err, ErrInvalidCodeVerifier)

	_, err = GenerateCodeVerifierWithOctets(97)
	assert.ErrorIs(t, err, ErrInvalidCodeVerifier)
}

func TestExtendablePKCE_CustomVerifiers(t *testing.T) {
	pkce := NewDefaultPKCE()
	assert.Equal(t, []string{CodeChallengeMethodS256, CodeChallengeMethodPlain}, pkce.SupportedMethods())

	// 1. Inject a custom S512 TransformFunc
	pkce.RegisterTransform("S512", func(verifier string) (string, error) {
		h := sha512.Sum512([]byte(verifier))
		return base64.RawURLEncoding.EncodeToString(h[:]), nil
	})

	assert.True(t, pkce.IsValidCodeChallengeMethod("S512"))
	assert.Equal(t, []string{CodeChallengeMethodS256, "S512", CodeChallengeMethodPlain}, pkce.SupportedMethods())

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	s512Challenge, err := pkce.ComputeCodeChallenge(verifier, "S512")
	require.NoError(t, err)
	assert.NotEmpty(t, s512Challenge)
	assert.True(t, pkce.VerifyCodeVerifier(verifier, s512Challenge, "S512"))
	assert.False(t, pkce.VerifyCodeVerifier(verifier, "wrong_challenge_value", "S512"))

	// 2. Inject a custom VerifierFunc
	pkce.RegisterVerifierFunc("custom-prefix", func(v, expected string) bool {
		return "prefix_"+v == expected
	})
	assert.True(t, pkce.IsValidCodeChallengeMethod("custom-prefix"))
	_, err = pkce.ComputeCodeChallenge(verifier, "custom-prefix")
	assert.ErrorIs(t, err, ErrUnsupportedCodeChallengeMethod)
	assert.True(t, pkce.VerifyCodeVerifier(verifier, "prefix_"+verifier, "custom-prefix"))
	assert.False(t, pkce.VerifyCodeVerifier(verifier, "wrong_"+verifier, "custom-prefix"))

	// 3. Remove "plain" method (RFC 7636 Section 7.2)
	pkce.RemoveMethod(CodeChallengeMethodPlain)
	assert.False(t, pkce.IsValidCodeChallengeMethod(CodeChallengeMethodPlain))
	assert.False(t, pkce.IsValidCodeChallengeMethod("")) // empty defaults to plain, which is now disabled
	assert.False(t, pkce.VerifyCodeVerifier(verifier, verifier, CodeChallengeMethodPlain))
}

func TestPKCE_ValidateRequests(t *testing.T) {
	pkce := NewDefaultPKCE()
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	authReq := AuthorizationRequest{
		CodeChallenge:       challenge,
		CodeChallengeMethod: CodeChallengeMethodS256,
	}
	assert.Equal(t, CodeChallengeMethodS256, authReq.EffectiveMethod())
	assert.NoError(t, pkce.ValidateAuthorizationRequest(authReq))

	defaultMethodReq := AuthorizationRequest{
		CodeChallenge: verifier,
	}
	assert.Equal(t, CodeChallengeMethodPlain, defaultMethodReq.EffectiveMethod())
	assert.NoError(t, pkce.ValidateAuthorizationRequest(defaultMethodReq))

	invalidChallengeReq := AuthorizationRequest{
		CodeChallenge: "bad challenge with spaces",
	}
	assert.ErrorIs(t, pkce.ValidateAuthorizationRequest(invalidChallengeReq), ErrInvalidCodeChallenge)

	unsupportedMethodReq := AuthorizationRequest{
		CodeChallenge:       challenge,
		CodeChallengeMethod: "UNKNOWN",
	}
	assert.ErrorIs(t, pkce.ValidateAuthorizationRequest(unsupportedMethodReq), ErrUnsupportedCodeChallengeMethod)

	tokenReq := TokenRequest{
		CodeVerifier: verifier,
	}
	assert.NoError(t, pkce.ValidateTokenRequest(tokenReq, challenge, CodeChallengeMethodS256))
	assert.ErrorIs(t, pkce.ValidateTokenRequest(TokenRequest{CodeVerifier: "short"}, challenge, CodeChallengeMethodS256), ErrInvalidCodeVerifier)
	assert.ErrorIs(t, pkce.ValidateTokenRequest(tokenReq, "wrong-challenge", CodeChallengeMethodS256), ErrCodeVerifierMismatch)
}

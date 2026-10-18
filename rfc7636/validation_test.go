package rfc7636

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCodeVerifierValidation(t *testing.T) {
	// 43 character valid verifier
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
}

func TestVerifyCodeVerifier_Mismatches(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	expectedChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	// Wrong verifier
	assert.False(t, VerifyCodeVerifier("wrong_verifier_123456789012345678901234567890123456", expectedChallenge, CodeChallengeMethodS256))

	// Empty challenge
	assert.False(t, VerifyCodeVerifier(verifier, "", CodeChallengeMethodS256))

	// Unsupported method
	assert.False(t, VerifyCodeVerifier(verifier, expectedChallenge, "INVALID_METHOD"))
}

func TestIsValidCodeChallengeMethod(t *testing.T) {
	assert.True(t, IsValidCodeChallengeMethod("S256"))
	assert.True(t, IsValidCodeChallengeMethod("plain"))
	assert.True(t, IsValidCodeChallengeMethod(""))
	assert.False(t, IsValidCodeChallengeMethod("RS256"))
}

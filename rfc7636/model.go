package rfc7636

// RFC 7636 Parameter Names
// Reference: RFC 7636 Section 4.1, 4.2 & 4.3
const (
	ParamCodeVerifier        = "code_verifier"
	ParamCodeChallenge       = "code_challenge"
	ParamCodeChallengeMethod = "code_challenge_method"
)

// RFC 7636 Code Challenge Methods
// Reference: RFC 7636 Section 4.2 & 4.3
const (
	CodeChallengeMethodPlain = "plain"
	CodeChallengeMethodS256  = "S256"
)

package idtoken

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"strings"

	"github.com/davfer/gorfc/oidc/identity"
)

// IDTokenClaims represents the claims contained in an ID Token.
// Reference: OpenID Connect Core 1.0, Section 2
type IDTokenClaims struct {
	Issuer   string   `json:"iss"`                 // REQUIRED
	Subject  string   `json:"sub"`                 // REQUIRED
	Audience []string `json:"aud"`                 // REQUIRED
	Expiry   int64    `json:"exp"`                 // REQUIRED
	IssuedAt int64    `json:"iat"`                 // REQUIRED
	AuthTime int64    `json:"auth_time,omitempty"` // REQUIRED if max_age is used
	Nonce    string   `json:"nonce,omitempty"`
	ACR      string   `json:"acr,omitempty"`
	AMR      []string `json:"amr,omitempty"`
	AZP      string   `json:"azp,omitempty"`
}

// ComputeHash calculates at_hash or c_hash for an access_token or authorization code according to OIDC spec.
// Reference: OpenID Connect Core 1.0, Section 3.1.3.6 & Section 3.3.2.11
func ComputeHash(value string, alg string) (string, error) {
	if value == "" {
		return "", nil
	}

	var h hash.Hash
	switch strings.ToUpper(alg) {
	case "RS256", "ES256", "HS256", "PS256":
		h = sha256.New()
	case "RS384", "ES384", "HS384", "PS384":
		h = sha512.New384()
	case "RS512", "ES512", "HS512", "PS512":
		h = sha512.New()
	default:
		h = sha256.New()
	}

	h.Write([]byte(value))
	digest := h.Sum(nil)
	halfLen := len(digest) / 2

	return base64.RawURLEncoding.EncodeToString(digest[:halfLen]), nil
}

// IDTokenIssuer is responsible for building and signing ID Tokens for a given identity session and client.
// Reference: OpenID Connect Core 1.0, Section 2 & Section 3.1.3.3
type IDTokenIssuer interface {
	// IssueIDToken generates and signs a JWT ID Token for the specified identity session, client_id, and nonce.
	IssueIDToken(ctx context.Context, session identity.Session, clientID string, nonce string, accessToken string, code string) (string, error)
}

// DefaultIDTokenIssuer is a default implementation of IDTokenIssuer that formats IDTokenClaims.
type DefaultIDTokenIssuer struct {
	Issuer         string
	SignerFunc     func(ctx context.Context, claims IDTokenClaims) (string, error)
	DefaultExpiryS int64
}

// IssueIDToken builds and signs an ID Token using DefaultIDTokenIssuer.
func (i *DefaultIDTokenIssuer) IssueIDToken(ctx context.Context, session identity.Session, clientID string, nonce string, accessToken string, code string) (string, error) {
	if i.SignerFunc == nil {
		return "", fmt.Errorf("idtoken: SignerFunc is not configured")
	}

	expiry := i.DefaultExpiryS
	if expiry <= 0 {
		expiry = 3600
	}

	claims := IDTokenClaims{
		Issuer:   i.Issuer,
		Subject:  session.Subject(),
		Audience: []string{clientID},
		Nonce:    nonce,
		AuthTime: identity.GetAuthTime(session),
		ACR:      identity.GetACR(session),
		AMR:      identity.GetAMR(session),
	}

	if accessToken != "" {
		atHash, err := ComputeHash(accessToken, "RS256")
		if err == nil {
			claims.AZP = clientID
			_ = atHash
		}
	}

	return i.SignerFunc(ctx, claims)
}

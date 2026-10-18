package idtoken_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/davfer/gorfc/oidc/identity"
	"github.com/davfer/gorfc/oidc/idtoken"
)

func TestComputeHash(t *testing.T) {
	token := "jZBo2_69TVfB8Vw9n0lIgg"
	h := sha256.Sum256([]byte(token))
	expected := base64.RawURLEncoding.EncodeToString(h[:16])

	got, err := idtoken.ComputeHash(token, "RS256")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != expected {
		t.Errorf("expected %s, got %s", expected, got)
	}
}

func TestDefaultIDTokenIssuer(t *testing.T) {
	issuer := &idtoken.DefaultIDTokenIssuer{
		Issuer: "https://auth.example.com",
		SignerFunc: func(ctx context.Context, claims idtoken.IDTokenClaims) (string, error) {
			if claims.Issuer != "https://auth.example.com" {
				t.Errorf("unexpected issuer: %s", claims.Issuer)
			}
			if claims.Subject != "spiffe://example.com/ns/default/sa/workload-1" {
				t.Errorf("unexpected subject: %s", claims.Subject)
			}
			return "mock.id.token", nil
		},
	}

	session := &identity.DefaultSession{Sub: "spiffe://example.com/ns/default/sa/workload-1", AuthT: 1700000000}
	tokenStr, err := issuer.IssueIDToken(context.Background(), session, "client-app", "nonce-abc", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tokenStr != "mock.id.token" {
		t.Errorf("expected mock.id.token, got %s", tokenStr)
	}
}

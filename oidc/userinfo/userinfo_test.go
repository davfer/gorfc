package userinfo_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/davfer/gorfc/oidc/identity"
	"github.com/davfer/gorfc/oidc/userinfo"
)

type mockTokenValidator struct {
	validToken string
	subject    string
	scopes     []string
}

func (m *mockTokenValidator) ValidateAccessToken(ctx context.Context, tokenStr string) (string, []string, error) {
	if tokenStr == m.validToken {
		return m.subject, m.scopes, nil
	}
	return "", nil, fmt.Errorf("invalid token")
}

type mockUserInfoProvider struct {
	claims *identity.StandardClaims
}

func (m *mockUserInfoProvider) GetUserInfo(ctx context.Context, subject string, scopes []string) (*identity.StandardClaims, error) {
	if subject == m.claims.Subject {
		return m.claims, nil
	}
	return nil, fmt.Errorf("not found")
}

func TestUserInfoHandler_MissingToken(t *testing.T) {
	h := userinfo.NewUserInfoHandler(nil, nil)
	req := httptest.NewRequest("GET", "/userinfo", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for missing token, got %d", w.Code)
	}
}

func TestUserInfoHandler_ValidTokenAndProfileEmailScopes(t *testing.T) {
	val := &mockTokenValidator{
		validToken: "valid_access_token_123",
		subject:    "spiffe://example.com/ns/default/sa/workload-1",
		scopes:     []string{"openid", "profile", "email"},
	}

	prov := &mockUserInfoProvider{
		claims: &identity.StandardClaims{
			Subject:       "spiffe://example.com/ns/default/sa/workload-1",
			Name:          "Workload Service",
			Email:         "workload@example.com",
			EmailVerified: true,
			PhoneNumber:   "+1234567890",
		},
	}

	h := userinfo.NewUserInfoHandler(val, prov)

	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer valid_access_token_123")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	var claims identity.StandardClaims
	if err := json.NewDecoder(w.Body).Decode(&claims); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if claims.Subject != "spiffe://example.com/ns/default/sa/workload-1" {
		t.Errorf("unexpected sub: %s", claims.Subject)
	}
	if claims.Name != "Workload Service" {
		t.Errorf("unexpected name: %s", claims.Name)
	}
	if claims.Email != "workload@example.com" {
		t.Errorf("unexpected email: %s", claims.Email)
	}
	if claims.PhoneNumber != "" {
		t.Errorf("expected phone_number to be omitted without phone scope, got %s", claims.PhoneNumber)
	}
}

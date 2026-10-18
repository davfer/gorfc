package token_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/davfer/gorfc/oauth/client"
	oauthToken "github.com/davfer/gorfc/oauth/token"
	"github.com/davfer/gorfc/oidc/identity"
	"github.com/davfer/gorfc/oidc/token"
	"github.com/davfer/gorfc/rfc6749"
)

type mockIDTokenIssuer struct{}

func (m *mockIDTokenIssuer) IssueIDToken(ctx context.Context, session identity.Session, clientID string, nonce string, accessToken string, code string) (string, error) {
	return "signed.id.token.jwt", nil
}

type mockIdentityProvider struct {
	session identity.Session
}

func (m *mockIdentityProvider) GetSession(ctx context.Context, r *http.Request) (identity.Session, error) {
	return m.session, nil
}

func TestTokenHandler_AppendsIDToken(t *testing.T) {
	mockIssuer := &mockIDTokenIssuer{}
	mockUser := &mockIdentityProvider{session: &identity.DefaultSession{Sub: "user-999"}}

	idToken, err := mockIssuer.IssueIDToken(context.Background(), mockUser.session, "client-id", "", "access-token-123", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if idToken != "signed.id.token.jwt" {
		t.Errorf("expected signed.id.token.jwt, got %s", idToken)
	}
}

func TestTokenHandler_ServeHTTP_FallbackWhenNil(t *testing.T) {
	h := token.NewTokenHandler(nil, nil, nil)
	req := httptest.NewRequest("POST", "/token", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500 when handler is nil, got %d", w.Code)
	}
}

func TestTokenResponseSerialization(t *testing.T) {
	resp := token.TokenResponse{
		AccessToken: "acc_123",
		TokenType:   "Bearer",
		IDToken:     "id_token_jwt",
		ExpiresIn:   3600,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal token response: %v", err)
	}

	var unmarshaled token.TokenResponse
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal token response: %v", err)
	}

	if unmarshaled.IDToken != "id_token_jwt" {
		t.Errorf("expected id_token_jwt, got %s", unmarshaled.IDToken)
	}
}

type mockClientAuth struct {
	client client.Client
}

func (m *mockClientAuth) AuthenticateClient(ctx context.Context, r *http.Request) (client.Client, error) {
	return m.client, nil
}

func TestTokenHandler_ServeHTTP_WithOpenIDScope(t *testing.T) {
	mockIssuer := &mockIDTokenIssuer{}
	mockUser := &mockIdentityProvider{session: &identity.DefaultSession{Sub: "user-999"}}

	svc := oauthToken.NewTokenService(map[string]oauthToken.GrantHandler{
		"authorization_code": oauthToken.GrantHandlerFunc(func(ctx context.Context, req rfc6749.TokenRequest) (*rfc6749.TokenResponse, error) {
			return &rfc6749.TokenResponse{
				AccessToken:  "access_token_123",
				TokenType:    "Bearer",
				RefreshToken: "refresh_token_456",
				ExpiresIn:    3600,
				Scope:        "openid profile",
			}, nil
		}),
	})

	clientAuth := &mockClientAuth{
		client: &client.DefaultClient{ID: "client_1", AllowedGrantTypes: []string{"authorization_code"}},
	}

	h := token.NewTokenHandlerFromService(svc, clientAuth, nil, mockIssuer, mockUser)

	form := url.Values{
		"grant_type": {"authorization_code"},
		"code":       {"valid_code"},
	}
	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp token.TokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.AccessToken != "access_token_123" {
		t.Errorf("expected access_token_123, got %s", resp.AccessToken)
	}
	if resp.IDToken != "signed.id.token.jwt" {
		t.Errorf("expected signed.id.token.jwt, got %s", resp.IDToken)
	}
	if resp.RefreshToken != "refresh_token_456" {
		t.Errorf("expected refresh_token_456, got %s", resp.RefreshToken)
	}
}

func TestTokenHandler_ServeHTTP_WithoutOpenIDScope(t *testing.T) {
	mockIssuer := &mockIDTokenIssuer{}

	svc := oauthToken.NewTokenService(map[string]oauthToken.GrantHandler{
		"client_credentials": oauthToken.GrantHandlerFunc(func(ctx context.Context, req rfc6749.TokenRequest) (*rfc6749.TokenResponse, error) {
			return &rfc6749.TokenResponse{
				AccessToken: "access_token_cc",
				TokenType:   "Bearer",
				ExpiresIn:   1800,
				Scope:       "read write",
			}, nil
		}),
	})

	clientAuth := &mockClientAuth{
		client: &client.DefaultClient{ID: "client_2", AllowedGrantTypes: []string{"client_credentials"}},
	}

	h := token.NewTokenHandlerFromService(svc, clientAuth, nil, mockIssuer, nil)

	form := url.Values{
		"grant_type": {"client_credentials"},
	}
	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var rawMap map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &rawMap); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if rawMap["access_token"] != "access_token_cc" {
		t.Errorf("expected access_token_cc, got %v", rawMap["access_token"])
	}
	if _, exists := rawMap["id_token"]; exists {
		t.Errorf("id_token should not be present when scope does not contain openid")
	}
}

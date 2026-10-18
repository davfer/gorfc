package authorize_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/davfer/gorfc/oauth/client"
	"github.com/davfer/gorfc/oauth/grant"
	"github.com/davfer/gorfc/oidc/authorize"
	"github.com/davfer/gorfc/oidc/identity"
	"github.com/davfer/gorfc/rfc6749"
)

type mockClientStore struct {
	client client.Client
}

func (m *mockClientStore) GetClient(ctx context.Context, id string) (client.Client, error) {
	if m.client != nil && id == m.client.ClientID() {
		return m.client, nil
	}
	return nil, nil
}

type mockIdentityProvider struct {
	session identity.Session
	err     error
}

func (m *mockIdentityProvider) GetSession(ctx context.Context, r *http.Request) (identity.Session, error) {
	return m.session, m.err
}

type mockErrorHandler struct {
	lastError rfc6749.ErrorResponse
	lastCode  int
}

func (m *mockErrorHandler) WriteAuthorizationError(w http.ResponseWriter, r *http.Request, redirectURI string, errResp rfc6749.ErrorResponse) {
	m.lastError = errResp
	if redirectURI != "" {
		u, _ := url.Parse(redirectURI)
		q := u.Query()
		q.Set("error", errResp.Error)
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	} else {
		m.lastCode = http.StatusBadRequest
		http.Error(w, errResp.Error, http.StatusBadRequest)
	}
}

type mockInteractionHandler struct {
	invoked bool
	lastReq rfc6749.AuthorizationRequest
}

func (m *mockInteractionHandler) HandleInteraction(w http.ResponseWriter, r *http.Request, req rfc6749.AuthorizationRequest) {
	m.invoked = true
	m.lastReq = req
	w.WriteHeader(http.StatusOK)
}

type mockCodeCreator struct {
	createdCode string
}

func (m *mockCodeCreator) CreateCode(ctx context.Context, req rfc6749.AuthorizationRequest, userID string) (*grant.AuthorizationCode, error) {
	return &grant.AuthorizationCode{
		Code: m.createdCode,
	}, nil
}

func TestAuthorizeHandler_ScopeOpenIDRequired(t *testing.T) {
	c := &client.DefaultClient{
		ID:                  "test-client",
		AllowedRedirectURIs: []string{"https://app.example.com/callback"},
	}
	cs := &mockClientStore{client: c}
	errH := &mockErrorHandler{}

	h := authorize.NewAuthorizeHandler(cs, nil, nil, nil, nil, errH)

	// Missing openid scope
	req := httptest.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://app.example.com/callback&response_type=code&scope=profile", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if errH.lastError.Error != rfc6749.ErrInvalidScope {
		t.Errorf("expected invalid_scope error, got %s", errH.lastError.Error)
	}
}

func TestAuthorizeHandler_PromptNone_NotLoggedIn(t *testing.T) {
	c := &client.DefaultClient{
		ID:                  "test-client",
		AllowedRedirectURIs: []string{"https://app.example.com/callback"},
	}
	cs := &mockClientStore{client: c}
	up := &mockIdentityProvider{session: nil}
	errH := &mockErrorHandler{}

	h := authorize.NewAuthorizeHandler(cs, up, nil, nil, nil, errH)

	req := httptest.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://app.example.com/callback&response_type=code&scope=openid&prompt=none", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if errH.lastError.Error != authorize.ErrLoginRequired {
		t.Errorf("expected login_required error for prompt=none without session, got %s", errH.lastError.Error)
	}
}

func TestAuthorizeHandler_SuccessfulAuthorizationCode(t *testing.T) {
	c := &client.DefaultClient{
		ID:                  "test-client",
		AllowedRedirectURIs: []string{"https://app.example.com/callback"},
	}
	cs := &mockClientStore{client: c}
	up := &mockIdentityProvider{session: &identity.DefaultSession{Sub: "user-123"}}
	errH := &mockErrorHandler{}

	h := authorize.NewAuthorizeHandler(cs, up, nil, nil, nil, errH)

	req := httptest.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://app.example.com/callback&response_type=code&scope=openid&state=xyz123", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected HTTP 302 redirect, got %d", w.Code)
	}

	loc := w.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("invalid redirect location: %v", err)
	}

	if u.Query().Get("state") != "xyz123" {
		t.Errorf("expected state xyz123, got %s", u.Query().Get("state"))
	}
	if u.Query().Get("code") == "" {
		t.Errorf("expected authorization code in redirect query")
	}
}

func TestAuthorizeHandler_HumanInteractionHandler_Invoked(t *testing.T) {
	c := &client.DefaultClient{
		ID:                  "test-client",
		AllowedRedirectURIs: []string{"https://app.example.com/callback"},
	}
	cs := &mockClientStore{client: c}
	up := &mockIdentityProvider{err: authorize.ErrNeedsHumanInteraction}
	errH := &mockErrorHandler{}
	interactionH := &mockInteractionHandler{}

	h := authorize.NewAuthorizeHandler(cs, up, nil, interactionH, nil, errH)

	req := httptest.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://app.example.com/callback&response_type=code&scope=openid&state=xyz123", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if !interactionH.invoked {
		t.Errorf("expected HumanInteractionHandler to be invoked")
	}
	if interactionH.lastReq.ClientID != "test-client" {
		t.Errorf("expected client_id test-client, got %s", interactionH.lastReq.ClientID)
	}
}

func TestAuthorizeHandler_CodeCreator_Invoked(t *testing.T) {
	c := &client.DefaultClient{
		ID:                  "test-client",
		AllowedRedirectURIs: []string{"https://app.example.com/callback"},
	}
	cs := &mockClientStore{client: c}
	up := &mockIdentityProvider{session: &identity.DefaultSession{Sub: "user-123"}}
	errH := &mockErrorHandler{}
	codeCreator := &mockCodeCreator{createdCode: "custom-generated-code-456"}

	h := authorize.NewAuthorizeHandler(cs, up, nil, nil, codeCreator, errH)

	req := httptest.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://app.example.com/callback&response_type=code&scope=openid&state=xyz123", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected HTTP 302 redirect, got %d", w.Code)
	}

	loc := w.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("invalid redirect location: %v", err)
	}

	if u.Query().Get("code") != "custom-generated-code-456" {
		t.Errorf("expected code custom-generated-code-456, got %s", u.Query().Get("code"))
	}
}

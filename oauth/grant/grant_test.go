package grant

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/davfer/gorfc/oauth/client"
	"github.com/davfer/gorfc/oauth/identity"
	"github.com/davfer/gorfc/rfc6749"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockUserConsentDecider struct {
	mock.Mock
}

func (m *MockUserConsentDecider) AuthenticateUser(ctx context.Context, r *http.Request) (string, error) {
	args := m.Called(ctx, r)
	return args.String(0), args.Error(1)
}

type MockCodeGrantStore struct {
	mock.Mock
}

func (m *MockCodeGrantStore) CreateCode(ctx context.Context, req rfc6749.AuthorizationRequest, subject string) (*AuthorizationCode, error) {
	args := m.Called(ctx, req, subject)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*AuthorizationCode), args.Error(1)
}

func (m *MockCodeGrantStore) ExchangeCode(ctx context.Context, code string, clientID string, redirectURI string) (*AuthorizationCode, error) {
	args := m.Called(ctx, code, clientID, redirectURI)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*AuthorizationCode), args.Error(1)
}

type MockTokenIssuer struct {
	mock.Mock
}

func (m *MockTokenIssuer) IssueToken(ctx context.Context, req rfc6749.TokenRequest, c client.Client) (*rfc6749.TokenResponse, error) {
	args := m.Called(ctx, req, c)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*rfc6749.TokenResponse), args.Error(1)
}

func (m *MockTokenIssuer) RefreshToken(ctx context.Context, req rfc6749.TokenRequest, c client.Client) (*rfc6749.TokenResponse, error) {
	args := m.Called(ctx, req, c)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*rfc6749.TokenResponse), args.Error(1)
}

type MockUserCredentialsValidator struct {
	mock.Mock
}

func (m *MockUserCredentialsValidator) ValidateCredentials(ctx context.Context, username string, password string) (identity.Identity, error) {
	args := m.Called(ctx, username, password)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(identity.Identity), args.Error(1)
}

type MinimalClient struct {
	id string
}

func (c MinimalClient) ClientID() string {
	return c.id
}

func TestAuthorizationCodeGrant(t *testing.T) {
	ctx := client.WithContext(context.Background(), MinimalClient{id: "client1"})
	cl, _ := client.FromContext(ctx)

	t.Run("Missing Code", func(t *testing.T) {
		codeStore := &MockCodeGrantStore{}
		tokenIssuer := &MockTokenIssuer{}
		g := NewAuthorizationCodeGrant(codeStore, tokenIssuer)

		req := rfc6749.TokenRequest{GrantType: "authorization_code"}
		_, err := g.HandleToken(ctx, req)
		requireProtocolError(t, err, rfc6749.ErrInvalidRequest)
	})

	t.Run("Code Exchange Failure", func(t *testing.T) {
		codeStore := &MockCodeGrantStore{}
		tokenIssuer := &MockTokenIssuer{}
		g := NewAuthorizationCodeGrant(codeStore, tokenIssuer)

		req := rfc6749.TokenRequest{
			GrantType: "authorization_code",
			Extra:     map[string]string{"code": "invalid_code"},
		}
		codeStore.On("ExchangeCode", ctx, "invalid_code", "client1", "").Return(nil, errors.New("not found"))

		_, err := g.HandleToken(ctx, req)
		requireProtocolError(t, err, rfc6749.ErrInvalidGrant)
	})

	t.Run("Successful Exchange", func(t *testing.T) {
		codeStore := &MockCodeGrantStore{}
		tokenIssuer := &MockTokenIssuer{}
		g := NewAuthorizationCodeGrant(codeStore, tokenIssuer)

		req := rfc6749.TokenRequest{
			GrantType: "authorization_code",
			Extra: map[string]string{
				"code":         "valid_code",
				"redirect_uri": "https://example.com/cb",
			},
		}
		authCode := &AuthorizationCode{Code: "valid_code"}
		expectedToken := &rfc6749.TokenResponse{AccessToken: "token123", TokenType: "Bearer"}

		codeStore.On("ExchangeCode", ctx, "valid_code", "client1", "https://example.com/cb").Return(authCode, nil)
		tokenIssuer.On("IssueToken", ctx, req, cl).Return(expectedToken, nil)

		resp, err := g.HandleToken(ctx, req)
		assert.NoError(t, err)
		assert.Equal(t, expectedToken, resp)
	})

	t.Run("PKCE Required But Missing Verifier", func(t *testing.T) {
		pkceClient := &client.DefaultClient{ID: "client1", RequirePKCE: true}
		pkceCtx := client.WithContext(context.Background(), pkceClient)

		codeStore := &MockCodeGrantStore{}
		tokenIssuer := &MockTokenIssuer{}
		g := NewAuthorizationCodeGrant(codeStore, tokenIssuer)

		req := rfc6749.TokenRequest{
			GrantType: "authorization_code",
			Extra:     map[string]string{"code": "valid_code"},
		}
		authCode := &AuthorizationCode{Code: "valid_code"}
		codeStore.On("ExchangeCode", pkceCtx, "valid_code", "client1", "").Return(authCode, nil)

		_, err := g.HandleToken(pkceCtx, req)
		requireProtocolError(t, err, rfc6749.ErrInvalidGrant)
	})

	t.Run("PKCE Required With Valid S256 Verifier", func(t *testing.T) {
		pkceClient := &client.DefaultClient{ID: "client1", RequirePKCE: true}
		pkceCtx := client.WithContext(context.Background(), pkceClient)

		codeStore := &MockCodeGrantStore{}
		tokenIssuer := &MockTokenIssuer{}
		g := NewAuthorizationCodeGrant(codeStore, tokenIssuer)

		verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

		req := rfc6749.TokenRequest{
			GrantType: "authorization_code",
			Extra: map[string]string{
				"code":          "valid_code",
				"code_verifier": verifier,
			},
		}
		authCode := &AuthorizationCode{
			Code:                "valid_code",
			CodeChallenge:       challenge,
			CodeChallengeMethod: "S256",
		}
		expectedToken := &rfc6749.TokenResponse{AccessToken: "token_pkce_123", TokenType: "Bearer"}

		codeStore.On("ExchangeCode", pkceCtx, "valid_code", "client1", "").Return(authCode, nil)
		tokenIssuer.On("IssueToken", pkceCtx, req, pkceClient).Return(expectedToken, nil)

		resp, err := g.HandleToken(pkceCtx, req)
		assert.NoError(t, err)
		assert.Equal(t, expectedToken, resp)
	})
}

func TestRefreshTokenGrant(t *testing.T) {
	ctx := client.WithContext(context.Background(), MinimalClient{id: "client1"})
	cl, _ := client.FromContext(ctx)

	t.Run("Missing Refresh Token", func(t *testing.T) {
		tokenIssuer := &MockTokenIssuer{}
		g := NewRefreshTokenGrant(tokenIssuer)

		req := rfc6749.TokenRequest{GrantType: "refresh_token"}
		_, err := g.HandleToken(ctx, req)
		requireProtocolError(t, err, rfc6749.ErrInvalidRequest)
	})

	t.Run("Successful Refresh", func(t *testing.T) {
		tokenIssuer := &MockTokenIssuer{}
		g := NewRefreshTokenGrant(tokenIssuer)

		req := rfc6749.TokenRequest{
			GrantType: "refresh_token",
			Extra:     map[string]string{"refresh_token": "refresh_123"},
		}
		expectedToken := &rfc6749.TokenResponse{AccessToken: "new_token", TokenType: "Bearer"}
		tokenIssuer.On("RefreshToken", ctx, req, cl).Return(expectedToken, nil)

		resp, err := g.HandleToken(ctx, req)
		assert.NoError(t, err)
		assert.Equal(t, expectedToken, resp)
	})
}

func TestClientCredentialsGrant(t *testing.T) {
	ctx := client.WithContext(context.Background(), MinimalClient{id: "client1"})
	cl, _ := client.FromContext(ctx)

	tokenIssuer := &MockTokenIssuer{}
	g := NewClientCredentialsGrant(tokenIssuer)

	req := rfc6749.TokenRequest{GrantType: "client_credentials"}
	expectedToken := &rfc6749.TokenResponse{AccessToken: "cc_token", TokenType: "Bearer"}
	tokenIssuer.On("IssueToken", ctx, req, cl).Return(expectedToken, nil)

	resp, err := g.HandleToken(ctx, req)
	assert.NoError(t, err)
	assert.Equal(t, expectedToken, resp)
}

func TestPasswordGrant(t *testing.T) {
	ctx := client.WithContext(context.Background(), MinimalClient{id: "client1"})
	cl, _ := client.FromContext(ctx)

	t.Run("Missing Credentials", func(t *testing.T) {
		validator := &MockUserCredentialsValidator{}
		tokenIssuer := &MockTokenIssuer{}
		g := NewPasswordGrant(validator, tokenIssuer)

		req := rfc6749.TokenRequest{GrantType: "password"}
		_, err := g.HandleToken(ctx, req)
		requireProtocolError(t, err, rfc6749.ErrInvalidRequest)
	})

	t.Run("Invalid Credentials", func(t *testing.T) {
		validator := &MockUserCredentialsValidator{}
		tokenIssuer := &MockTokenIssuer{}
		g := NewPasswordGrant(validator, tokenIssuer)

		req := rfc6749.TokenRequest{
			GrantType: "password",
			Extra:     map[string]string{"username": "user1", "password": "wrongpassword"},
		}
		validator.On("ValidateCredentials", mock.Anything, "user1", "wrongpassword").Return(nil, errors.New("invalid pass"))

		_, err := g.HandleToken(ctx, req)
		requireProtocolError(t, err, rfc6749.ErrInvalidGrant)
	})

	t.Run("Successful Password Grant", func(t *testing.T) {
		validator := &MockUserCredentialsValidator{}
		tokenIssuer := &MockTokenIssuer{}
		g := NewPasswordGrant(validator, tokenIssuer)

		req := rfc6749.TokenRequest{
			GrantType: "password",
			Extra:     map[string]string{"username": "user1", "password": "pass1"},
		}
		id := identity.SimpleIdentity{Sub: "user_123"}
		validator.On("ValidateCredentials", mock.Anything, "user1", "pass1").Return(id, nil)
		expectedToken := &rfc6749.TokenResponse{AccessToken: "pass_token", TokenType: "Bearer"}
		tokenIssuer.On("IssueToken", mock.Anything, req, cl).Return(expectedToken, nil)

		resp, err := g.HandleToken(ctx, req)
		assert.NoError(t, err)
		assert.Equal(t, expectedToken, resp)
	})
}

func TestAuthorizationCodeGrant_HandleAuthorize(t *testing.T) {
	ctx := identity.WithContext(context.Background(), identity.SimpleIdentity{Sub: "user_123"})
	req := rfc6749.AuthorizationRequest{
		ResponseType: "code",
		ClientID:     "client1",
		RedirectURI:  "https://example.com/cb",
		State:        "state123",
	}

	t.Run("Missing Dependencies", func(t *testing.T) {
		g := NewAuthorizationCodeGrant(nil, nil)
		_, err := g.HandleAuthorize(ctx, req)
		requireProtocolError(t, err, rfc6749.ErrServerError)
	})

	t.Run("Missing Identity in Context", func(t *testing.T) {
		g := NewAuthorizationCodeGrantFull(nil, nil, &MockCodeGrantStore{})
		_, err := g.HandleAuthorize(context.Background(), req)
		requireProtocolError(t, err, rfc6749.ErrAccessDenied)
	})

	t.Run("Successful Code Authorization", func(t *testing.T) {
		codeStore := &MockCodeGrantStore{}
		g := NewAuthorizationCodeGrantFull(nil, nil, codeStore)

		codeStore.On("CreateCode", ctx, req, "user_123").Return(&AuthorizationCode{Code: "auth_code_xyz"}, nil)

		resp, err := g.HandleAuthorize(ctx, req)
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, "auth_code_xyz", resp.Code)
		assert.Equal(t, "state123", resp.State)
	})
}

func TestImplicitGrant_HandleAuthorize(t *testing.T) {
	ctx := identity.WithContext(context.Background(), identity.SimpleIdentity{Sub: "user_123"})
	req := rfc6749.AuthorizationRequest{
		ResponseType: "token",
		ClientID:     "client1",
		RedirectURI:  "https://example.com/cb",
		State:        "state456",
		Scope:        "read write",
	}

	t.Run("Successful Implicit Grant Authorization", func(t *testing.T) {
		tokenIssuer := &MockTokenIssuer{}
		g := NewImplicitGrant(tokenIssuer)

		expectedToken := &rfc6749.TokenResponse{
			AccessToken: "implicit_access_token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			Scope:       "read write",
		}
		tokenIssuer.On("IssueToken", mock.Anything, mock.MatchedBy(func(tr rfc6749.TokenRequest) bool {
			return tr.GrantType == "implicit" && tr.Scope == "read write"
		}), nil).Return(expectedToken, nil)

		resp, err := g.HandleAuthorize(ctx, req)
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.True(t, resp.UseFragment)
		assert.Equal(t, "state456", resp.State)
		assert.Equal(t, "implicit_access_token", resp.Params["access_token"])
		assert.Equal(t, "Bearer", resp.Params["token_type"])
		assert.Equal(t, "3600", resp.Params["expires_in"])
	})
}

func requireProtocolError(t *testing.T, err error, expectedErrorCode string) {
	t.Helper()
	assert.Error(t, err)
	var protoErr rfc6749.ProtocolError
	if assert.ErrorAs(t, err, &protoErr) {
		assert.Equal(t, expectedErrorCode, protoErr.Response.Error)
	}
}

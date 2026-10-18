package grant

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/davfer/gorfc/oauth/client"
	"github.com/davfer/gorfc/oauth/identity"
	"github.com/davfer/gorfc/rfc6749"
	"github.com/davfer/gorfc/rfc7636"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type MockChallenger struct {
	mock.Mock
}

func (m *MockChallenger) Challenge(ctx context.Context, req AuthorizationChallengeRequest) (identity.Identity, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(identity.Identity), args.Error(1)
}

type MockChallengeCodeCreator struct {
	mock.Mock
}

func (m *MockChallengeCodeCreator) CreateChallengeCode(ctx context.Context, req AuthorizationChallengeRequest, subject string) (*AuthorizationCode, error) {
	args := m.Called(ctx, req, subject)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*AuthorizationCode), args.Error(1)
}

func TestFirstPartyAppGrant_HandleChallenge(t *testing.T) {
	ctx := context.Background()

	t.Run("Missing Challenger returns ServerError", func(t *testing.T) {
		g := &FirstPartyAppGrant{}
		req := AuthorizationChallengeRequest{
			ResponseType: rfc6749.ResponseTypeCode,
			ClientID:     "client1",
		}
		_, err := g.HandleChallenge(ctx, req)
		requireProtocolError(t, err, rfc6749.ErrServerError)
	})

	t.Run("Invalid ResponseType returns UnsupportedResponseType", func(t *testing.T) {
		challenger := &MockChallenger{}
		codeCreator := &MockCodeGrantStore{}
		g := NewFirstPartyAppGrant(challenger, codeCreator)

		req := AuthorizationChallengeRequest{
			ResponseType: "token", // Must be "code"
			ClientID:     "client1",
		}
		_, err := g.HandleChallenge(ctx, req)
		requireProtocolError(t, err, rfc6749.ErrUnsupportedResponseType)
	})

	t.Run("Missing ClientID and AuthSession returns InvalidRequest", func(t *testing.T) {
		challenger := &MockChallenger{}
		codeCreator := &MockCodeGrantStore{}
		g := NewFirstPartyAppGrant(challenger, codeCreator)

		req := AuthorizationChallengeRequest{
			ResponseType: rfc6749.ResponseTypeCode,
		}
		_, err := g.HandleChallenge(ctx, req)
		requireProtocolError(t, err, rfc6749.ErrInvalidRequest)
	})

	t.Run("ClientID mismatch with authenticated Client returns InvalidClient", func(t *testing.T) {
		challenger := &MockChallenger{}
		codeCreator := &MockCodeGrantStore{}
		g := NewFirstPartyAppGrant(challenger, codeCreator)

		clientCtx := client.WithContext(ctx, MinimalClient{id: "client-authenticated"})
		req := AuthorizationChallengeRequest{
			ResponseType: rfc6749.ResponseTypeCode,
			ClientID:     "client-different",
		}
		_, err := g.HandleChallenge(clientCtx, req)
		requireProtocolError(t, err, rfc6749.ErrInvalidClient)
	})

	t.Run("Invalid Scope returns InvalidScope", func(t *testing.T) {
		challenger := &MockChallenger{}
		codeCreator := &MockCodeGrantStore{}
		g := NewFirstPartyAppGrant(challenger, codeCreator)

		req := AuthorizationChallengeRequest{
			ResponseType: rfc6749.ResponseTypeCode,
			ClientID:     "client1",
			Scope:        "invalid\"scope",
		}
		_, err := g.HandleChallenge(ctx, req)
		requireProtocolError(t, err, rfc6749.ErrInvalidScope)
	})

	t.Run("Invalid PKCE CodeChallenge returns InvalidRequest", func(t *testing.T) {
		challenger := &MockChallenger{}
		codeCreator := &MockCodeGrantStore{}
		g := NewFirstPartyAppGrant(challenger, codeCreator)

		req := AuthorizationChallengeRequest{
			ResponseType:  rfc6749.ResponseTypeCode,
			ClientID:      "client1",
			CodeChallenge: "invalid challenge with spaces",
		}
		_, err := g.HandleChallenge(ctx, req)
		requireProtocolError(t, err, rfc6749.ErrInvalidRequest)
	})

	t.Run("Invalid PKCE CodeChallengeMethod returns InvalidRequest", func(t *testing.T) {
		challenger := &MockChallenger{}
		codeCreator := &MockCodeGrantStore{}
		g := NewFirstPartyAppGrant(challenger, codeCreator)

		req := AuthorizationChallengeRequest{
			ResponseType:        rfc6749.ResponseTypeCode,
			ClientID:            "client1",
			CodeChallenge:       "E9Melhoa2OwvFrGMTJguCH5rtx642N-wp9P94Bi27e8",
			CodeChallengeMethod: "MD5", // unsupported
		}
		_, err := g.HandleChallenge(ctx, req)
		requireProtocolError(t, err, rfc6749.ErrInvalidRequest)
	})

	t.Run("Challenger requires additional factor - does not proceed", func(t *testing.T) {
		challenger := &MockChallenger{}
		codeCreator := &MockCodeGrantStore{}
		g := NewFirstPartyAppGrant(challenger, codeCreator)

		req := AuthorizationChallengeRequest{
			ResponseType: rfc6749.ResponseTypeCode,
			ClientID:     "client1",
			AuthSession:  "session-123",
		}

		challengeErr := AuthorizationChallengeError{
			ErrorCode:        ErrInsufficientAuthorization,
			ErrorDescription: "One-time password required",
			AuthSession:      "session-123",
			Parameters:       map[string]any{"otp_required": true},
		}

		challenger.On("Challenge", ctx, req).Return(nil, challengeErr)

		resp, err := g.HandleChallenge(ctx, req)
		assert.Nil(t, resp)
		require.Error(t, err)

		var authChallengeErr AuthorizationChallengeError
		require.True(t, errors.As(err, &authChallengeErr))
		assert.Equal(t, ErrInsufficientAuthorization, authChallengeErr.ErrorCode)
		assert.Equal(t, "One-time password required", authChallengeErr.ErrorDescription)
		assert.Equal(t, "session-123", authChallengeErr.AuthSession)
		assert.Equal(t, true, authChallengeErr.Parameters["otp_required"])
		assert.Equal(t, http.StatusForbidden, authChallengeErr.StatusCode())

		// Verify CodeCreator was NEVER called!
		codeCreator.AssertNotCalled(t, "CreateCode", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("Challenger redirects to web - does not proceed", func(t *testing.T) {
		challenger := &MockChallenger{}
		codeCreator := &MockCodeGrantStore{}
		g := NewFirstPartyAppGrant(challenger, codeCreator)

		req := AuthorizationChallengeRequest{
			ResponseType: rfc6749.ResponseTypeCode,
			ClientID:     "client1",
			AuthSession:  "session-abc",
		}

		redirectErr := AuthorizationChallengeError{
			ErrorCode:  ErrRedirectToWeb,
			RequestURI: "urn:ietf:params:oauth:request_uri:12345",
			ExpiresIn:  600,
		}

		challenger.On("Challenge", ctx, req).Return(nil, redirectErr)

		resp, err := g.HandleChallenge(ctx, req)
		assert.Nil(t, resp)
		require.Error(t, err)

		var authChallengeErr AuthorizationChallengeError
		require.True(t, errors.As(err, &authChallengeErr))
		assert.Equal(t, ErrRedirectToWeb, authChallengeErr.ErrorCode)
		assert.Equal(t, "urn:ietf:params:oauth:request_uri:12345", authChallengeErr.RequestURI)
		assert.Equal(t, int64(600), authChallengeErr.ExpiresIn)
		assert.Equal(t, http.StatusForbidden, authChallengeErr.StatusCode())

		codeCreator.AssertNotCalled(t, "CreateCode", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("Challenger succeeds and returns Identity - proceeds to issue code", func(t *testing.T) {
		challenger := &MockChallenger{}
		codeCreator := &MockCodeGrantStore{}
		g := NewFirstPartyAppGrant(challenger, codeCreator)

		req := AuthorizationChallengeRequest{
			ResponseType:        rfc6749.ResponseTypeCode,
			ClientID:            "client1",
			Scope:               "openid profile",
			AuthSession:         "session-finished",
			CodeChallenge:       "E9Melhoa2OwvFrGMTJguCH5rtx642N-wp9P94Bi27e8",
			CodeChallengeMethod: "S256",
			State:               "state-xyz",
		}

		id := identity.SimpleIdentity{Sub: "user-1234"}
		challenger.On("Challenge", ctx, req).Return(id, nil)

		expectedAuthReq := rfc6749.AuthorizationRequest{
			ResponseType: rfc6749.ResponseTypeCode,
			ClientID:     "client1",
			Scope:        "openid profile",
			State:        "state-xyz",
		}
		expectedCode := &AuthorizationCode{
			Code:                "code-xyz-987",
			ClientID:            "client1",
			Subject:             "user-1234",
			CodeChallenge:       req.CodeChallenge,
			CodeChallengeMethod: req.CodeChallengeMethod,
		}
		codeCreator.On("CreateCode", ctx, expectedAuthReq, "user-1234").Return(expectedCode, nil)

		resp, err := g.HandleChallenge(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, "code-xyz-987", resp.AuthorizationCode)
		assert.Equal(t, "session-finished", resp.AuthSession)
	})

	t.Run("Challenger succeeds with dedicated ChallengeCodeCreator", func(t *testing.T) {
		challenger := &MockChallenger{}
		challengeCodeCreator := &MockChallengeCodeCreator{}
		g := NewFirstPartyAppGrantWithChallengeCreator(challenger, challengeCodeCreator)

		req := AuthorizationChallengeRequest{
			ResponseType: rfc6749.ResponseTypeCode,
			ClientID:     "client1",
			AuthSession:  "session-dedicated",
		}

		id := identity.SimpleIdentity{Sub: "user-special"}
		challenger.On("Challenge", ctx, req).Return(id, nil)

		expectedCode := &AuthorizationCode{
			Code:     "code-dedicated-123",
			ClientID: "client1",
			Subject:  "user-special",
		}
		challengeCodeCreator.On("CreateChallengeCode", ctx, req, "user-special").Return(expectedCode, nil)

		resp, err := g.HandleChallenge(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, "code-dedicated-123", resp.AuthorizationCode)
		assert.Equal(t, "session-dedicated", resp.AuthSession)
	})

	t.Run("SimpleChallengerFunc adapter with Identity in context", func(t *testing.T) {
		codeCreator := &MockCodeGrantStore{}
		fn := func(ctx context.Context, req AuthorizationChallengeRequest) error {
			if req.Get("otp") != "123456" {
				return AuthorizationChallengeError{
					ErrorCode: ErrInsufficientAuthorization,
				}
			}
			return nil
		}
		g := NewFirstPartyAppGrant(SimpleChallengerFunc(fn), codeCreator)

		req := AuthorizationChallengeRequest{
			ResponseType: rfc6749.ResponseTypeCode,
			ClientID:     "client1",
			Extra:        map[string]string{"otp": "123456"},
		}

		ctxWithUser := identity.WithContext(ctx, identity.SimpleIdentity{Sub: "user-from-context"})

		expectedAuthReq := rfc6749.AuthorizationRequest{
			ResponseType: rfc6749.ResponseTypeCode,
			ClientID:     "client1",
		}
		expectedCode := &AuthorizationCode{
			Code:     "code-from-ctx",
			ClientID: "client1",
			Subject:  "user-from-context",
		}
		codeCreator.On("CreateCode", ctxWithUser, expectedAuthReq, "user-from-context").Return(expectedCode, nil)

		resp, err := g.HandleChallenge(ctxWithUser, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, "code-from-ctx", resp.AuthorizationCode)
	})
}

func TestFirstPartyAppGrant_HandleToken(t *testing.T) {
	ctx := client.WithContext(context.Background(), MinimalClient{id: "client1"})
	cl, _ := client.FromContext(ctx)

	t.Run("Missing Code", func(t *testing.T) {
		codeStore := &MockCodeGrantStore{}
		tokenIssuer := &MockTokenIssuer{}
		challenger := &MockChallenger{}
		g := NewFirstPartyAppGrantFull(challenger, codeStore, codeStore, tokenIssuer)

		req := rfc6749.TokenRequest{GrantType: "authorization_code"}
		_, err := g.HandleToken(ctx, req)
		requireProtocolError(t, err, rfc6749.ErrInvalidRequest)
	})

	t.Run("Valid Token Request without redirect_uri", func(t *testing.T) {
		codeStore := &MockCodeGrantStore{}
		tokenIssuer := &MockTokenIssuer{}
		challenger := &MockChallenger{}
		g := NewFirstPartyAppGrantFull(challenger, codeStore, codeStore, tokenIssuer)

		authCode := &AuthorizationCode{
			Code:      "valid-code",
			ClientID:  "client1",
			Subject:   "user-123",
			ExpiresAt: 9999999999,
		}
		// In First-Party App flow, redirect_uri is empty
		codeStore.On("ExchangeCode", ctx, "valid-code", "client1", "").Return(authCode, nil)

		tokenReq := rfc6749.TokenRequest{
			GrantType: "authorization_code",
			Extra: map[string]string{
				"code": "valid-code",
			},
		}

		expectedCtx := identity.WithContext(ctx, identity.SimpleIdentity{Sub: "user-123"})
		tokenResp := &rfc6749.TokenResponse{
			AccessToken: "access-token-123",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			AuthSession: "session-abc",
		}
		tokenIssuer.On("IssueToken", expectedCtx, tokenReq, cl).Return(tokenResp, nil)

		resp, err := g.HandleToken(ctx, tokenReq)
		require.NoError(t, err)
		assert.Equal(t, "access-token-123", resp.AccessToken)
		assert.Equal(t, "session-abc", resp.AuthSession)
	})

	t.Run("Valid Token Request with PKCE", func(t *testing.T) {
		codeStore := &MockCodeGrantStore{}
		tokenIssuer := &MockTokenIssuer{}
		challenger := &MockChallenger{}
		g := NewFirstPartyAppGrantFull(challenger, codeStore, codeStore, tokenIssuer)

		verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		challenge, err := rfc7636.ComputeCodeChallenge(verifier, rfc7636.CodeChallengeMethodS256)
		require.NoError(t, err)

		authCode := &AuthorizationCode{
			Code:                "pkce-code",
			ClientID:            "client1",
			Subject:             "user-pkce",
			CodeChallenge:       challenge,
			CodeChallengeMethod: rfc7636.CodeChallengeMethodS256,
		}
		codeStore.On("ExchangeCode", ctx, "pkce-code", "client1", "").Return(authCode, nil)

		tokenReq := rfc6749.TokenRequest{
			GrantType: "authorization_code",
			Extra: map[string]string{
				"code":          "pkce-code",
				"code_verifier": verifier,
			},
		}

		expectedCtx := identity.WithContext(ctx, identity.SimpleIdentity{Sub: "user-pkce"})
		tokenResp := &rfc6749.TokenResponse{
			AccessToken: "pkce-token",
			TokenType:   "Bearer",
		}
		tokenIssuer.On("IssueToken", expectedCtx, tokenReq, cl).Return(tokenResp, nil)

		resp, err := g.HandleToken(ctx, tokenReq)
		require.NoError(t, err)
		assert.Equal(t, "pkce-token", resp.AccessToken)
	})
}

func TestFirstPartyAppGrant_ServeHTTP(t *testing.T) {
	challenger := &MockChallenger{}
	codeCreator := &MockCodeGrantStore{}
	g := NewFirstPartyAppGrant(challenger, codeCreator)

	t.Run("Non-POST request returns error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/authorize-challenge", nil)
		rec := httptest.NewRecorder()

		g.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		var errResp rfc6749.ErrorResponse
		err := json.NewDecoder(rec.Body).Decode(&errResp)
		require.NoError(t, err)
		assert.Equal(t, rfc6749.ErrInvalidRequest, errResp.Error)
	})

	t.Run("Challenge returns insufficient_authorization with 403 Forbidden", func(t *testing.T) {
		form := url.Values{}
		form.Set("client_id", "my-app")
		form.Set("response_type", "code")
		form.Set("username", "alice")

		httpReq := httptest.NewRequest(http.MethodPost, "/authorize-challenge", strings.NewReader(form.Encode()))
		httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		expectedReq := AuthorizationChallengeRequest{
			ClientID:     "my-app",
			ResponseType: "code",
			Extra:        map[string]string{"username": "alice", "client_id": "my-app", "response_type": "code"},
		}

		challenger.On("Challenge", mock.Anything, expectedReq).Return(nil, AuthorizationChallengeError{
			ErrorCode:        ErrInsufficientAuthorization,
			ErrorDescription: "Enter passkey",
			AuthSession:      "auth-sess-1",
			Parameters:       map[string]any{"challenge": "webauthn-xyz"},
		})

		g.ServeHTTP(rec, httpReq)

		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
		assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

		var raw map[string]any
		err := json.NewDecoder(rec.Body).Decode(&raw)
		require.NoError(t, err)
		assert.Equal(t, ErrInsufficientAuthorization, raw["error"])
		assert.Equal(t, "Enter passkey", raw["error_description"])
		assert.Equal(t, "auth-sess-1", raw["auth_session"])
		assert.Equal(t, "webauthn-xyz", raw["challenge"])
	})

	t.Run("Challenge succeeds with 200 OK and authorization_code", func(t *testing.T) {
		form := url.Values{}
		form.Set("client_id", "my-app")
		form.Set("response_type", "code")
		form.Set("auth_session", "auth-sess-1")
		form.Set("passkey_signature", "sig-123")

		httpReq := httptest.NewRequest(http.MethodPost, "/authorize-challenge", strings.NewReader(form.Encode()))
		httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		expectedReq := AuthorizationChallengeRequest{
			ClientID:     "my-app",
			ResponseType: "code",
			AuthSession:  "auth-sess-1",
			Extra: map[string]string{
				"client_id":         "my-app",
				"response_type":     "code",
				"auth_session":      "auth-sess-1",
				"passkey_signature": "sig-123",
			},
		}

		id := identity.SimpleIdentity{Sub: "alice-id"}
		challenger.On("Challenge", mock.Anything, expectedReq).Return(id, nil)

		expectedAuthReq := rfc6749.AuthorizationRequest{
			ResponseType: "code",
			ClientID:     "my-app",
		}
		expectedCode := &AuthorizationCode{
			Code:     "auth-code-alice",
			ClientID: "my-app",
			Subject:  "alice-id",
		}
		codeCreator.On("CreateCode", mock.Anything, expectedAuthReq, "alice-id").Return(expectedCode, nil)

		g.ServeHTTP(rec, httpReq)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
		assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

		var resp AuthorizationChallengeResponse
		err := json.NewDecoder(rec.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "auth-code-alice", resp.AuthorizationCode)
		assert.Equal(t, "auth-sess-1", resp.AuthSession)
	})
}

func TestGenerateAuthSession(t *testing.T) {
	sess1, err := GenerateAuthSession()
	require.NoError(t, err)
	assert.NotEmpty(t, sess1)

	sess2, err := GenerateAuthSession()
	require.NoError(t, err)
	assert.NotEmpty(t, sess2)
	assert.NotEqual(t, sess1, sess2)
}

func TestAuthorizationChallengeError_JSON(t *testing.T) {
	orig := AuthorizationChallengeError{
		ErrorCode:        ErrInsufficientAuthorization,
		ErrorDescription: "MFA required",
		AuthSession:      "sess-123",
		Parameters: map[string]any{
			"otp_required": true,
		},
	}

	data, err := json.Marshal(orig)
	require.NoError(t, err)

	var unmarshaled AuthorizationChallengeError
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, orig.ErrorCode, unmarshaled.ErrorCode)
	assert.Equal(t, orig.ErrorDescription, unmarshaled.ErrorDescription)
	assert.Equal(t, orig.AuthSession, unmarshaled.AuthSession)
	assert.Equal(t, true, unmarshaled.Parameters["otp_required"])
}

func TestAuthorizationChallengeResponse_JSON(t *testing.T) {
	orig := AuthorizationChallengeResponse{
		AuthorizationCode: "code-123",
		AuthSession:       "sess-456",
		Parameters: map[string]any{
			"custom_info": "value",
		},
	}

	data, err := json.Marshal(orig)
	require.NoError(t, err)

	var unmarshaled AuthorizationChallengeResponse
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, orig.AuthorizationCode, unmarshaled.AuthorizationCode)
	assert.Equal(t, orig.AuthSession, unmarshaled.AuthSession)
	assert.Equal(t, "value", unmarshaled.Parameters["custom_info"])
}

func TestAuthorizationChallengeRequest_Unmarshal(t *testing.T) {
	req := AuthorizationChallengeRequest{
		ClientID:     "client1",
		ResponseType: "code",
		Scope:        "openid",
		AuthSession:  "session-1",
		Extra: map[string]string{
			"username": "user1",
		},
	}

	type Target struct {
		ClientID     string `json:"client_id"`
		ResponseType string `json:"response_type"`
		Scope        string `json:"scope"`
		AuthSession  string `json:"auth_session"`
		Username     string `json:"username"`
	}

	var target Target
	err := req.Unmarshal(&target)
	require.NoError(t, err)
	assert.Equal(t, "client1", target.ClientID)
	assert.Equal(t, "code", target.ResponseType)
	assert.Equal(t, "openid", target.Scope)
	assert.Equal(t, "session-1", target.AuthSession)
	assert.Equal(t, "user1", target.Username)
}

package token_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/davfer/gorfc/oauth/client"
	"github.com/davfer/gorfc/oauth/grant"
	"github.com/davfer/gorfc/oauth/token"
	"github.com/davfer/gorfc/rfc6749"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockClientAuthenticator struct {
	mock.Mock
}

func (m *MockClientAuthenticator) AuthenticateClient(ctx context.Context, r *http.Request) (client.Client, error) {
	args := m.Called(ctx, r)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(client.Client), args.Error(1)
}

type MockCodeGrantStore struct {
	mock.Mock
}

func (m *MockCodeGrantStore) ExchangeCode(ctx context.Context, code string, clientID string, redirectURI string) (*grant.AuthorizationCode, error) {
	args := m.Called(ctx, code, clientID, redirectURI)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*grant.AuthorizationCode), args.Error(1)
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

type MockErrorHandler struct {
	mock.Mock
}

func (m *MockErrorHandler) WriteTokenError(w http.ResponseWriter, r *http.Request, errResp rfc6749.ErrorResponse) {
	m.Called(w, r, errResp)
	w.WriteHeader(http.StatusBadRequest)
}

func TestTokenHandler_ServeHTTP(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		contentType    string
		formData       url.Values
		setupMocks     func(*MockClientAuthenticator, *MockCodeGrantStore, *MockTokenIssuer, *MockErrorHandler)
		expectedStatus int
	}{
		{
			name:           "Method Not Allowed",
			method:         http.MethodGet,
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:        "Invalid Content Type",
			method:      http.MethodPost,
			contentType: "application/json",
			setupMocks: func(a *MockClientAuthenticator, c *MockCodeGrantStore, i *MockTokenIssuer, e *MockErrorHandler) {
				e.On("WriteTokenError", mock.Anything, mock.Anything, mock.MatchedBy(func(r rfc6749.ErrorResponse) bool {
					return r.Error == rfc6749.ErrInvalidRequest
				})).Return()
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:        "Unsupported Grant Type",
			method:      http.MethodPost,
			contentType: token.ContentTypeFormUrlEncoded,
			formData: url.Values{
				"grant_type": {"unknown_grant"},
			},
			setupMocks: func(a *MockClientAuthenticator, c *MockCodeGrantStore, i *MockTokenIssuer, e *MockErrorHandler) {
				a.On("AuthenticateClient", mock.Anything, mock.Anything).Return(&client.DefaultClient{ID: "client1"}, nil)
				e.On("WriteTokenError", mock.Anything, mock.Anything, mock.MatchedBy(func(r rfc6749.ErrorResponse) bool {
					return r.Error == rfc6749.ErrUnsupportedGrantType
				})).Return()
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:        "Client Authentication Failed",
			method:      http.MethodPost,
			contentType: token.ContentTypeFormUrlEncoded,
			formData: url.Values{
				"grant_type": {"authorization_code"},
			},
			setupMocks: func(a *MockClientAuthenticator, c *MockCodeGrantStore, i *MockTokenIssuer, e *MockErrorHandler) {
				a.On("AuthenticateClient", mock.Anything, mock.Anything).Return(nil, errors.New("auth failed"))
				e.On("WriteTokenError", mock.Anything, mock.Anything, mock.MatchedBy(func(r rfc6749.ErrorResponse) bool {
					return r.Error == rfc6749.ErrInvalidClient
				})).Return()
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:        "Unauthorized Grant Type for Client",
			method:      http.MethodPost,
			contentType: token.ContentTypeFormUrlEncoded,
			formData: url.Values{
				"grant_type": {"password"},
			},
			setupMocks: func(a *MockClientAuthenticator, c *MockCodeGrantStore, i *MockTokenIssuer, e *MockErrorHandler) {
				a.On("AuthenticateClient", mock.Anything, mock.Anything).Return(&client.DefaultClient{
					ID:                "client1",
					AllowedGrantTypes: []string{"authorization_code"}, // Not password
				}, nil)
				e.On("WriteTokenError", mock.Anything, mock.Anything, mock.MatchedBy(func(r rfc6749.ErrorResponse) bool {
					return r.Error == rfc6749.ErrUnauthorizedClient
				})).Return()
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:        "Invalid Authorization Code",
			method:      http.MethodPost,
			contentType: token.ContentTypeFormUrlEncoded,
			formData: url.Values{
				"grant_type": {"authorization_code"},
				"code":       {"invalid_code"},
			},
			setupMocks: func(a *MockClientAuthenticator, c *MockCodeGrantStore, i *MockTokenIssuer, e *MockErrorHandler) {
				cl := &client.DefaultClient{ID: "client1", AllowedGrantTypes: []string{"authorization_code"}}
				a.On("AuthenticateClient", mock.Anything, mock.Anything).Return(cl, nil)
				c.On("ExchangeCode", mock.Anything, "invalid_code", "client1", "").Return(nil, errors.New("invalid code"))
				e.On("WriteTokenError", mock.Anything, mock.Anything, mock.MatchedBy(func(r rfc6749.ErrorResponse) bool {
					return r.Error == rfc6749.ErrInvalidGrant
				})).Return()
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:        "Successful Token Issuance",
			method:      http.MethodPost,
			contentType: token.ContentTypeFormUrlEncoded,
			formData: url.Values{
				"grant_type":   {"authorization_code"},
				"code":         {"valid_code"},
				"redirect_uri": {"https://example.com/cb"},
			},
			setupMocks: func(a *MockClientAuthenticator, c *MockCodeGrantStore, i *MockTokenIssuer, e *MockErrorHandler) {
				cl := &client.DefaultClient{ID: "client1", AllowedGrantTypes: []string{"authorization_code"}}
				code := &grant.AuthorizationCode{Code: "valid_code"}

				a.On("AuthenticateClient", mock.Anything, mock.Anything).Return(cl, nil)
				c.On("ExchangeCode", mock.Anything, "valid_code", "client1", "https://example.com/cb").Return(code, nil)

				i.On("IssueToken", mock.Anything, mock.Anything, cl).Return(&rfc6749.TokenResponse{
					AccessToken: "access_token_123",
					TokenType:   "Bearer",
					ExpiresIn:   3600,
				}, nil)
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientAuth := &MockClientAuthenticator{}
			codeStore := &MockCodeGrantStore{}
			tokenIssuer := &MockTokenIssuer{}
			errHandler := &MockErrorHandler{}

			if tt.setupMocks != nil {
				tt.setupMocks(clientAuth, codeStore, tokenIssuer, errHandler)
			}

			handlers := map[string]token.GrantHandler{
				rfc6749.GrantTypeAuthorizationCode: token.GrantHandlerFunc(func(ctx context.Context, req rfc6749.TokenRequest) (*rfc6749.TokenResponse, error) {
					c, _ := client.FromContext(ctx)
					code := req.Get("code")
					if code == "" || !rfc6749.IsValidCode(code) {
						return nil, rfc6749.ProtocolError{Response: rfc6749.ErrorResponse{Error: rfc6749.ErrInvalidRequest}}
					}
					authCode, err := codeStore.ExchangeCode(ctx, code, c.ClientID(), req.Get("redirect_uri"))
					if err != nil || authCode == nil {
						return nil, rfc6749.ProtocolError{Response: rfc6749.ErrorResponse{Error: rfc6749.ErrInvalidGrant}}
					}
					return tokenIssuer.IssueToken(ctx, req, c)
				}),
				rfc6749.GrantTypeRefreshToken: token.GrantHandlerFunc(func(ctx context.Context, req rfc6749.TokenRequest) (*rfc6749.TokenResponse, error) {
					c, _ := client.FromContext(ctx)
					refreshToken := req.Get("refresh_token")
					if refreshToken == "" {
						return nil, rfc6749.ProtocolError{Response: rfc6749.ErrorResponse{Error: rfc6749.ErrInvalidRequest}}
					}
					return tokenIssuer.RefreshToken(ctx, req, c)
				}),
			}

			handler := token.NewTokenHandler(clientAuth, errHandler, handlers)

			var req *http.Request
			if tt.formData != nil {
				req = httptest.NewRequest(tt.method, "/token", strings.NewReader(tt.formData.Encode()))
			} else {
				req = httptest.NewRequest(tt.method, "/token", nil)
			}

			if tt.contentType != "" {
				req.Header.Set(token.HeaderContentType, tt.contentType)
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if w.Code == http.StatusOK {
				assert.Equal(t, token.ContentTypeJSON, w.Header().Get(token.HeaderContentType))
				assert.Equal(t, token.CacheControlNoStore, w.Header().Get(token.HeaderCacheControl))
				assert.Equal(t, token.PragmaNoCache, w.Header().Get(token.HeaderPragma))
			}

			clientAuth.AssertExpectations(t)
			codeStore.AssertExpectations(t)
			tokenIssuer.AssertExpectations(t)
			errHandler.AssertExpectations(t)
		})
	}
}

func TestTokenHandler_CustomGrantAndExtraParams(t *testing.T) {
	clientAuth := &MockClientAuthenticator{}
	errHandler := &MockErrorHandler{}

	var receivedReq rfc6749.TokenRequest
	var receivedClient client.Client

	customHandler := func(ctx context.Context, req rfc6749.TokenRequest) (*rfc6749.TokenResponse, error) {
		receivedReq = req
		c, ok := client.FromContext(ctx)
		if ok {
			receivedClient = c
		}
		return &rfc6749.TokenResponse{
			AccessToken: "custom_access_token",
			TokenType:   "Bearer",
		}, nil
	}

	handler := token.NewTokenHandler(clientAuth, errHandler, map[string]token.GrantHandler{
		"urn:ietf:params:oauth:grant-type:custom": token.GrantHandlerFunc(customHandler),
	})

	clientAuth.On("AuthenticateClient", mock.Anything, mock.Anything).Return(&client.DefaultClient{ID: "client1"}, nil)

	formData := url.Values{
		"grant_type":    {"urn:ietf:params:oauth:grant-type:custom"},
		"custom_param":  {"custom_value_123"},
		"code_verifier": {"verifier_xyz"},
	}

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(formData.Encode()))
	req.Header.Set(token.HeaderContentType, token.ContentTypeFormUrlEncoded)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "urn:ietf:params:oauth:grant-type:custom", receivedReq.GrantType)
	assert.Equal(t, "custom_value_123", receivedReq.Get("custom_param"))
	assert.Equal(t, "verifier_xyz", receivedReq.Get("code_verifier"))
	assert.NotNil(t, receivedClient)
	assert.Equal(t, "client1", receivedClient.ClientID())
}

func TestTokenService_HandleToken(t *testing.T) {
	t.Run("nil client returns invalid_client error", func(t *testing.T) {
		svc := token.NewTokenService(nil)
		resp, err := svc.HandleToken(context.Background(), nil, rfc6749.TokenRequest{
			GrantType: "authorization_code",
		})
		assert.Nil(t, resp)
		assert.Error(t, err)
		var protoErr rfc6749.ProtocolError
		assert.True(t, errors.As(err, &protoErr))
		assert.Equal(t, rfc6749.ErrInvalidClient, protoErr.Response.Error)
	})

	t.Run("unsupported grant type returns error", func(t *testing.T) {
		svc := token.NewTokenService(nil)
		cl := &client.DefaultClient{ID: "client-1", AllowedGrantTypes: []string{"password"}}
		resp, err := svc.HandleToken(context.Background(), cl, rfc6749.TokenRequest{
			GrantType: "authorization_code",
		})
		assert.Nil(t, resp)
		assert.Error(t, err)
		var protoErr rfc6749.ProtocolError
		assert.True(t, errors.As(err, &protoErr))
		assert.Equal(t, rfc6749.ErrUnauthorizedClient, protoErr.Response.Error)
	})

	t.Run("unregistered grant type handler returns unsupported_grant_type", func(t *testing.T) {
		svc := token.NewTokenService(nil)
		cl := &client.DefaultClient{ID: "client-1", AllowedGrantTypes: []string{"authorization_code"}}
		resp, err := svc.HandleToken(context.Background(), cl, rfc6749.TokenRequest{
			GrantType: "authorization_code",
		})
		assert.Nil(t, resp)
		assert.Error(t, err)
		var protoErr rfc6749.ProtocolError
		assert.True(t, errors.As(err, &protoErr))
		assert.Equal(t, rfc6749.ErrUnsupportedGrantType, protoErr.Response.Error)
	})

	t.Run("successful execution passes client in context and returns token", func(t *testing.T) {
		var ctxClient client.Client
		mockHandler := token.GrantHandlerFunc(func(ctx context.Context, req rfc6749.TokenRequest) (*rfc6749.TokenResponse, error) {
			ctxClient, _ = client.FromContext(ctx)
			return &rfc6749.TokenResponse{
				AccessToken: "token_abc",
				TokenType:   "Bearer",
				ExpiresIn:   3600,
			}, nil
		})

		svc := token.NewTokenService(nil)
		svc.RegisterGrantHandler("authorization_code", mockHandler)

		cl := &client.DefaultClient{ID: "client-1", AllowedGrantTypes: []string{"authorization_code"}}
		resp, err := svc.HandleToken(context.Background(), cl, rfc6749.TokenRequest{
			GrantType: "authorization_code",
		})
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, "token_abc", resp.AccessToken)
		assert.Equal(t, "Bearer", resp.TokenType)
		assert.NotNil(t, ctxClient)
		assert.Equal(t, "client-1", ctxClient.ClientID())
	})
}

package authorize_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/davfer/gorfc/oauth/authorize"
	"github.com/davfer/gorfc/oauth/client"
	"github.com/davfer/gorfc/oauth/identity"
	"github.com/davfer/gorfc/rfc6749"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mocks

type MockClientStore struct {
	mock.Mock
}

func (m *MockClientStore) GetClient(ctx context.Context, clientID string) (client.Client, error) {
	args := m.Called(ctx, clientID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(client.Client), args.Error(1)
}

type MockUserConsentDecider struct {
	mock.Mock
}

func (m *MockUserConsentDecider) AuthenticateUser(ctx context.Context, r *http.Request) (identity.Identity, error) {
	args := m.Called(ctx, r)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(identity.Identity), args.Error(1)
}

type MockCodeGrantStore struct {
	mock.Mock
}

func (m *MockCodeGrantStore) CreateCode(ctx context.Context, req rfc6749.AuthorizationRequest, subject string) (string, error) {
	args := m.Called(ctx, req, subject)
	return args.String(0), args.Error(1)
}

type MockErrorHandler struct {
	mock.Mock
}

func (m *MockErrorHandler) WriteAuthorizationError(w http.ResponseWriter, r *http.Request, redirectURI string, errResp rfc6749.ErrorResponse) {
	m.Called(w, r, redirectURI, errResp)
	w.WriteHeader(http.StatusBadRequest)
}

func TestAuthorizeHandler_ServeHTTP(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		queryParams    map[string]string
		setupMocks     func(*MockClientStore, *MockUserConsentDecider, *MockCodeGrantStore, *MockErrorHandler)
		expectedStatus int
		expectedHeader map[string]string
	}{
		{
			name:           "Method Not Allowed",
			method:         http.MethodPut,
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:   "Missing Client ID",
			method: http.MethodGet,
			queryParams: map[string]string{
				"response_type": "code",
			},
			setupMocks: func(c *MockClientStore, u *MockUserConsentDecider, g *MockCodeGrantStore, e *MockErrorHandler) {
				e.On("WriteAuthorizationError", mock.Anything, mock.Anything, "", mock.MatchedBy(func(r rfc6749.ErrorResponse) bool {
					return r.Error == rfc6749.ErrInvalidRequest
				})).Return()
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "Client Not Found",
			method: http.MethodGet,
			queryParams: map[string]string{
				"response_type": "code",
				"client_id":     "unknown",
				"redirect_uri":  "https://example.com/cb",
			},
			setupMocks: func(c *MockClientStore, u *MockUserConsentDecider, g *MockCodeGrantStore, e *MockErrorHandler) {
				c.On("GetClient", mock.Anything, "unknown").Return(nil, errors.New("not found"))
				e.On("WriteAuthorizationError", mock.Anything, mock.Anything, "https://example.com/cb", mock.MatchedBy(func(r rfc6749.ErrorResponse) bool {
					return r.Error == rfc6749.ErrUnauthorizedClient
				})).Return()
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "Invalid Redirect URI",
			method: http.MethodGet,
			queryParams: map[string]string{
				"response_type": "code",
				"client_id":     "client1",
				"redirect_uri":  "https://evil.com/cb",
			},
			setupMocks: func(c *MockClientStore, u *MockUserConsentDecider, g *MockCodeGrantStore, e *MockErrorHandler) {
				c.On("GetClient", mock.Anything, "client1").Return(&client.DefaultClient{
					ID:                  "client1",
					AllowedRedirectURIs: []string{"https://example.com/cb"},
				}, nil)
				e.On("WriteAuthorizationError", mock.Anything, mock.Anything, "", mock.MatchedBy(func(r rfc6749.ErrorResponse) bool {
					return r.Error == rfc6749.ErrInvalidRequest
				})).Return()
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "Unsupported Response Type",
			method: http.MethodGet,
			queryParams: map[string]string{
				"response_type": "token",
				"client_id":     "client1",
				"redirect_uri":  "https://example.com/cb",
			},
			setupMocks: func(c *MockClientStore, u *MockUserConsentDecider, g *MockCodeGrantStore, e *MockErrorHandler) {
				c.On("GetClient", mock.Anything, "client1").Return(&client.DefaultClient{
					ID:                  "client1",
					AllowedRedirectURIs: []string{"https://example.com/cb"},
				}, nil)
				u.On("AuthenticateUser", mock.Anything, mock.Anything).Return(identity.SimpleIdentity{Sub: "user123"}, nil)
				e.On("WriteAuthorizationError", mock.Anything, mock.Anything, "https://example.com/cb", mock.MatchedBy(func(r rfc6749.ErrorResponse) bool {
					return r.Error == rfc6749.ErrUnsupportedResponseType
				})).Return()
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "Access Denied by User",
			method: http.MethodGet,
			queryParams: map[string]string{
				"response_type": "code",
				"client_id":     "client1",
				"redirect_uri":  "https://example.com/cb",
			},
			setupMocks: func(c *MockClientStore, u *MockUserConsentDecider, g *MockCodeGrantStore, e *MockErrorHandler) {
				c.On("GetClient", mock.Anything, "client1").Return(&client.DefaultClient{
					ID:                  "client1",
					AllowedRedirectURIs: []string{"https://example.com/cb"},
				}, nil)
				u.On("AuthenticateUser", mock.Anything, mock.Anything).Return(nil, errors.New("access denied"))
				e.On("WriteAuthorizationError", mock.Anything, mock.Anything, "https://example.com/cb", mock.MatchedBy(func(r rfc6749.ErrorResponse) bool {
					return r.Error == rfc6749.ErrAccessDenied
				})).Return()
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "Successful Authorization",
			method: http.MethodGet,
			queryParams: map[string]string{
				"response_type": "code",
				"client_id":     "client1",
				"redirect_uri":  "https://example.com/cb",
				"state":         "xyz",
			},
			setupMocks: func(c *MockClientStore, u *MockUserConsentDecider, g *MockCodeGrantStore, e *MockErrorHandler) {
				c.On("GetClient", mock.Anything, "client1").Return(&client.DefaultClient{
					ID:                  "client1",
					AllowedRedirectURIs: []string{"https://example.com/cb"},
				}, nil)
				u.On("AuthenticateUser", mock.Anything, mock.Anything).Return(identity.SimpleIdentity{Sub: "user123"}, nil)
				g.On("CreateCode", mock.Anything, mock.Anything, "user123").Return("splash", nil)
			},
			expectedStatus: http.StatusFound,
			expectedHeader: map[string]string{
				"Location": "https://example.com/cb?code=splash&state=xyz",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientStore := &MockClientStore{}
			userDecider := &MockUserConsentDecider{}
			codeStore := &MockCodeGrantStore{}
			errHandler := &MockErrorHandler{}

			if tt.setupMocks != nil {
				tt.setupMocks(clientStore, userDecider, codeStore, errHandler)
			}

			handlers := map[string]authorize.AuthorizeGrantHandler{
				rfc6749.ResponseTypeCode: authorize.AuthorizeGrantHandlerFunc(func(ctx context.Context, req rfc6749.AuthorizationRequest) (*authorize.AuthorizeResponse, error) {
					id, ok := identity.FromContext(ctx)
					if !ok || id == nil {
						return nil, rfc6749.ProtocolError{Response: rfc6749.ErrorResponse{Error: rfc6749.ErrAccessDenied}}
					}
					code, err := codeStore.CreateCode(ctx, req, id.Subject())
					if err != nil || code == "" {
						return nil, rfc6749.ProtocolError{Response: rfc6749.ErrorResponse{Error: rfc6749.ErrServerError}}
					}
					return &authorize.AuthorizeResponse{
						Code:  code,
						State: req.State,
					}, nil
				}),
			}

			handler := authorize.NewAuthorizeHandler(clientStore, userDecider, errHandler, handlers)

			req := httptest.NewRequest(tt.method, "/authorize", nil)
			if tt.queryParams != nil {
				q := req.URL.Query()
				for k, v := range tt.queryParams {
					q.Set(k, v)
				}
				req.URL.RawQuery = q.Encode()
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			for k, v := range tt.expectedHeader {
				assert.Equal(t, v, w.Header().Get(k))
			}

			clientStore.AssertExpectations(t)
			userDecider.AssertExpectations(t)
			codeStore.AssertExpectations(t)
			errHandler.AssertExpectations(t)
		})
	}
}

func TestAuthorizeHandler_NeedsHumanInteraction(t *testing.T) {
	clientStore := &MockClientStore{}
	userDecider := &MockUserConsentDecider{}
	errHandler := &MockErrorHandler{}

	clientStore.On("GetClient", mock.Anything, "client1").Return(&client.DefaultClient{
		ID:                  "client1",
		AllowedRedirectURIs: []string{"https://example.com/cb"},
	}, nil)

	userDecider.On("AuthenticateUser", mock.Anything, mock.Anything).Return(nil, authorize.ErrNeedsHumanInteraction)

	var interactionCalled bool
	handler := authorize.NewAuthorizeHandler(clientStore, userDecider, errHandler, nil)
	handler.SetHumanInteractionHandler(authorize.HumanInteractionHandlerFunc(func(w http.ResponseWriter, r *http.Request, req rfc6749.AuthorizationRequest) {
		interactionCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>Login Form</html>"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/authorize?response_type=code&client_id=client1&redirect_uri=https://example.com/cb", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.True(t, interactionCalled)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "<html>Login Form</html>", w.Body.String())
}

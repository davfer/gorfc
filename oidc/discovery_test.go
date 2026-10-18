package oidc_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/davfer/gorfc/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscoveryHandler_ServeHTTP(t *testing.T) {
	t.Run("successful provider metadata serving", func(t *testing.T) {
		expectedMeta := oidc.ProviderMetadata{
			Issuer:                 "https://auth.example.com",
			AuthorizationEndpoint: "https://auth.example.com/authorize",
			TokenEndpoint:         "https://auth.example.com/token",
			JwksURI:                "https://auth.example.com/.well-known/jwks.json",
			ResponseTypesSupported: []string{"code"},
			SubjectTypesSupported:  []string{"public"},
			IDTokenSigningAlgValuesSupported: []string{"RS256"},
		}

		provider := func(ctx context.Context) (oidc.ProviderMetadata, error) {
			return expectedMeta, nil
		}

		handler := oidc.NewDiscoveryHandler(provider, nil)

		req := httptest.NewRequest(http.MethodGet, oidc.DiscoveryPath, nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
		assert.Contains(t, rec.Body.String(), `"issuer":"https://auth.example.com"`)
		assert.Contains(t, rec.Body.String(), `"jwks_uri":"https://auth.example.com/.well-known/jwks.json"`)
	})

	t.Run("provider error triggers error handler", func(t *testing.T) {
		providerErr := errors.New("database connection failed")
		provider := func(ctx context.Context) (oidc.ProviderMetadata, error) {
			return oidc.ProviderMetadata{}, providerErr
		}

		var capturedErr error
		customErrorHandler := func(w http.ResponseWriter, err error) {
			capturedErr = err
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		handler := oidc.NewDiscoveryHandler(provider, customErrorHandler)

		req := httptest.NewRequest(http.MethodGet, oidc.DiscoveryPath, nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		require.Error(t, capturedErr)
		assert.Equal(t, providerErr, capturedErr)
	})
}

package jwks_test

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/davfer/gorfc/jwks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type failingProvider struct{}

func (f *failingProvider) GetKeys(ctx any) ([]any, error) {
	return nil, errors.New("kms error")
}

func TestHandler_ServeHTTP(t *testing.T) {
	t.Run("successful JWKS response", func(t *testing.T) {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		provider, err := jwks.CreateMemoryProvider([]any{priv})
		require.NoError(t, err)

		handler := jwks.NewHandler(provider, nil)

		req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "application/jwk-set+json", rec.Header().Get("Content-Type"))
		assert.Contains(t, rec.Body.String(), `"keys":[{`)
		assert.Contains(t, rec.Body.String(), `"kty":"RSA"`)
	})

	t.Run("empty keys returned when provider has no keys", func(t *testing.T) {
		provider, err := jwks.CreateMemoryProvider([]any{})
		require.NoError(t, err)

		handler := jwks.NewHandler(provider, nil)

		req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "application/jwk-set+json", rec.Header().Get("Content-Type"))
		assert.JSONEq(t, `{"keys":[]}`, rec.Body.String())
	})
}

package rfc6749

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTokenRequest(t *testing.T) {
	t.Run("Valid Form Data", func(t *testing.T) {
		formData := url.Values{
			"grant_type":   {"authorization_code"},
			"code":         {"code123"},
			"redirect_uri": {"https://example.com/cb"},
			"scope":        {"read write"},
		}

		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(formData.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		parsed, err := ParseTokenRequest(req)
		require.NoError(t, err)

		assert.Equal(t, "authorization_code", parsed.GrantType)
		assert.Equal(t, "read write", parsed.Scope)
		assert.Equal(t, "code123", parsed.Get("code"))
		assert.Equal(t, "https://example.com/cb", parsed.Get("redirect_uri"))
	})

	t.Run("Invalid Content Type", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")

		_, err := ParseTokenRequest(req)
		require.Error(t, err)

		var protoErr ProtocolError
		require.ErrorAs(t, err, &protoErr)
		assert.Equal(t, ErrInvalidRequest, protoErr.Response.Error)
	})
}

func TestTokenRequest_Get(t *testing.T) {
	req := TokenRequest{
		GrantType: "authorization_code",
		Scope:     "read write",
		Extra: map[string]string{
			"code":          "code123",
			"redirect_uri":  "https://example.com/cb",
			"code_verifier": "verifier_abc",
		},
	}

	assert.Equal(t, "authorization_code", req.Get("grant_type"))
	assert.Equal(t, "read write", req.Get("scope"))
	assert.Equal(t, "code123", req.Get("code"))
	assert.Equal(t, "https://example.com/cb", req.Get("redirect_uri"))
	assert.Equal(t, "verifier_abc", req.Get("code_verifier"))
	assert.Equal(t, "", req.Get("nonexistent"))
}

func TestTokenRequest_Unmarshal(t *testing.T) {
	t.Run("Unmarshal into PKCE Extension struct", func(t *testing.T) {
		type PKCETokenRequest struct {
			GrantType    string `json:"grant_type"`
			Code         string `json:"code"`
			CodeVerifier string `json:"code_verifier"`
		}

		req := TokenRequest{
			GrantType: "authorization_code",
			Extra: map[string]string{
				"code":          "code_xyz",
				"code_verifier": "verifier_12345",
			},
		}

		var pkceReq PKCETokenRequest
		err := req.Unmarshal(&pkceReq)
		require.NoError(t, err)

		assert.Equal(t, "authorization_code", pkceReq.GrantType)
		assert.Equal(t, "code_xyz", pkceReq.Code)
		assert.Equal(t, "verifier_12345", pkceReq.CodeVerifier)
	})

	t.Run("Unmarshal into AuthorizationCodeTokenRequest", func(t *testing.T) {
		req := TokenRequest{
			GrantType: "authorization_code",
			Extra: map[string]string{
				"code":         "auth_code_99",
				"redirect_uri": "https://app.example.com/callback",
				"client_id":    "client_app",
			},
		}

		var authCodeReq AuthorizationCodeTokenRequest
		err := req.Unmarshal(&authCodeReq)
		require.NoError(t, err)

		assert.Equal(t, "authorization_code", authCodeReq.GrantType)
		assert.Equal(t, "auth_code_99", authCodeReq.Code)
		assert.Equal(t, "https://app.example.com/callback", authCodeReq.RedirectURI)
		assert.Equal(t, "client_app", authCodeReq.ClientID)
	})
}

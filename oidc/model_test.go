package oidc_test

import (
	"encoding/json"
	"testing"

	"github.com/davfer/gorfc/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetFlow(t *testing.T) {
	tests := []struct {
		name         string
		responseType string
		wantFlow     string
	}{
		{name: "code", responseType: oidc.ResponseTypeCode, wantFlow: oidc.FlowAuthorizationCode},
		{name: "id_token", responseType: oidc.ResponseTypeIDToken, wantFlow: oidc.FlowImplicit},
		{name: "id_token token", responseType: oidc.ResponseTypeIDTokenToken, wantFlow: oidc.FlowImplicit},
		{name: "code id_token", responseType: oidc.ResponseTypeCodeIDToken, wantFlow: oidc.FlowHybrid},
		{name: "code token", responseType: oidc.ResponseTypeCodeToken, wantFlow: oidc.FlowHybrid},
		{name: "code id_token token", responseType: oidc.ResponseTypeCodeIDTokenToken, wantFlow: oidc.FlowHybrid},
		{name: "unknown response_type", responseType: "none", wantFlow: ""},
		{name: "empty response_type", responseType: "", wantFlow: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantFlow, oidc.GetFlow(tt.responseType))
		})
	}
}

func TestProviderMetadata_Supports(t *testing.T) {
	meta := oidc.ProviderMetadata{
		ScopesSupported:        []string{"openid", "profile", "email"},
		ResponseTypesSupported: []string{"code", "id_token"},
		GrantTypesSupported:    []string{"authorization_code", "refresh_token"},
	}

	t.Run("SupportsScope", func(t *testing.T) {
		assert.True(t, meta.SupportsScope("openid"))
		assert.True(t, meta.SupportsScope("email"))
		assert.False(t, meta.SupportsScope("phone"))
	})

	t.Run("SupportsResponseType", func(t *testing.T) {
		assert.True(t, meta.SupportsResponseType("code"))
		assert.False(t, meta.SupportsResponseType("token"))
	})

	t.Run("SupportsGrantType", func(t *testing.T) {
		assert.True(t, meta.SupportsGrantType("authorization_code"))
		assert.False(t, meta.SupportsGrantType("client_credentials"))
	})
}

func TestWebFingerResponse_GetIssuer(t *testing.T) {
	tests := []struct {
		name       string
		resp       oidc.WebFingerResponse
		wantIssuer string
	}{
		{
			name: "issuer link present",
			resp: oidc.WebFingerResponse{
				Subject: "acct:user@example.com",
				Links: []oidc.WebFingerLink{
					{Rel: "http://example.com/rel", Href: "http://example.com"},
					{Rel: oidc.IssuerRel, Href: "https://auth.example.com"},
				},
			},
			wantIssuer: "https://auth.example.com",
		},
		{
			name: "no issuer link present",
			resp: oidc.WebFingerResponse{
				Subject: "acct:user@example.com",
				Links: []oidc.WebFingerLink{
					{Rel: "http://example.com/rel", Href: "http://example.com"},
				},
			},
			wantIssuer: "",
		},
		{
			name:       "empty links",
			resp:       oidc.WebFingerResponse{Subject: "user"},
			wantIssuer: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantIssuer, tt.resp.GetIssuer())
		})
	}
}

func TestOIDCModels_JSONSerialization(t *testing.T) {
	t.Run("IDTokenClaims", func(t *testing.T) {
		claims := oidc.IDTokenClaims{
			Issuer:   "https://auth.example.com",
			Subject:  "sub-1",
			Audience: []string{"client-1"},
			Expiry:   1700000000,
			IssuedAt: 1700000000,
			Nonce:    "nonce123",
		}

		data, err := json.Marshal(claims)
		require.NoError(t, err)

		var unmarshaled oidc.IDTokenClaims
		err = json.Unmarshal(data, &unmarshaled)
		require.NoError(t, err)
		assert.Equal(t, claims, unmarshaled)
	})

	t.Run("StandardClaims with Address", func(t *testing.T) {
		claims := oidc.StandardClaims{
			Subject:       "sub-1",
			Name:          "John Doe",
			GivenName:     "John",
			FamilyName:    "Doe",
			Email:         "john@example.com",
			EmailVerified: true,
			Address: &oidc.AddressClaim{
				Formatted:  "123 Main St, Anytown",
				Country:    "US",
				PostalCode: "12345",
			},
		}

		data, err := json.Marshal(claims)
		require.NoError(t, err)

		var unmarshaled oidc.StandardClaims
		err = json.Unmarshal(data, &unmarshaled)
		require.NoError(t, err)
		assert.Equal(t, claims, unmarshaled)
	})

	t.Run("AuthorizationRequest and Response", func(t *testing.T) {
		req := oidc.AuthorizationRequest{
			Scope:        "openid profile",
			ResponseType: oidc.ResponseTypeCode,
			ClientID:     "client1",
			RedirectURI:  "https://app.example.com/cb",
			Nonce:        "n123",
			MaxAge:       300,
		}

		data, err := json.Marshal(req)
		require.NoError(t, err)

		var unmarshaledReq oidc.AuthorizationRequest
		err = json.Unmarshal(data, &unmarshaledReq)
		require.NoError(t, err)
		assert.Equal(t, req, unmarshaledReq)

		resp := oidc.AuthorizationResponse{
			Code:  "code123",
			State: "state123",
		}
		respData, err := json.Marshal(resp)
		require.NoError(t, err)

		var unmarshaledResp oidc.AuthorizationResponse
		err = json.Unmarshal(respData, &unmarshaledResp)
		require.NoError(t, err)
		assert.Equal(t, resp, unmarshaledResp)
	})
}

package rfc7519_test

import (
	"encoding/json"
	"testing"

	"github.com/davfer/gorfc/rfc7519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAudience_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name      string
		jsonInput string
		want      rfc7519.Audience
		wantErr   bool
	}{
		{
			name:      "single string audience",
			jsonInput: `"https://api.example.com"`,
			want:      rfc7519.Audience{"https://api.example.com"},
			wantErr:   false,
		},
		{
			name:      "array of string audiences",
			jsonInput: `["https://api.example.com", "https://auth.example.com"]`,
			want:      rfc7519.Audience{"https://api.example.com", "https://auth.example.com"},
			wantErr:   false,
		},
		{
			name:      "empty array audience",
			jsonInput: `[]`,
			want:      rfc7519.Audience{},
			wantErr:   false,
		},
		{
			name:      "invalid numeric audience type",
			jsonInput: `12345`,
			want:      nil,
			wantErr:   true,
		},
		{
			name:      "invalid boolean audience type",
			jsonInput: `true`,
			want:      nil,
			wantErr:   true,
		},
		{
			name:      "invalid object audience type",
			jsonInput: `{"aud": "api"}`,
			want:      nil,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var aud rfc7519.Audience
			err := aud.UnmarshalJSON([]byte(tt.jsonInput))

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, aud)
			}
		})
	}
}

func TestAudience_MarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		aud  rfc7519.Audience
		want string
	}{
		{
			name: "single audience marshals to string",
			aud:  rfc7519.Audience{"https://api.example.com"},
			want: `"https://api.example.com"`,
		},
		{
			name: "multiple audiences marshal to array",
			aud:  rfc7519.Audience{"https://api.example.com", "https://service.example.com"},
			want: `["https://api.example.com","https://service.example.com"]`,
		},
		{
			name: "empty audience slice marshals to array",
			aud:  rfc7519.Audience{},
			want: `[]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.aud)
			require.NoError(t, err)
			assert.JSONEq(t, tt.want, string(data))
		})
	}
}

func TestClaims_JSONSerialization(t *testing.T) {
	t.Run("Claims with single audience", func(t *testing.T) {
		claims := rfc7519.Claims{
			Issuer:    "https://auth.example.com",
			Subject:   "user-123",
			Audience:  rfc7519.Audience{"api-service"},
			ExpiresAt: 1700003600,
			NotBefore: 1700000000,
			IssuedAt:  1700000000,
			ID:        "jwt-id-999",
		}

		data, err := json.Marshal(claims)
		require.NoError(t, err)

		var unmarshaled rfc7519.Claims
		err = json.Unmarshal(data, &unmarshaled)
		require.NoError(t, err)
		assert.Equal(t, claims, unmarshaled)
	})

	t.Run("Claims with multiple audiences", func(t *testing.T) {
		claims := rfc7519.Claims{
			Issuer:   "https://auth.example.com",
			Subject:  "user-456",
			Audience: rfc7519.Audience{"api1", "api2"},
		}

		data, err := json.Marshal(claims)
		require.NoError(t, err)

		var unmarshaled rfc7519.Claims
		err = json.Unmarshal(data, &unmarshaled)
		require.NoError(t, err)
		assert.Equal(t, claims, unmarshaled)
	})
}

func TestHeader_JSONSerialization(t *testing.T) {
	header := rfc7519.Header{
		Typ:  "JWT",
		Alg:  "RS256",
		Kid:  "key-1",
		Jku:  "https://auth.example.com/.well-known/jwks.json",
		Crit: []string{"b64"},
	}

	data, err := json.Marshal(header)
	require.NoError(t, err)

	var unmarshaled rfc7519.Header
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)
	assert.Equal(t, header, unmarshaled)
}

func TestUnsecuredJWT_JSONSerialization(t *testing.T) {
	token := rfc7519.UnsecuredJWT{
		Header: rfc7519.Header{
			Typ: "JWT",
			Alg: "none",
		},
		Claims: rfc7519.Claims{
			Issuer:  "https://auth.example.com",
			Subject: "unsecured-subject",
		},
	}

	data, err := json.Marshal(token)
	require.NoError(t, err)

	var unmarshaled rfc7519.UnsecuredJWT
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)
	assert.Equal(t, token, unmarshaled)
}

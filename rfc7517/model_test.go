package rfc7517_test

import (
	"encoding/json"
	"testing"

	"github.com/davfer/gorfc/rfc7517"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWK_JSONSerialization(t *testing.T) {
	tests := []struct {
		name     string
		jwk      rfc7517.JWK
		expected map[string]any
	}{
		{
			name: "RSA public key",
			jwk: rfc7517.JWK{
				Kty: "RSA",
				Use: "sig",
				Alg: "RS256",
				Kid: "key-rsa-1",
				N:   "n-modulus-base64url",
				E:   "AQAB",
			},
			expected: map[string]any{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": "key-rsa-1",
				"n":   "n-modulus-base64url",
				"e":   "AQAB",
			},
		},
		{
			name: "EC public key",
			jwk: rfc7517.JWK{
				Kty: "EC",
				Crv: "P-256",
				X:   "x-coord",
				Y:   "y-coord",
				Kid: "key-ec-1",
			},
			expected: map[string]any{
				"kty": "EC",
				"crv": "P-256",
				"x":   "x-coord",
				"y":   "y-coord",
				"kid": "key-ec-1",
			},
		},
		{
			name: "OKP Ed25519 public key",
			jwk: rfc7517.JWK{
				Kty: "OKP",
				Crv: "Ed25519",
				X:   "ed25519-public-key-bytes",
				Kid: "key-ed-1",
			},
			expected: map[string]any{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   "ed25519-public-key-bytes",
				"kid": "key-ed-1",
			},
		},
		{
			name: "Symmetric oct key",
			jwk: rfc7517.JWK{
				Kty: "oct",
				K:   "symmetric-key-base64url",
				Alg: "HS256",
				Use: "sig",
			},
			expected: map[string]any{
				"kty": "oct",
				"k":   "symmetric-key-base64url",
				"alg": "HS256",
				"use": "sig",
			},
		},
		{
			name: "RSA key with Oth prime info",
			jwk: rfc7517.JWK{
				Kty: "RSA",
				N:   "modulus",
				E:   "AQAB",
				Oth: []rfc7517.Oth{
					{R: "prime1", D: "exp1", T: "coeff1"},
				},
			},
			expected: map[string]any{
				"kty": "RSA",
				"n":   "modulus",
				"e":   "AQAB",
				"oth": []any{
					map[string]any{"r": "prime1", "d": "exp1", "t": "coeff1"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.jwk)
			require.NoError(t, err)

			var resultMap map[string]any
			err = json.Unmarshal(data, &resultMap)
			require.NoError(t, err)

			assert.Equal(t, tt.expected, resultMap)

			// Verify roundtrip unmarshaling into JWK struct
			var unmarshaledJWK rfc7517.JWK
			err = json.Unmarshal(data, &unmarshaledJWK)
			require.NoError(t, err)
			assert.Equal(t, tt.jwk, unmarshaledJWK)
		})
	}
}

func TestJWKS_JSONSerialization(t *testing.T) {
	t.Run("Empty JWKS", func(t *testing.T) {
		jwks := rfc7517.JWKS{Keys: []rfc7517.JWK{}}
		data, err := json.Marshal(jwks)
		require.NoError(t, err)
		assert.JSONEq(t, `{"keys":[]}`, string(data))
	})

	t.Run("Populated JWKS", func(t *testing.T) {
		jwks := rfc7517.JWKS{
			Keys: []rfc7517.JWK{
				{Kty: "RSA", Kid: "1", N: "mod", E: "AQAB"},
				{Kty: "EC", Kid: "2", Crv: "P-256", X: "x", Y: "y"},
			},
		}

		data, err := json.Marshal(jwks)
		require.NoError(t, err)

		var unmarshaled rfc7517.JWKS
		err = json.Unmarshal(data, &unmarshaled)
		require.NoError(t, err)
		assert.Len(t, unmarshaled.Keys, 2)
		assert.Equal(t, jwks, unmarshaled)
	})
}

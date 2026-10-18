package jwks

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/davfer/gorfc/rfc7517"
)

// KeyProvider defines the contract for fetching JSON Web Keys.
// By strictly returning []JWK, we guarantee type safety and avoid `any`.
type KeyProvider interface {
	GetKeys(ctx context.Context) ([]rfc7517.JWK, error)
}

type MemoryProvider struct {
	Keys []rfc7517.JWK
}

func CreateMemoryProvider(keys []any) (*MemoryProvider, error) {
	keysJWK := make([]rfc7517.JWK, 0, len(keys))
	for _, key := range keys {
		jwk, err := KeyToJWK(key)
		if err != nil {
			return nil, err
		}
		keysJWK = append(keysJWK, jwk)
	}
	return &MemoryProvider{Keys: keysJWK}, nil
}

func (m *MemoryProvider) GetKeys(ctx context.Context) ([]rfc7517.JWK, error) {
	return m.Keys, nil
}

func KeyToJWK(rawKey any) (rfc7517.JWK, error) {
	// 1. SAFETY CHECK: If a private key is passed, extract the public key.
	// This ensures we never leak private key material to the JWKS endpoint.
	origKey := rawKey
	if priv, ok := rawKey.(interface{ Public() crypto.PublicKey }); ok {
		rawKey = priv.Public()
	}

	var jwk rfc7517.JWK

	// 2. Type switch on the PUBLIC key to build the JWK parameters.
	switch k := rawKey.(type) {
	case *rsa.PublicKey:
		jwk.Kty = "RSA"
		jwk.N = base64.RawURLEncoding.EncodeToString(k.N.Bytes())
		jwk.E = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes())
	case *ecdsa.PublicKey:
		jwk.Kty = "EC"
		jwk.X = base64.RawURLEncoding.EncodeToString(k.X.Bytes())
		jwk.Y = base64.RawURLEncoding.EncodeToString(k.Y.Bytes())
		jwk.Crv = k.Curve.Params().Name
	case ed25519.PublicKey:
		jwk.Kty = "OKP" // Octet Key Pair
		jwk.Crv = "Ed25519"
		jwk.X = base64.RawURLEncoding.EncodeToString(k)
	default:
		return rfc7517.JWK{}, fmt.Errorf("unsupported key type: %T", rawKey)
	}

	// 3. Extract optional metadata from either wrapper object or public key
	checkKey := func(fn func(any)) {
		fn(origKey)
		fn(rawKey)
	}

	checkKey(func(target any) {
		if jwk.Kid == "" {
			if k, ok := target.(interface{ KeyID() string }); ok {
				jwk.Kid = k.KeyID()
			}
		}
		if jwk.Use == "" {
			if u, ok := target.(interface{ KeyUse() string }); ok {
				jwk.Use = u.KeyUse()
			}
		}
		if len(jwk.KeyOps) == 0 {
			if o, ok := target.(interface{ KeyOps() []string }); ok {
				jwk.KeyOps = o.KeyOps()
			}
		}
		if jwk.Alg == "" {
			if a, ok := target.(interface{ Alg() string }); ok {
				jwk.Alg = a.Alg()
			}
		}
	})

	return jwk, nil
}

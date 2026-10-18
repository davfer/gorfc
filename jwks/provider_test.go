package jwks_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/davfer/gorfc/jwks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type customKeyWrapper struct {
	rawKey any
	kid    string
	use    string
	ops    []string
	alg    string
}

func (c *customKeyWrapper) Public() crypto.PublicKey { return c.rawKey.(crypto.PublicKey) }
func (c *customKeyWrapper) KeyID() string    { return c.kid }
func (c *customKeyWrapper) KeyUse() string   { return c.use }
func (c *customKeyWrapper) KeyOps() []string { return c.ops }
func (c *customKeyWrapper) Alg() string      { return c.alg }

func TestKeyToJWK_PublicKeyTypes(t *testing.T) {
	t.Run("RSA Public Key", func(t *testing.T) {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		jwk, err := jwks.KeyToJWK(&priv.PublicKey)
		require.NoError(t, err)

		assert.Equal(t, "RSA", jwk.Kty)
		assert.NotEmpty(t, jwk.N)
		assert.NotEmpty(t, jwk.E)
		assert.Empty(t, jwk.D, "Public JWK must not contain private exponent D")
	})

	t.Run("ECDSA Public Key", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		jwk, err := jwks.KeyToJWK(&priv.PublicKey)
		require.NoError(t, err)

		assert.Equal(t, "EC", jwk.Kty)
		assert.Equal(t, "P-256", jwk.Crv)
		assert.NotEmpty(t, jwk.X)
		assert.NotEmpty(t, jwk.Y)
		assert.Empty(t, jwk.D, "Public JWK must not contain private scalar D")
	})

	t.Run("Ed25519 Public Key", func(t *testing.T) {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		jwk, err := jwks.KeyToJWK(pub)
		require.NoError(t, err)

		assert.Equal(t, "OKP", jwk.Kty)
		assert.Equal(t, "Ed25519", jwk.Crv)
		assert.NotEmpty(t, jwk.X)
	})
}

func TestKeyToJWK_SecurityGuardrails_PrivateKeyStripping(t *testing.T) {
	t.Run("RSA Private Key input must strip private CRT parameters", func(t *testing.T) {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		jwk, err := jwks.KeyToJWK(priv) // Passing Private Key!
		require.NoError(t, err)

		assert.Equal(t, "RSA", jwk.Kty)
		assert.NotEmpty(t, jwk.N)
		assert.NotEmpty(t, jwk.E)

		// Verify zero leakage of sensitive key material
		assert.Empty(t, jwk.D, "CRITICAL: Private exponent D leaked")
		assert.Empty(t, jwk.P, "CRITICAL: First prime factor P leaked")
		assert.Empty(t, jwk.Q, "CRITICAL: Second prime factor Q leaked")
		assert.Empty(t, jwk.Dp, "CRITICAL: CRT exponent Dp leaked")
		assert.Empty(t, jwk.Dq, "CRITICAL: CRT exponent Dq leaked")
		assert.Empty(t, jwk.Qi, "CRITICAL: CRT coefficient Qi leaked")
	})

	t.Run("ECDSA Private Key input must strip private scalar D", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		jwk, err := jwks.KeyToJWK(priv)
		require.NoError(t, err)

		assert.Equal(t, "EC", jwk.Kty)
		assert.NotEmpty(t, jwk.X)
		assert.NotEmpty(t, jwk.Y)
		assert.Empty(t, jwk.D, "CRITICAL: Private key D leaked")
	})

	t.Run("Ed25519 Private Key input must convert to public key", func(t *testing.T) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		jwk, err := jwks.KeyToJWK(priv)
		require.NoError(t, err)

		assert.Equal(t, "OKP", jwk.Kty)
		assert.Equal(t, "Ed25519", jwk.Crv)
		assert.NotEmpty(t, jwk.X)
	})
}

func TestKeyToJWK_MetadataInterfaces(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	wrapper := &customKeyWrapper{
		rawKey: pub,
		kid:    "kid-custom-123",
		use:    "sig",
		ops:    []string{"verify"},
		alg:    "EdDSA",
	}

	jwk, err := jwks.KeyToJWK(wrapper)
	require.NoError(t, err)

	assert.Equal(t, "kid-custom-123", jwk.Kid)
	assert.Equal(t, "sig", jwk.Use)
	assert.Equal(t, []string{"verify"}, jwk.KeyOps)
	assert.Equal(t, "EdDSA", jwk.Alg)
}

func TestKeyToJWK_UnsupportedType(t *testing.T) {
	_, err := jwks.KeyToJWK("invalid-string-key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key type")
}

func TestCreateMemoryProvider(t *testing.T) {
	privRSA, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubEd, _, _ := ed25519.GenerateKey(rand.Reader)

	provider, err := jwks.CreateMemoryProvider([]any{privRSA, pubEd})
	require.NoError(t, err)

	keys, err := provider.GetKeys(context.Background())
	require.NoError(t, err)
	assert.Len(t, keys, 2)
	assert.Equal(t, "RSA", keys[0].Kty)
	assert.Equal(t, "OKP", keys[1].Kty)
}

# gorfc 🛡️

**Go RFC Standards & Identity Infrastructure Primitives**

`gorfc` is a lightweight, spec-compliant, zero-dependency Go library that provides data models, validation functions, HTTP handlers, and cryptographic primitives for IETF RFCs and OpenID specifications.

Designed specifically to serve as the building blocks for modern **Identity Providers (IdP)**, **OAuth 2.0 / OpenID Connect Authorization Servers**, **Resource Servers**, and **secure enterprise applications**.

---

## 🚀 Key Features

- **Standard Library Pure**: Built using 100% Go standard library (`net/http`, `crypto`, `encoding/json`, `math/big`). No external bloat.
- **Strict RFC Specification Fidelity**: Direct alignment with official IETF RFCs and OpenID Connect specifications, complete with ABNF grammar validation.
- **Identity Provider Ready**: Ready-to-use models for Authorization Requests, Token Requests, UserInfo, OIDC Discovery (`.well-known/openid-configuration`), and JWKS endpoints.
- **Key Safety Guardrails**: Built-in protection preventing accidental exposure of private key material when publishing JWK sets.
- **Flexible JSON Handling**: Seamless custom JSON marshaling for single-value vs array-value claims (e.g., JWT `aud` claim).
- **Exhaustive Claim Dictionary**: Over 70+ spec-registered JWT claim constants mapped across RFC 7519, OIDC, RFC 7800, RFC 8055, RFC 8225, RFC 8417, RFC 8693, RFC 9200, RFC 9449, RFC 9711, and 3GPP standards.

---

## 📋 Implemented Specifications Matrix

| Specification / Standard | Package | Key Components & Primitives | Status |
|---|---|---|---|
| **RFC 6749** <br> *(OAuth 2.0 Authorization Framework)* | [`rfc6749`](./rfc6749) | `AuthorizationRequest`, `TokenRequest`, `TokenResponse`, `ErrorResponse`, Grant Types, ABNF Validators (`isVSCHAR`, `isNQCHAR`, `isNQSCHAR`) | ✅ Implemented |
| **RFC 7517** / **RFC 7518** <br> *(JSON Web Key & Algorithms)* | [`rfc7517`](./rfc7517) | `JWK`, `JWKS`, RSA Parameters (`n`, `e`, `d`, `p`, `q`, `dp`, `dq`, `qi`), EC Parameters (`crv`, `x`, `y`), OKP (Ed25519), Symmetric (`k`) | ✅ Implemented |
| **RFC 7519** <br> *(JSON Web Token)* | [`rfc7519`](./rfc7519) | Registered `Claims`, `Header`, `Audience` (dual string/slice JSON handler), 70+ Standard Claim Constants (`claims.go`) | ✅ Implemented |
| **OpenID Connect Core 1.0** | [`oidc`](./oidc) | `IDTokenClaims`, `StandardClaims`, `AddressClaim`, Authentication Requests/Responses, Flow Determination | ✅ Implemented |
| **OpenID Connect Discovery 1.0** | [`oidc`](./oidc) | `ProviderMetadata` (`/.well-known/openid-configuration`), `WebFingerResponse` (`/.well-known/webfinger`), Discovery HTTP Handler | ✅ Implemented |
| **JWKS Publishing** | [`jwks`](./jwks) | `KeyProvider` interface, `MemoryProvider`, `KeyToJWK` safety converter (strips private keys), HTTP Handler (`application/jwk-set+json`) | ✅ Implemented |
| **RFC 7636** <br> *(PKCE)* | [`rfc7636`](./rfc7636) | Proof Key for Code Exchange (Code Challenge & Verifier, S256/Plain) | ✅ Implemented |
| **RFC 8176** <br> *(Authentication Method Reference Values)* | [`rfc8176`](./rfc8176) | Registered AMR Constants (`pwd`, `mfa`, `otp`, `user`, `hwk`, etc.), IANA AMR Registry integration | ✅ Implemented |
| **draft-ietf-oauth-first-party-apps** <br> *(First-Party Applications)* | [`oauth/grant`](./oauth/grant) | `FirstPartyAppGrant`, `AuthorizationChallengeRequest`, `AuthorizationChallengeResponse`, `AuthorizationChallengeError`, `Challenger`, `ChallengeCodeCreator`, 256-bit `auth_session` generator | ✅ Implemented |
| **RFC 9449** *(DPoP)* | `rfc9449` | Demonstration of Proof-of-Possession at the Application Layer | 🛠️ Planned |
| **RFC 7662** *(Token Introspection)* | `rfc7662` | OAuth 2.0 Token Introspection Endpoint | 🛠️ Planned |
| **RFC 7009** *(Token Revocation)* | `rfc7009` | OAuth 2.0 Token Revocation Endpoint | 🛠️ Planned |
| **RFC 8414** *(AS Metadata)* | `rfc8414` | OAuth 2.0 Authorization Server Metadata | 🛠️ Planned |

---

## 📦 Package Architecture

```
gorfc/
├── rfc6749/   # RFC 6749: OAuth 2.0 Authorization Framework models & ABNF validators
├── rfc7517/   # RFC 7517: JSON Web Key (JWK) & JWK Set (JWKS) structures
├── rfc7519/   # RFC 7519: JSON Web Token (JWT) claims, headers & claim constants
├── oidc/      # OpenID Connect Core 1.0 & Discovery Metadata primitives
├── jwks/      # JWKS KeyProvider & HTTP Handler (application/jwk-set+json)
├── oauth/     # OAuth 2.0 server flow handlers & client authentication abstractions
├── jwt/       # High-level JWT signature & validation helpers
└── gauss/     # Standalone module (github.com/davfer/gauss): Adaptive identity & proof engine
```

---

## 💡 Code Examples

### 1. Validating OAuth 2.0 Scope & Requests (`rfc6749`)

```go
package main

import (
	"fmt"
	"github.com/davfer/gorfc/rfc6749"
)

func main() {
	req := rfc6749.AuthorizationRequest{
		ResponseType: rfc6749.ResponseTypeCode,
		ClientID:     "my-client-id",
		Scope:        "openid profile email",
		State:        "xyz123",
	}

	if req.IsAuthorizationCodeRequest() {
		fmt.Println("Valid Authorization Code flow requested")
	}

	// Spec ABNF Validation (RFC 6749 Appendix A)
	if rfc6749.IsValidScope(req.Scope) && rfc6749.IsValidClientID(req.ClientID) {
		fmt.Println("Request parameters satisfy RFC 6749 ABNF rules!")
	}
}
```

### 2. Serving an OpenID Provider Discovery Endpoint (`oidc`)

```go
package main

import (
	"context"
	"net/http"

	"github.com/davfer/gorfc/oidc"
)

func main() {
	// 1. Define metadata provider
	provider := func(ctx context.Context) (oidc.ProviderMetadata, error) {
		return oidc.ProviderMetadata{
			Issuer:                 "https://auth.example.com",
			AuthorizationEndpoint: "https://auth.example.com/oauth2/authorize",
			TokenEndpoint:         "https://auth.example.com/oauth2/token",
			JwksURI:                "https://auth.example.com/.well-known/jwks.json",
			ResponseTypesSupported: []string{oidc.ResponseTypeCode, oidc.ResponseTypeIDToken},
			SubjectTypesSupported:  []string{"public"},
			IDTokenSigningAlgValuesSupported: []string{"RS256"},
		}, nil
	}

	// 2. Mount Discovery HTTP Handler
	http.Handle(oidc.DiscoveryPath, oidc.NewDiscoveryHandler(provider, nil))
	http.ListenAndServe(":8080", nil)
}
```

### 3. Publishing a Spec-Compliant JWKS Endpoint (`jwks` + `rfc7517`)

```go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"

	"github.com/davfer/gorfc/jwks"
)

func main() {
	// Generate an RSA Key Pair for signing
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Create a MemoryProvider; KeyToJWK automatically strips private key components!
	provider, err := jwks.CreateMemoryProvider([]any{privateKey})
	if err != nil {
		panic(err)
	}

	// Serve the JWKS endpoint (Sets Content-Type: application/jwk-set+json)
	http.Handle("/.well-known/jwks.json", jwks.NewHandler(provider, nil))
	http.ListenAndServe(":8080", nil)
}
```

### 4. Using Comprehensive Standard JWT Claims (`rfc7519`)

```go
package main

import (
	"fmt"
	"time"

	"github.com/davfer/gorfc/rfc7519"
)

func main() {
	claims := rfc7519.Claims{
		Issuer:    "https://auth.example.com",
		Subject:   "user-12345",
		Audience:  rfc7519.Audience{"api.example.com", "service.example.com"},
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}

	// Access standard registered claim names from claims.go constant dictionary
	fmt.Printf("Claim Issuer Key: %s -> Value: %s\n", rfc7519.ClaimIss, claims.Issuer)
}
```

---

## ⚙️ Development & Testing

Run all unit tests across the workspace:

```bash
go test ./...
```

Verify build compilation:

```bash
go build ./...
```

---

## 📄 License

This project is licensed under the MIT License.

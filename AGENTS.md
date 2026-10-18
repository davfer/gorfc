# AGENTS.md - AI Agent Operating Manual for `gorfc`

## Overview & Mission

`gorfc` is a pure Go library designed to provide lightweight, zero-dependency, spec-compliant primitives for IETF RFCs and OpenID specifications.

The goal of `gorfc` is to serve as the definitive foundation for building robust, secure, and fully spec-compliant:
- **Identity Providers (IdP)**
- **OAuth 2.0 / OpenID Connect Authorization Servers (AS)**
- **Resource Servers (RS)**
- **Secure Enterprise & Client Applications**

When operating within this codebase, AI agents (such as Antigravity, GitHub Copilot, Claude, etc.) and human developers MUST adhere to the standards, conventions, and architectural rules outlined in this document.

---

## Core Principles for AI Agents

1. **Spec Fidelity First**:
   - Every struct, field, constant, and error code MUST directly reference its authoritative specification and section number in comments.
   - Example: `// Reference: RFC 6749, Section 4.1.1` or `// Reference: OpenID Connect Core 1.0, Section 3.1.2.1`.

2. **Zero External Dependencies**:
   - Rely strictly on the Go Standard Library (`net/http`, `crypto`, `encoding/json`, `math/big`, `strings`, etc.). Innovate with the use of experimental libraries from Go Standard Library as long as they are not deprecated.
   - Do NOT add third-party dependencies (e.g., third-party JWT or HTTP framework libraries) to core RFC packages unless explicitly instructed. Of course, this does not apply to examples directory.

3. **Key Safety Guardrails**:
   - Private key material (`d`, `p`, `q`, `dp`, `dq`, `qi`) MUST NEVER be serialized or exposed on public JWKS endpoints.
   - Always ensure public key extraction logic (such as `jwks.KeyToJWK`) strips private components before returning public JWK sets.

4. **Strict ABNF Syntax Validation**:
   - RFC 6749 and related specifications define strict Augmented Backus-Naur Form (ABNF) rules for parameter syntax.
   - Ensure input validation helper functions (e.g., `isVSCHAR`, `isNQCHAR`, `isNQSCHAR`) are used to validate parameter formatting.

5. **Flexible JSON Serialization**:
   - Specifications frequently allow fields to be either a single string or an array of strings (e.g., `aud` in JWT RFC 7519, `aud` in OIDC).
   - Implement custom `MarshalJSON` and `UnmarshalJSON` methods on custom types (like `rfc7519.Audience`) to seamlessly handle both formats.

---

## Repository Map & Package Responsibilities

```
gorfc/
├── iana/            # IANA Registries: Non-RFC IANA registries & Media Types Registry (RFC 6838)
├── rfc6749/         # RFC 6749: OAuth 2.0 Authorization Framework models, grant types & ABNF validators
├── rfc7517/         # RFC 7517: JSON Web Key (JWK) & JWK Set (JWKS) data structures & key parameters
├── rfc7519/         # RFC 7519: JSON Web Token (JWT) claims set, JOSE headers & exhaustive claim dictionary
├── rfc7636/         # RFC 7636: Proof Key for Code Exchange (PKCE) parameters, ABNF verifiers & S256/plain challenges
├── rfc8176/         # RFC 8176: Authentication Method Reference (AMR) Values
├── rfc8259/         # RFC 8259: The JavaScript Object Notation (JSON) Data Interchange Format
├── rfc9101/         # RFC 9101: The OAuth 2.0 Authorization Framework: JWT-Secured Authorization Request (JAR)
├── rfc9110/         # RFC 9110: HTTP Semantics field names & HTTP headers
├── oidc/            # OpenID Connect Core 1.0 & Discovery 1.0 facade, Provider, Server & Builder
├── oidc/identity/   # Decoupled OIDC Session interfaces (Session, AuthenticatedSession, ACRSession), StandardClaims & IdentityProvider
├── oidc/idtoken/    # IDTokenClaims, IDTokenIssuer interface, DefaultIDTokenIssuer & ComputeHash (at_hash, c_hash)
├── oidc/authorize/  # OIDC Authorization Endpoint handler (AuthorizeHandler) & Authentication Requests
├── oidc/token/      # OIDC Token Endpoint handler (TokenHandler) & token response extension
├── oidc/userinfo/   # OIDC UserInfo Endpoint handler (UserInfoHandler) & TokenValidator
├── jwks/            # HTTP Handler serving application/jwk-set+json and KeyProvider memory adapters
├── oauth/           # High-level OAuth 2.0 server models & top-level facade
├── oauth/authorize/ # OAuth 2.0 Authorization Endpoint handler (AuthorizeHandler) & interfaces
├── oauth/token/     # OAuth 2.0 Token Endpoint: domain service (TokenService), HTTP adapter (TokenHandler), GrantHandler & interfaces
├── oauth/client/    # Decoupled Client interfaces, composition abstractions (PKCEClient, ScopedClient), DefaultClient & context helpers
├── oauth/identity/  # Decoupled Identity interface, SimpleIdentity & context helpers
├── oauth/grant/     # Modular grant type handlers (authorization_code, refresh_token, client_credentials, password)
├── jwt/             # High-level JWT signature, verification, and token parsing utilities
└── gauss/           # Standalone module (github.com/davfer/gauss): Adaptive identity & proof engine
```

### Package Details

#### 1. `iana` (IANA Registries)
- **Scope**: Authoritative definitions from IANA registries for items without a single primary RFC.
- **`headers.go`**: Delegates standard HTTP Field Name Registry constants to `rfc9110`.
- **`mediatypes.go`**: Media Types Registry (RFC 6838: `MediaTypeFormUrlEncoded` and delegates to `rfc8259`, `rfc7517`, `rfc7519`, `rfc9101`).

#### 2. `rfc8259` (JSON Data Format)
- **Scope**: `MediaTypeJSON` (`application/json`).

#### 3. `rfc9101` (OAuth 2.0 JAR)
- **Scope**: `MediaTypeOAuthAuthzReqJWT` (`application/oauth-authz-req+jwt`).

#### 4. `rfc9110` (HTTP Semantics)
- **Scope**: RFC 9110 HTTP Field Names (`HeaderContentType`, `HeaderCacheControl`, `HeaderPragma`, `HeaderAuthorization`, `HeaderWWWAuthenticate`, `HeaderLocation`).

#### 1. `rfc6749` (OAuth 2.0 Core)
- **Scope**: RFC 6749 models (`AuthorizationRequest`, `TokenRequest`, `TokenResponse`, `ErrorResponse`).
- **Constants**: Response Types (`code`, `token`), Grant Types (`authorization_code`, `password`, `client_credentials`, `refresh_token`), Error Codes, HTTP Headers (`HeaderContentType`, `HeaderCacheControl`, `HeaderPragma`, `HeaderAuthorization`, `HeaderWWWAuthenticate`), Media Types (`ContentTypeJSON`, `ContentTypeFormUrlEncoded`, `ContentTypeJSONOnly`), and Cache Directives (`CacheControlNoStore`, `PragmaNoCache`).
- **Validators**: `IsValidScope`, `IsValidScopeToken`, `IsValidClientID`, `IsValidState`, `IsValidCode`, `IsValidError`.

#### 2. `rfc7517` (JWK & JWKS)
- **Scope**: `JWK` and `JWKS` structures covering Common, RSA, EC, OKP (Ed25519), and Symmetric key parameters (RFC 7517 & RFC 7518).

#### 3. `rfc7519` (JWT & Standard Claim Dictionary)
- **Scope**: Standard Registered Claims (`Claims`), JOSE Header (`Header`), Unsecured JWT wrapper (`UnsecuredJWT`).
- **`claims.go`**: Contains an exhaustive dictionary of standard claim constants (`ClaimIss`, `ClaimSub`, `ClaimAud`, `ClaimNonce`, `ClaimAcr`, `ClaimAmr`, `ClaimCnf`, `ClaimHtm`, `ClaimHtu`, `ClaimAth`, etc.) spanning RFC 7519, OIDC, RFC 7800, RFC 8055, RFC 8225, RFC 8417, RFC 8693, RFC 9200, RFC 9449, RFC 9711, and 3GPP standards.

#### 4. `rfc7636` (PKCE)
- **Scope**: Proof Key for Code Exchange constants (`code_verifier`, `code_challenge`, `code_challenge_method`), transform methods (`S256`, `plain`), ABNF verifiers, and constant-time verification logic (`VerifyCodeVerifier`, `ComputeCodeChallenge`).

#### 5. `rfc8176` (Authentication Method Reference Values)
- **Scope**: RFC 8176 AMR constants (`AMRPwd`, `AMRMfa`, `AMROtp`, `AMRUser`, `AMRHwk`, etc.) registered in the IANA Authentication Method Reference Values Registry.

#### 6. `oauth/client` & `oauth/identity`
- **Scope**: Standalone leaf packages containing `Client` and `Identity` abstractions and context injection helpers (`client.WithContext`, `client.FromContext`, `identity.WithContext`, `identity.FromContext`), avoiding parent package imports in `oauth/grant`.

#### 7. `oauth/grant` (Grant Type Handlers & First-Party Apps)
- **Scope**: Grant type handlers (`authorization_code`, `refresh_token`, `client_credentials`, `password`, `implicit`) and OAuth 2.0 for First-Party Applications (`draft-ietf-oauth-first-party-apps-04`).
- **First-Party Apps**: `FirstPartyAppGrant`, `AuthorizationChallengeRequest`, `AuthorizationChallengeResponse`, `AuthorizationChallengeError`, `Challenger`, `ChallengeCodeCreator`, and `GenerateAuthSession`.

---

## Guidelines for Extending the Codebase

When adding new RFC implementations (e.g., DPoP RFC 9449, Token Introspection RFC 7662, PAR RFC 9126):

1. **Package Naming**:
   - For pure spec data models and constants, create a directory named `rfcXXXX` (e.g., `rfc7636`).
   - For high-level handlers or feature packages, use concise domain names (e.g., `pkce`, `dpop`).

2. **File Structure**:
   - Put spec data types and constants in `model.go`.
   - Put validation functions and helpers in `validation.go` or `model.go`.
   - Add unit tests in `*_test.go`.

3. **Documentation**:
   - Update `README.md` to add the new RFC to the Specification Matrix.
   - Update `AGENTS.md` package map if a new directory is created.

---

## Developer Commands

Run all tests across all packages:
```bash
go test ./...
```

Verify build clean state:
```bash
go build ./...
```

Tidy dependencies:
```bash
go mod tidy
```

package oidc

import (
	"github.com/davfer/gorfc/jwks"
	"github.com/davfer/gorfc/oidc/authorize"
	"github.com/davfer/gorfc/oidc/token"
	"github.com/davfer/gorfc/oidc/userinfo"
)

// Provider represents a configured OpenID Connect 1.0 Provider facade.
// Reference: OpenID Connect Discovery 1.0 & OpenID Connect Core 1.0
type Provider struct {
	metadata         ProviderMetadata
	authorizeHandler *authorize.AuthorizeHandler
	tokenHandler     *token.TokenHandler
	userInfoHandler  *userinfo.UserInfoHandler
	discoveryHandler *DiscoveryHandler
	jwksHandler      *jwks.Handler
	keyProvider      jwks.KeyProvider
	tokenService     token.TokenService
}

// Metadata returns the Provider's OpenID Provider Metadata.
func (p *Provider) Metadata() ProviderMetadata {
	return p.metadata
}

// AuthorizeHandler returns the Authorization Endpoint handler.
func (p *Provider) AuthorizeHandler() *authorize.AuthorizeHandler {
	return p.authorizeHandler
}

// TokenHandler returns the Token Endpoint HTTP handler.
func (p *Provider) TokenHandler() *token.TokenHandler {
	return p.tokenHandler
}

// UserInfoHandler returns the UserInfo Endpoint HTTP handler.
func (p *Provider) UserInfoHandler() *userinfo.UserInfoHandler {
	return p.userInfoHandler
}

// DiscoveryHandler returns the Well-Known OpenID Configuration HTTP handler.
func (p *Provider) DiscoveryHandler() *DiscoveryHandler {
	return p.discoveryHandler
}

// JWKSHandler returns the JWKS Endpoint HTTP handler.
func (p *Provider) JWKSHandler() *jwks.Handler {
	return p.jwksHandler
}

// KeyProvider returns the configured JWKS key provider.
func (p *Provider) KeyProvider() jwks.KeyProvider {
	return p.keyProvider
}

// TokenService returns the configured TokenService.
func (p *Provider) TokenService() token.TokenService {
	return p.tokenService
}

package oidc

import (
	"context"
	"fmt"
	"net/http"

	"github.com/davfer/gorfc/jwks"
	oauthAuthz "github.com/davfer/gorfc/oauth/authorize"
	"github.com/davfer/gorfc/oauth/grant"
	oauthToken "github.com/davfer/gorfc/oauth/token"
	"github.com/davfer/gorfc/oidc/authorize"
	"github.com/davfer/gorfc/oidc/identity"
	"github.com/davfer/gorfc/oidc/idtoken"
	"github.com/davfer/gorfc/oidc/token"
	"github.com/davfer/gorfc/oidc/userinfo"
	"github.com/davfer/gorfc/rfc6749"
)

// Builder constructs an OpenID Connect Provider instance with fluent configuration.
type Builder struct {
	issuer             string
	clientStore        oauthAuthz.ClientStore
	identityProvider   identity.IdentityProvider
	userInfoProvider   identity.UserInfoProvider
	idTokenIssuer      idtoken.IDTokenIssuer
	codeCreator        grant.CodeCreator
	tokenValidator     userinfo.TokenValidator
	interactionHandler oauthAuthz.HumanInteractionHandler
	errHandler         oauthAuthz.ErrorHandler
	keyProvider        jwks.KeyProvider
	tokenService       token.TokenService
	clientAuth         oauthToken.ClientAuthenticator
}

// NewBuilder creates a new Builder instance.
func NewBuilder() *Builder {
	return &Builder{}
}

// SetIssuer configures the Issuer URI (e.g. "https://auth.example.com").
func (b *Builder) SetIssuer(issuer string) *Builder {
	b.issuer = issuer
	return b
}

// SetClientStore configures the ClientStore dependency.
func (b *Builder) SetClientStore(clientStore oauthAuthz.ClientStore) *Builder {
	b.clientStore = clientStore
	return b
}

// SetIdentityProvider configures the IdentityProvider dependency.
func (b *Builder) SetIdentityProvider(identityProvider identity.IdentityProvider) *Builder {
	b.identityProvider = identityProvider
	return b
}

// SetUserInfoProvider configures the UserInfoProvider dependency.
func (b *Builder) SetUserInfoProvider(userInfoProvider identity.UserInfoProvider) *Builder {
	b.userInfoProvider = userInfoProvider
	return b
}

// SetIDTokenIssuer configures the IDTokenIssuer dependency.
func (b *Builder) SetIDTokenIssuer(issuer idtoken.IDTokenIssuer) *Builder {
	b.idTokenIssuer = issuer
	return b
}

// SetTokenValidator configures the TokenValidator dependency for UserInfo requests.
func (b *Builder) SetTokenValidator(validator userinfo.TokenValidator) *Builder {
	b.tokenValidator = validator
	return b
}

// SetCodeCreator configures the authorization code creator for code and hybrid response types.
func (b *Builder) SetCodeCreator(creator grant.CodeCreator) *Builder {
	b.codeCreator = creator
	return b
}

// SetHumanInteractionHandler configures the interaction handler for human login/consent.
func (b *Builder) SetHumanInteractionHandler(handler oauthAuthz.HumanInteractionHandler) *Builder {
	b.interactionHandler = handler
	return b
}

// SetErrorHandler configures the ErrorHandler dependency.
func (b *Builder) SetErrorHandler(errHandler oauthAuthz.ErrorHandler) *Builder {
	b.errHandler = errHandler
	return b
}

// SetKeyProvider configures the JWKS key provider dependency.
func (b *Builder) SetKeyProvider(provider jwks.KeyProvider) *Builder {
	b.keyProvider = provider
	return b
}

// SetJWKSProvider is an alias for SetKeyProvider.
func (b *Builder) SetJWKSProvider(provider jwks.KeyProvider) *Builder {
	return b.SetKeyProvider(provider)
}

// SetTokenService configures the OAuth TokenService and client authenticator for the token endpoint.
func (b *Builder) SetTokenService(service token.TokenService, clientAuth oauthToken.ClientAuthenticator) *Builder {
	b.tokenService = service
	b.clientAuth = clientAuth
	return b
}

type defaultErrorHandler struct{}

func (d *defaultErrorHandler) WriteAuthorizationError(w http.ResponseWriter, r *http.Request, redirectURI string, errResp rfc6749.ErrorResponse) {
	http.Error(w, errResp.Error, http.StatusBadRequest)
}

// Build constructs and returns a configured Provider instance.
func (b *Builder) Build() (*Provider, error) {
	if b.issuer == "" {
		return nil, fmt.Errorf("oidc: issuer is required")
	}

	errH := b.errHandler
	if errH == nil {
		errH = &defaultErrorHandler{}
	}

	authzHandler := authorize.NewAuthorizeHandler(
		b.clientStore,
		b.identityProvider,
		b.idTokenIssuer,
		b.interactionHandler,
		b.codeCreator,
		errH,
	)

	uInfoHandler := userinfo.NewUserInfoHandler(b.tokenValidator, b.userInfoProvider)

	var tokHandler *token.TokenHandler
	if b.tokenService != nil {
		tokHandler = token.NewTokenHandlerFromService(
			b.tokenService,
			b.clientAuth,
			nil,
			b.idTokenIssuer,
			b.identityProvider,
		)
	}

	var jwksHandler *jwks.Handler
	if b.keyProvider != nil {
		jwksHandler = jwks.NewHandler(b.keyProvider, nil)
	}

	metadata := ProviderMetadata{
		Issuer:                b.issuer,
		AuthorizationEndpoint: b.issuer + "/authorize",
		TokenEndpoint:         b.issuer + "/token",
		UserinfoEndpoint:      b.issuer + "/userinfo",
		JwksURI:               b.issuer + "/jwks",
		ResponseTypesSupported: []string{
			authorize.ResponseTypeCode,
			authorize.ResponseTypeIDToken,
			authorize.ResponseTypeIDTokenToken,
			authorize.ResponseTypeCodeIDToken,
			authorize.ResponseTypeCodeToken,
			authorize.ResponseTypeCodeIDTokenToken,
		},
		SubjectTypesSupported: []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{
			"RS256",
		},
		ScopesSupported: []string{
			authorize.ScopeOpenID,
			authorize.ScopeProfile,
			authorize.ScopeEmail,
			authorize.ScopeAddress,
			authorize.ScopePhone,
		},
	}

	discHandler := NewDiscoveryHandler(func(ctx context.Context) (ProviderMetadata, error) {
		return metadata, nil
	}, nil)

	return &Provider{
		metadata:         metadata,
		authorizeHandler: authzHandler,
		tokenHandler:     tokHandler,
		userInfoHandler:  uInfoHandler,
		discoveryHandler: discHandler,
		jwksHandler:      jwksHandler,
		keyProvider:      b.keyProvider,
		tokenService:     b.tokenService,
	}, nil
}

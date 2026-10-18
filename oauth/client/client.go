package client

// Client represents the minimal base interface for an OAuth 2.0 client registered with the Authorization Server.
type Client interface {
	ClientID() string
}

// ScopedClient is an optional composition interface for clients with restricted scope lists.
// If a Client does not implement ScopedClient, all requested scopes are permitted by default.
type ScopedClient interface {
	Client
	Scopes() []string
}

// RedirectURIClient is an optional composition interface for clients with restricted redirect URIs.
// If a Client does not implement RedirectURIClient, all redirect URIs are permitted by default.
type RedirectURIClient interface {
	Client
	RedirectURIs() []string
}

// GrantTypesClient is an optional composition interface for clients with restricted grant types.
// If a Client does not implement GrantTypesClient, all grant types are permitted by default.
type GrantTypesClient interface {
	Client
	GrantTypes() []string
}

// ResponseTypesClient is an optional composition interface for clients with restricted response types.
// If a Client does not implement ResponseTypesClient, all response types are permitted by default.
type ResponseTypesClient interface {
	Client
	ResponseTypes() []string
}

// ConfidentialClient is an optional composition interface for confidential clients.
// If a Client does not implement ConfidentialClient, the client is assumed public by default.
type ConfidentialClient interface {
	Client
	IsConfidential() bool
}

// PKCEClient is an optional composition interface for clients requiring Proof Key for Code Exchange (PKCE).
// Reference: RFC 7636
type PKCEClient interface {
	Client
	RequiresPKCE() bool
}

// DefaultClient provides a concrete struct implementing all client extension interfaces for convenience.
type DefaultClient struct {
	ID                   string   `json:"client_id"`
	Secret               string   `json:"client_secret,omitempty"`
	AllowedRedirectURIs  []string `json:"redirect_uris,omitempty"`
	AllowedGrantTypes    []string `json:"grant_types,omitempty"`
	AllowedResponseTypes []string `json:"response_types,omitempty"`
	AllowedScopes        []string `json:"scopes,omitempty"`
	Confidential         bool     `json:"is_confidential"`
	RequirePKCE          bool     `json:"require_pkce"`
}

func (c *DefaultClient) ClientID() string        { return c.ID }
func (c *DefaultClient) RedirectURIs() []string  { return c.AllowedRedirectURIs }
func (c *DefaultClient) GrantTypes() []string    { return c.AllowedGrantTypes }
func (c *DefaultClient) ResponseTypes() []string { return c.AllowedResponseTypes }
func (c *DefaultClient) Scopes() []string        { return c.AllowedScopes }
func (c *DefaultClient) IsConfidential() bool    { return c.Confidential }
func (c *DefaultClient) RequiresPKCE() bool      { return c.RequirePKCE }

// ValidateGrantType checks if the client is allowed to use a given grant_type.
// If client does not implement GrantTypesClient or GrantTypes() is empty, all grant types are allowed by default.
func ValidateGrantType(c Client, grantType string) bool {
	gtClient, ok := c.(GrantTypesClient)
	if !ok {
		return true
	}
	grantTypes := gtClient.GrantTypes()
	if len(grantTypes) == 0 {
		return true
	}
	for _, gt := range grantTypes {
		if gt == grantType {
			return true
		}
	}
	return false
}

// ValidateRedirectURI checks if the redirect_uri is authorized for the client.
// If client does not implement RedirectURIClient or RedirectURIs() is empty, all redirect URIs are allowed by default.
func ValidateRedirectURI(c Client, redirectURI string) bool {
	rClient, ok := c.(RedirectURIClient)
	if !ok {
		return true
	}
	uris := rClient.RedirectURIs()
	if len(uris) == 0 {
		return true
	}
	for _, u := range uris {
		if u == redirectURI {
			return true
		}
	}
	return false
}

// RequiresPKCE checks if PKCE is required for the client.
// If client implements PKCEClient, returns client.RequiresPKCE(). Otherwise false by default.
func RequiresPKCE(c Client) bool {
	if pClient, ok := c.(PKCEClient); ok {
		return pClient.RequiresPKCE()
	}
	return false
}

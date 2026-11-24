package rfc8707

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsValidResourceURI(t *testing.T) {
	validURIs := []string{
		"https://api.example.com/",
		"https://api.example.com:8443/",
		"https://example.com/resource",
		"https://example.com/resource?tenant=123",
		"urn:example:animal:ferret:nose",
		"mailto:user@example.com",
		"custom+scheme-1.0://service.internal/v1",
	}
	for _, u := range validURIs {
		assert.True(t, IsValidResourceURI(u), "expected valid resource URI: %s", u)
	}

	invalidURIs := []string{
		"",
		"relative/path/only",
		"/absolute/path/without/scheme",
		"https://",
		"https:///path-without-host",
		"https://api.example.com/#fragment",
		"https://api.example.com/#",
		"urn:",
		"123invalidscheme://example.com",
		"ht tp://example.com/with space",
		"https://example.com/with space",
		"https://example.com/\x00control",
	}
	for _, u := range invalidURIs {
		assert.False(t, IsValidResourceURI(u), "expected invalid resource URI: %s", u)
	}
}

func TestAreValidResourceURIs(t *testing.T) {
	assert.False(t, AreValidResourceURIs(nil))
	assert.False(t, AreValidResourceURIs([]string{}))
	assert.True(t, AreValidResourceURIs([]string{"https://api.example.com/", "https://db.example.com/"}))
	assert.False(t, AreValidResourceURIs([]string{"https://api.example.com/", "https://bad.example.com/#frag"}))
}

func TestResourcesJSONSerialization(t *testing.T) {
	// 1. Unmarshal single string
	var authReqSingle AuthorizationRequest
	err := json.Unmarshal([]byte(`{"resource":"https://api.example.com/"}`), &authReqSingle)
	require.NoError(t, err)
	assert.Equal(t, Resources{"https://api.example.com/"}, authReqSingle.Resources)

	// Marshal single string back to JSON string
	bSingle, err := json.Marshal(authReqSingle)
	require.NoError(t, err)
	assert.JSONEq(t, `{"resource":"https://api.example.com/"}`, string(bSingle))

	// 2. Unmarshal array of strings
	var tokenReqMulti TokenRequest
	err = json.Unmarshal([]byte(`{"resource":["https://api.example.com/","https://db.example.com/"]}`), &tokenReqMulti)
	require.NoError(t, err)
	assert.Equal(t, Resources{"https://api.example.com/", "https://db.example.com/"}, tokenReqMulti.Resources)

	// Marshal multiple strings back to JSON array
	bMulti, err := json.Marshal(tokenReqMulti)
	require.NoError(t, err)
	assert.JSONEq(t, `{"resource":["https://api.example.com/","https://db.example.com/"]}`, string(bMulti))

	// 3. Invalid JSON type
	var badReq TokenRequest
	err = json.Unmarshal([]byte(`{"resource":123}`), &badReq)
	assert.Error(t, err)
}

func TestParseResourcesFromRequestAndValues(t *testing.T) {
	vals := url.Values{
		ParamResource: {"https://api.example.com/", "https://db.example.com/"},
	}
	res := ParseResourcesFromValues(vals)
	assert.Equal(t, Resources{"https://api.example.com/", "https://db.example.com/"}, res)

	assert.Nil(t, ParseResourcesFromValues(nil))
	assert.Nil(t, ParseResourcesFromValues(url.Values{}))

	req, err := http.NewRequest(http.MethodPost, "https://as.example.com/token",
		strings.NewReader("grant_type=authorization_code&resource=https%3A%2F%2Fapi.example.com%2F&resource=https%3A%2F%2Fdb.example.com%2F"))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	parsed, err := ParseResourcesFromRequest(req)
	require.NoError(t, err)
	assert.Equal(t, Resources{"https://api.example.com/", "https://db.example.com/"}, parsed)
}

func TestNormalizeAndSubsetAndUnique(t *testing.T) {
	norm, err := NormalizeResourceURI("HTTPS://API.EXAMPLE.COM/v1/Items?Foo=Bar")
	require.NoError(t, err)
	assert.Equal(t, "https://api.example.com/v1/Items?Foo=Bar", norm)

	_, err = NormalizeResourceURI("https://api.example.com/#frag")
	assert.ErrorIs(t, err, ErrInvalidResourceURI)

	granted := Resources{"https://api.example.com/v1", "https://db.example.com/"}
	assert.True(t, granted.Contains("HTTPS://API.EXAMPLE.COM/v1"))
	assert.False(t, granted.Contains("https://other.example.com/"))

	assert.True(t, IsSubset([]string{"HTTPS://API.EXAMPLE.COM/v1"}, granted))
	assert.True(t, IsSubset(nil, granted))
	assert.False(t, IsSubset([]string{"https://other.example.com/"}, granted))

	dups := Resources{"https://api.example.com/v1", "HTTPS://API.EXAMPLE.COM/v1", "https://db.example.com/"}
	assert.Equal(t, Resources{"https://api.example.com/v1", "https://db.example.com/"}, dups.Unique())
}

func TestExtendableValidator(t *testing.T) {
	v := NewDefaultValidator()

	// By default, query components are allowed (RFC 8707 Section 2 MAY)
	assert.NoError(t, v.ValidateResource("https://api.example.com/v1?tenant=acme"))

	// Disallowing query components (RFC 8707 Section 2 SHOULD NOT)
	v.SetAllowQuery(false)
	assert.ErrorIs(t, v.ValidateResource("https://api.example.com/v1?tenant=acme"), ErrResourceQueryNotAllowed)
	assert.NoError(t, v.ValidateResource("https://api.example.com/v1"))

	// Registering allowed target resources
	v.RegisterAllowedResources("https://api.example.com/v1", "https://billing.example.com/")
	assert.Equal(t, []string{"https://api.example.com/v1", "https://billing.example.com/"}, v.AllowedResources())
	assert.True(t, v.IsValidResource("HTTPS://API.EXAMPLE.COM/v1"))
	assert.ErrorIs(t, v.ValidateResource("https://unknown.example.com/"), ErrUnrecognizedResource)

	// Injecting a custom ResourceVerifier (e.g., enforcing https scheme only)
	v.RegisterVerifierFunc("https-only", func(resource string) bool {
		return strings.HasPrefix(strings.ToLower(resource), "https://")
	})
	v.RegisterAllowedResources("http://legacy.example.com/")
	assert.ErrorIs(t, v.ValidateResource("http://legacy.example.com/"), ErrResourceVerifierRejected)

	v.RemoveVerifier("https-only")
	assert.NoError(t, v.ValidateResource("http://legacy.example.com/"))

	// Validate AuthorizationRequest & TokenRequest
	assert.NoError(t, v.ValidateAuthorizationRequest(AuthorizationRequest{
		Resources: Resources{"https://api.example.com/v1"},
	}))
	assert.ErrorIs(t, v.ValidateTokenRequest(TokenRequest{
		Resources: Resources{"https://api.example.com/v1", "https://bad.example.com/#frag"},
	}), ErrInvalidResourceURI)
}


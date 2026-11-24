package rfc8707

import (
	"errors"
	"net/url"
	"sort"
	"strings"
)

// Standard errors returned during RFC 8707 resource indicator validation.
// Reference: RFC 8707, Sections 2, 2.1, 2.2 & 6.2
var (
	ErrEmptyResource            = errors.New("resource parameter must not be empty")
	ErrInvalidResourceURI       = errors.New("resource must be a valid absolute URI without a fragment component")
	ErrResourceQueryNotAllowed  = errors.New("resource URI must not include a query component")
	ErrUnrecognizedResource     = errors.New("requested resource is unknown or not permitted")
	ErrResourceVerifierRejected = errors.New("requested resource was rejected by verifier")
)

// DefaultValidator is the default RFC 8707 Validator instance enforcing standard absolute-URI syntax.
// Reference: RFC 8707, Section 2
var DefaultValidator = NewDefaultValidator()

// NewDefaultValidator creates a new Validator with standard RFC 8707 behavior
// (allowing query components per RFC 8707 Section 2 MAY and accepting any syntactically valid absolute-URI).
// Reference: RFC 8707, Section 2
func NewDefaultValidator() *Validator {
	return &Validator{
		allowQuery:       true,
		allowedResources: make(map[string]struct{}),
		verifiers:        make(map[string]ResourceVerifier),
	}
}

// NewValidator creates a new Validator initialized with the given custom verifiers map.
func NewValidator(verifiers map[string]ResourceVerifier) *Validator {
	v := NewDefaultValidator()
	for name, verifier := range verifiers {
		if name != "" && verifier != nil {
			v.verifiers[name] = verifier
		}
	}
	return v
}

// SetAllowQuery configures whether resource URIs are allowed to include a query component.
// RFC 8707 Section 2 states a resource URI "MAY include a query component" and "SHOULD NOT include a query component".
// Reference: RFC 8707, Section 2
func (v *Validator) SetAllowQuery(allow bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.allowQuery = allow
}

// RegisterVerifier registers or replaces a named custom ResourceVerifier.
// Reference: RFC 8707, Section 2
func (v *Validator) RegisterVerifier(name string, verifier ResourceVerifier) {
	if name == "" || verifier == nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.verifiers == nil {
		v.verifiers = make(map[string]ResourceVerifier)
	}
	v.verifiers[name] = verifier
}

// RegisterVerifierFunc registers a named VerifierFunc on the Validator.
// Reference: RFC 8707, Section 2
func (v *Validator) RegisterVerifierFunc(name string, fn VerifierFunc) {
	if fn == nil {
		return
	}
	v.RegisterVerifier(name, fn)
}

// RemoveVerifier removes a named ResourceVerifier from the Validator.
func (v *Validator) RemoveVerifier(name string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.verifiers, name)
}

// RegisterAllowedResources registers one or more target resource URIs as recognized by the Authorization Server.
// When at least one allowed resource is registered, ValidateResource enforces that requested resources
// match one of the registered allowed resources.
// Reference: RFC 8707, Sections 2, 2.1 & 2.2
func (v *Validator) RegisterAllowedResources(resources ...string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.allowedResources == nil {
		v.allowedResources = make(map[string]struct{})
	}
	for _, res := range resources {
		if res == "" {
			continue
		}
		norm, err := NormalizeResourceURI(res)
		if err != nil {
			norm = res
		}
		v.allowedResources[norm] = struct{}{}
	}
}

// AllowedResources returns the sorted list of registered allowed resource URIs.
func (v *Validator) AllowedResources() []string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]string, 0, len(v.allowedResources))
	for res := range v.allowedResources {
		out = append(out, res)
	}
	sort.Strings(out)
	return out
}

// ValidateResource validates a single resource indicator URI against RFC 8707 Section 2 syntax rules,
// query policy, allowed resources (if configured), and all injected custom verifiers.
// Reference: RFC 8707, Section 2
func (v *Validator) ValidateResource(resource string) error {
	if resource == "" {
		return ErrEmptyResource
	}
	if !IsValidResourceURI(resource) {
		return ErrInvalidResourceURI
	}

	v.mu.RLock()
	allowQuery := v.allowQuery
	hasAllowList := len(v.allowedResources) > 0
	var inAllowList bool
	if hasAllowList {
		norm, err := NormalizeResourceURI(resource)
		if err != nil {
			norm = resource
		}
		_, inAllowList = v.allowedResources[norm]
	}
	verifiers := make([]ResourceVerifier, 0, len(v.verifiers))
	for _, verifier := range v.verifiers {
		verifiers = append(verifiers, verifier)
	}
	v.mu.RUnlock()

	if !allowQuery && HasQueryComponent(resource) {
		return ErrResourceQueryNotAllowed
	}
	if hasAllowList && !inAllowList {
		return ErrUnrecognizedResource
	}
	for _, verifier := range verifiers {
		if !verifier.VerifyResource(resource) {
			return ErrResourceVerifierRejected
		}
	}
	return nil
}

// IsValidResource returns true if ValidateResource(resource) succeeds.
// Reference: RFC 8707, Section 2
func (v *Validator) IsValidResource(resource string) bool {
	return v.ValidateResource(resource) == nil
}

// ValidateResources validates a slice of resource indicator URIs.
// Reference: RFC 8707, Section 2
func (v *Validator) ValidateResources(resources []string) error {
	for _, res := range resources {
		if err := v.ValidateResource(res); err != nil {
			return err
		}
	}
	return nil
}

// ValidateAuthorizationRequest validates the resource parameters of an OAuth 2.0 Authorization Request.
// Reference: RFC 8707, Section 2.1
func (v *Validator) ValidateAuthorizationRequest(req AuthorizationRequest) error {
	return v.ValidateResources(req.Resources)
}

// ValidateTokenRequest validates the resource parameters of an OAuth 2.0 Access Token Request.
// Reference: RFC 8707, Section 2.2
func (v *Validator) ValidateTokenRequest(req TokenRequest) error {
	return v.ValidateResources(req.Resources)
}

// IsValidResourceURI checks whether rawURI conforms to RFC 8707 Section 2 and RFC 3986 Section 4.3:
//   - MUST be a valid absolute-URI: scheme ":" hier-part [ "?" query ]
//   - MAY include a query component
//   - MUST NOT include a fragment component (no '#' character allowed)
//
// Reference: RFC 8707, Section 2 & RFC 3986, Section 4.3
func IsValidResourceURI(rawURI string) bool {
	if rawURI == "" {
		return false
	}

	// Reject control characters, spaces, and any fragment separator '#' (RFC 8707 Section 2).
	for i := 0; i < len(rawURI); i++ {
		c := rawURI[i]
		if c <= 0x20 || c >= 0x7F || c == '#' {
			return false
		}
	}

	colonIdx := strings.IndexByte(rawURI, ':')
	if colonIdx <= 0 {
		return false
	}
	scheme := rawURI[:colonIdx]
	if !isValidScheme(scheme) {
		return false
	}

	rest := rawURI[colonIdx+1:]
	if rest == "" {
		return false
	}

	u, err := url.Parse(rawURI)
	if err != nil || u.Scheme == "" || u.Fragment != "" {
		return false
	}

	// If hier-part starts with "//", it uses an authority component and MUST have a non-empty host.
	if strings.HasPrefix(rest, "//") {
		if u.Host == "" {
			return false
		}
		return true
	}

	// Otherwise, hier-part must be non-empty (path-abempty / path-absolute / path-rootless / opaque).
	return u.Opaque != "" || u.Path != ""
}

// AreValidResourceURIs checks that the slice is non-empty and all URIs satisfy IsValidResourceURI.
// Reference: RFC 8707, Section 2
func AreValidResourceURIs(uris []string) bool {
	if len(uris) == 0 {
		return false
	}
	for _, u := range uris {
		if !IsValidResourceURI(u) {
			return false
		}
	}
	return true
}

// HasQueryComponent returns true if the resource URI contains a query component ('?').
// Reference: RFC 8707, Section 2
func HasQueryComponent(rawURI string) bool {
	return strings.Contains(rawURI, "?")
}

// NormalizeResourceURI normalizes the scheme and host of a valid resource URI to lowercase
// per RFC 3986 Section 6.2.2.1 while preserving path and query case sensitivity.
// Reference: RFC 8707, Section 2 & RFC 3986, Section 6.2.2.1
func NormalizeResourceURI(rawURI string) (string, error) {
	if !IsValidResourceURI(rawURI) {
		return "", ErrInvalidResourceURI
	}
	u, err := url.Parse(rawURI)
	if err != nil {
		return "", ErrInvalidResourceURI
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	return u.String(), nil
}

// IsSubset checks whether every resource in requested is present in granted (using normalized URI comparison).
// Useful for verifying resource downscoping at the Token Endpoint during authorization_code or refresh_token grants.
// Reference: RFC 8707, Sections 2.2 & 3
func IsSubset(requested []string, granted []string) bool {
	if len(requested) == 0 {
		return true
	}
	grantedRes := Resources(granted)
	for _, req := range requested {
		if !grantedRes.Contains(req) {
			return false
		}
	}
	return true
}

// isValidScheme checks RFC 3986 Section 3.1 ABNF:
// scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
func isValidScheme(s string) bool {
	if len(s) == 0 {
		return false
	}
	if !isAlpha(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !isAlpha(c) && !isDigit(c) && c != '+' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

func isAlpha(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}


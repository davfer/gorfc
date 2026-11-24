package rfc8707

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
)

// RFC 8707 Parameter Names registered in the IANA "OAuth Parameters" Registry.
// Reference: RFC 8707, Section 2 & Section 6.1
const (
	// ParamResource indicates the target service or resource where the client intends to use the requested token.
	// Reference: RFC 8707, Section 2
	ParamResource = "resource"
)

// RFC 8707 Error Codes registered in the IANA "OAuth Extensions Error Registry".
// Reference: RFC 8707, Section 2 & Section 6.2
const (
	// ErrInvalidTarget indicates that the requested resource is invalid, missing, unknown, or malformed.
	// Reference: RFC 8707, Sections 2, 2.1, 2.2 & 6.2
	ErrInvalidTarget = "invalid_target"
)

// Resources is a custom type to handle the "resource" parameter, which RFC 8707 allows
// to be specified as either a single URI string or multiple URI strings.
// Reference: RFC 8707, Section 2
type Resources []string

// UnmarshalJSON parses either a single JSON string (`"resource": "https://api.example.com"`)
// or an array of JSON strings (`"resource": ["https://api.example.com", "https://db.example.com"]`)
// into a Resources slice.
// Reference: RFC 8707, Section 2
func (r *Resources) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*r = []string{single}
		return nil
	}

	var multiple []string
	if err := json.Unmarshal(data, &multiple); err != nil {
		return fmt.Errorf("rfc8707: resource parameter is neither string nor array of strings")
	}

	*r = multiple
	return nil
}

// MarshalJSON serializes a single resource as a JSON string and multiple resources as a JSON array.
// Reference: RFC 8707, Section 2
func (r Resources) MarshalJSON() ([]byte, error) {
	if len(r) == 1 {
		return json.Marshal(r[0])
	}
	return json.Marshal([]string(r))
}

// Contains checks whether the target resource URI is present in the Resources slice
// (using normalized RFC 3986 URI comparison).
// Reference: RFC 8707, Section 2
func (r Resources) Contains(target string) bool {
	normTarget, err := NormalizeResourceURI(target)
	if err != nil {
		normTarget = target
	}
	for _, item := range r {
		normItem, err := NormalizeResourceURI(item)
		if err != nil {
			normItem = item
		}
		if normItem == normTarget {
			return true
		}
	}
	return false
}

// Unique returns a new Resources slice with duplicate resource URIs removed while preserving order.
func (r Resources) Unique() Resources {
	if len(r) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(r))
	out := make(Resources, 0, len(r))
	for _, item := range r {
		key, err := NormalizeResourceURI(item)
		if err != nil {
			key = item
		}
		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			out = append(out, item)
		}
	}
	return out
}

// AuthorizationRequest represents the resource indicator parameter(s) for an OAuth 2.0 Authorization Request.
// Reference: RFC 8707, Sections 2 & 2.1
type AuthorizationRequest struct {
	Resources Resources `json:"resource,omitempty"`
}

// TokenRequest represents the resource indicator parameter(s) for an OAuth 2.0 Access Token Request.
// Reference: RFC 8707, Sections 2 & 2.2
type TokenRequest struct {
	Resources Resources `json:"resource,omitempty"`
}

// ParseResourcesFromValues extracts all "resource" parameter values from url.Values (query or form parameters).
// Reference: RFC 8707, Sections 2, 2.1 & 2.2
func ParseResourcesFromValues(values url.Values) Resources {
	if values == nil {
		return nil
	}
	raw, ok := values[ParamResource]
	if !ok || len(raw) == 0 {
		return nil
	}
	res := make(Resources, len(raw))
	copy(res, raw)
	return res
}

// ParseResourcesFromRequest parses the HTTP request form/query and extracts all "resource" parameter values.
// Reference: RFC 8707, Sections 2, 2.1 & 2.2
func ParseResourcesFromRequest(r *http.Request) (Resources, error) {
	if r == nil {
		return nil, nil
	}
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	return ParseResourcesFromValues(r.Form), nil
}

// ResourceVerifier defines the contract for custom resource indicator verification logic
// (e.g., checking against registered resource servers, tenant policies, or scheme restrictions).
// Reference: RFC 8707, Sections 2, 2.1 & 2.2
type ResourceVerifier interface {
	VerifyResource(resource string) bool
}

// VerifierFunc is a function adapter that implements ResourceVerifier.
type VerifierFunc func(resource string) bool

// VerifyResource calls the underlying VerifierFunc.
func (f VerifierFunc) VerifyResource(resource string) bool {
	return f(resource)
}

// Validator is an extendable Resource Indicators (RFC 8707) validator.
// It validates RFC 3986 Section 4.3 absolute-URI syntax rules and allows injecting custom
// ResourceVerifier implementations or allowed resource sets.
// Reference: RFC 8707, Sections 2, 2.1 & 2.2
type Validator struct {
	mu               sync.RWMutex
	allowQuery       bool
	allowedResources map[string]struct{}
	verifiers        map[string]ResourceVerifier
}


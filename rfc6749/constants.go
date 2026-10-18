package rfc6749

import (
	"github.com/davfer/gorfc/iana"
	"github.com/davfer/gorfc/rfc8259"
	"github.com/davfer/gorfc/rfc9110"
)

// Standard HTTP Header names used by RFC 6749 endpoints.
// Reference: RFC 9110, Section 16.3 & RFC 6749, Section 3.2 & 5.1
const (
	// HeaderContentType is the standard HTTP Content-Type header name.
	HeaderContentType = rfc9110.HeaderContentType

	// HeaderCacheControl is the standard HTTP Cache-Control header name.
	HeaderCacheControl = rfc9110.HeaderCacheControl

	// HeaderPragma is the standard HTTP Pragma header name.
	HeaderPragma = rfc9110.HeaderPragma

	// HeaderAuthorization is the standard HTTP Authorization header name.
	HeaderAuthorization = rfc9110.HeaderAuthorization

	// HeaderWWWAuthenticate is the standard HTTP WWW-Authenticate header name.
	HeaderWWWAuthenticate = rfc9110.HeaderWWWAuthenticate
)

// Standard Media Types used by RFC 6749 endpoints.
const (
	// ContentTypeJSON is the HTTP Content-Type header value for token responses.
	// Reference: RFC 6749, Section 5.1
	ContentTypeJSON = "application/json;charset=UTF-8"

	// ContentTypeFormUrlEncoded is the HTTP Content-Type header value for form-encoded requests.
	// Reference: RFC 6749, Section 3.2 & Section 4.1.3 (IANA Registry)
	ContentTypeFormUrlEncoded = iana.MediaTypeFormUrlEncoded

	// ContentTypeJSONOnly is the standard application/json media type.
	// Reference: RFC 8259 & IANA Media Types Registry
	ContentTypeJSONOnly = rfc8259.MediaTypeJSON
)

// Header field values specified by RFC 6749.
const (
	// CacheControlNoStore represents the "no-store" Cache-Control directive.
	// Reference: RFC 6749, Section 5.1
	CacheControlNoStore = "no-store"

	// PragmaNoCache represents the "no-cache" Pragma directive.
	// Reference: RFC 6749, Section 5.1
	PragmaNoCache = "no-cache"
)

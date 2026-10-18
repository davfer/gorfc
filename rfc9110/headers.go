package rfc9110

// Standard HTTP Header names defined by RFC 9110 (HTTP Semantics).
// Reference: RFC 9110, Section 16.3 & IANA HTTP Field Name Registry
const (
	// HeaderContentType is the standard Content-Type header name.
	// Reference: RFC 9110, Section 8.3
	HeaderContentType = "Content-Type"

	// HeaderCacheControl is the standard Cache-Control header name.
	// Reference: RFC 9110, Section 13.1.2
	HeaderCacheControl = "Cache-Control"

	// HeaderPragma is the standard Pragma header name.
	// Reference: RFC 9110, Section 13.1.3
	HeaderPragma = "Pragma"

	// HeaderAuthorization is the standard Authorization header name.
	// Reference: RFC 9110, Section 11.6.2
	HeaderAuthorization = "Authorization"

	// HeaderWWWAuthenticate is the standard WWW-Authenticate header name.
	// Reference: RFC 9110, Section 11.6.1
	HeaderWWWAuthenticate = "WWW-Authenticate"

	// HeaderLocation is the standard Location header name.
	// Reference: RFC 9110, Section 10.2.2
	HeaderLocation = "Location"
)

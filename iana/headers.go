package iana

import "github.com/davfer/gorfc/rfc9110"

// Standard HTTP Header names registered in the IANA HTTP Field Name Registry.
// Reference: RFC 9110, Section 16.3 & IANA HTTP Field Name Registry
const (
	HeaderContentType     = rfc9110.HeaderContentType
	HeaderCacheControl    = rfc9110.HeaderCacheControl
	HeaderPragma          = rfc9110.HeaderPragma
	HeaderAuthorization   = rfc9110.HeaderAuthorization
	HeaderWWWAuthenticate = rfc9110.HeaderWWWAuthenticate
	HeaderLocation        = rfc9110.HeaderLocation
)

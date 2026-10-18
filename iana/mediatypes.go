package iana

import (
	"github.com/davfer/gorfc/rfc7517"
	"github.com/davfer/gorfc/rfc7519"
	"github.com/davfer/gorfc/rfc8259"
	"github.com/davfer/gorfc/rfc9101"
)

// Standard MIME Media Types registered in the IANA Media Types Registry.
// Reference: RFC 6838 & IANA Media Types Registry
const (
	// MediaTypeJSON is the MIME type for JSON data.
	// Reference: RFC 8259, Section 11 & IANA Media Types Registry
	MediaTypeJSON = rfc8259.MediaTypeJSON

	// MediaTypeFormUrlEncoded is the MIME type for URL-encoded form data.
	// Reference: IANA Media Types Registry & W3C HTML Specification
	MediaTypeFormUrlEncoded = "application/x-www-form-urlencoded"

	// MediaTypeJWKSetJSON is the MIME type for JWK Sets.
	// Reference: RFC 7517, Section 8.5 & IANA Media Types Registry
	MediaTypeJWKSetJSON = rfc7517.MediaTypeJWKSetJSON

	// MediaTypeJWKJSON is the MIME type for a single JWK.
	// Reference: RFC 7517, Section 8.1 & IANA Media Types Registry
	MediaTypeJWKJSON = rfc7517.MediaTypeJWKJSON

	// MediaTypeJWT is the MIME type for JSON Web Tokens.
	// Reference: RFC 7519, Section 10.3 & IANA Media Types Registry
	MediaTypeJWT = rfc7519.MediaTypeJWT

	// MediaTypeOAuthAuthzReqJWT is the MIME type for OAuth Secured Authorization Requests (JAR).
	// Reference: RFC 9101, Section 10.1 & IANA Media Types Registry
	MediaTypeOAuthAuthzReqJWT = rfc9101.MediaTypeOAuthAuthzReqJWT
)

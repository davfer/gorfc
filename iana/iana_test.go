package iana_test

import (
	"testing"

	"github.com/davfer/gorfc/iana"
)

func TestHeaders(t *testing.T) {
	tests := []struct {
		got  string
		want string
	}{
		{iana.HeaderContentType, "Content-Type"},
		{iana.HeaderCacheControl, "Cache-Control"},
		{iana.HeaderPragma, "Pragma"},
		{iana.HeaderAuthorization, "Authorization"},
		{iana.HeaderWWWAuthenticate, "WWW-Authenticate"},
		{iana.HeaderLocation, "Location"},
	}

	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("expected %s, got %s", tt.want, tt.got)
		}
	}
}

func TestMediaTypes(t *testing.T) {
	tests := []struct {
		got  string
		want string
	}{
		{iana.MediaTypeJSON, "application/json"},
		{iana.MediaTypeFormUrlEncoded, "application/x-www-form-urlencoded"},
		{iana.MediaTypeJWKSetJSON, "application/jwk-set+json"},
		{iana.MediaTypeJWKJSON, "application/jwk+json"},
		{iana.MediaTypeJWT, "application/jwt"},
		{iana.MediaTypeOAuthAuthzReqJWT, "application/oauth-authz-req+jwt"},
	}

	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("expected %s, got %s", tt.want, tt.got)
		}
	}
}

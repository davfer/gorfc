package rfc9110_test

import (
	"testing"

	"github.com/davfer/gorfc/rfc9110"
)

func TestHeaders(t *testing.T) {
	tests := []struct {
		got  string
		want string
	}{
		{rfc9110.HeaderContentType, "Content-Type"},
		{rfc9110.HeaderCacheControl, "Cache-Control"},
		{rfc9110.HeaderPragma, "Pragma"},
		{rfc9110.HeaderAuthorization, "Authorization"},
		{rfc9110.HeaderWWWAuthenticate, "WWW-Authenticate"},
		{rfc9110.HeaderLocation, "Location"},
	}

	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("expected %s, got %s", tt.want, tt.got)
		}
	}
}

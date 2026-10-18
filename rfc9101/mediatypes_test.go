package rfc9101_test

import (
	"testing"

	"github.com/davfer/gorfc/rfc9101"
)

func TestMediaTypes(t *testing.T) {
	if rfc9101.MediaTypeOAuthAuthzReqJWT != "application/oauth-authz-req+jwt" {
		t.Errorf("expected application/oauth-authz-req+jwt, got %s", rfc9101.MediaTypeOAuthAuthzReqJWT)
	}
}

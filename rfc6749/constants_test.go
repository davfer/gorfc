package rfc6749_test

import (
	"testing"

	"github.com/davfer/gorfc/rfc6749"
)

func TestConstants(t *testing.T) {
	if rfc6749.HeaderContentType != "Content-Type" {
		t.Errorf("expected Content-Type, got %s", rfc6749.HeaderContentType)
	}
	if rfc6749.HeaderCacheControl != "Cache-Control" {
		t.Errorf("expected Cache-Control, got %s", rfc6749.HeaderCacheControl)
	}
	if rfc6749.HeaderPragma != "Pragma" {
		t.Errorf("expected Pragma, got %s", rfc6749.HeaderPragma)
	}
	if rfc6749.ContentTypeJSON != "application/json;charset=UTF-8" {
		t.Errorf("expected application/json;charset=UTF-8, got %s", rfc6749.ContentTypeJSON)
	}
	if rfc6749.ContentTypeFormUrlEncoded != "application/x-www-form-urlencoded" {
		t.Errorf("expected application/x-www-form-urlencoded, got %s", rfc6749.ContentTypeFormUrlEncoded)
	}
	if rfc6749.CacheControlNoStore != "no-store" {
		t.Errorf("expected no-store, got %s", rfc6749.CacheControlNoStore)
	}
	if rfc6749.PragmaNoCache != "no-cache" {
		t.Errorf("expected no-cache, got %s", rfc6749.PragmaNoCache)
	}
}

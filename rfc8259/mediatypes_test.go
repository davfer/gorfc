package rfc8259_test

import (
	"testing"

	"github.com/davfer/gorfc/rfc8259"
)

func TestMediaTypes(t *testing.T) {
	if rfc8259.MediaTypeJSON != "application/json" {
		t.Errorf("expected application/json, got %s", rfc8259.MediaTypeJSON)
	}
}

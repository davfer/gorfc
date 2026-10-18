package identity_test

import (
	"context"
	"testing"

	"github.com/davfer/gorfc/oidc/identity"
)

func TestDefaultSession(t *testing.T) {
	claims := &identity.StandardClaims{Name: "Workload-Service-1"}
	sess := &identity.DefaultSession{
		Sub:        "spiffe://example.com/ns/default/sa/workload-1",
		AuthT:      1700000000,
		ACRVal:     "mtls",
		AMRVal:     []string{"tls"},
		UserClaims: claims,
	}

	if sess.Subject() != "spiffe://example.com/ns/default/sa/workload-1" {
		t.Errorf("unexpected subject: %s", sess.Subject())
	}
	if identity.GetAuthTime(sess) != 1700000000 {
		t.Errorf("unexpected auth_time: %d", identity.GetAuthTime(sess))
	}
	if identity.GetACR(sess) != "mtls" {
		t.Errorf("unexpected ACR: %s", identity.GetACR(sess))
	}
	if len(identity.GetAMR(sess)) != 1 {
		t.Errorf("unexpected AMR length: %d", len(identity.GetAMR(sess)))
	}
	if identity.GetClaims(sess).Name != "Workload-Service-1" {
		t.Errorf("unexpected claims name: %s", identity.GetClaims(sess).Name)
	}

	ctx := identity.WithContext(context.Background(), sess)
	fromCtx, ok := identity.FromContext(ctx)
	if !ok || fromCtx.Subject() != sess.Subject() {
		t.Errorf("context injection failed")
	}
}

package oidc_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/davfer/gorfc/oidc"
)

func TestBuilderAndServer_DiscoveryEndpoint(t *testing.T) {
	builder := oidc.NewBuilder()
	builder.SetIssuer("https://auth.example.com")

	provider, err := builder.Build()
	if err != nil {
		t.Fatalf("failed to build provider: %v", err)
	}

	if provider.Metadata().Issuer != "https://auth.example.com" {
		t.Errorf("expected issuer https://auth.example.com, got %s", provider.Metadata().Issuer)
	}

	server := oidc.NewServer(provider)

	req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	server.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for discovery endpoint, got %d", w.Code)
	}

	var meta oidc.ProviderMetadata
	if err := json.NewDecoder(w.Body).Decode(&meta); err != nil {
		t.Fatalf("failed to decode discovery metadata: %v", err)
	}

	if meta.Issuer != "https://auth.example.com" {
		t.Errorf("expected issuer https://auth.example.com in JSON response, got %s", meta.Issuer)
	}
	if meta.AuthorizationEndpoint != "https://auth.example.com/authorize" {
		t.Errorf("expected authorization_endpoint https://auth.example.com/authorize, got %s", meta.AuthorizationEndpoint)
	}
}

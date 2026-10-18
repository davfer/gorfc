package oidc

import (
	"net/http"
)

// Server binds an OpenID Connect Provider to an http.ServeMux or HTTP handler.
type Server struct {
	provider *Provider
	mux      *http.ServeMux
}

// NewServer creates a new Server instance for an OpenID Connect Provider.
func NewServer(provider *Provider) *Server {
	mux := http.NewServeMux()
	s := &Server{
		provider: provider,
		mux:      mux,
	}
	s.registerRoutes()
	return s
}

// registerRoutes mounts OIDC standard routes on the mux.
func (s *Server) registerRoutes() {
	if s.provider == nil {
		return
	}

	if s.provider.DiscoveryHandler() != nil {
		s.mux.Handle(DiscoveryPath, s.provider.DiscoveryHandler())
	}

	if s.provider.AuthorizeHandler() != nil {
		s.mux.Handle("/authorize", s.provider.AuthorizeHandler())
	}

	if s.provider.TokenHandler() != nil {
		s.mux.Handle("/token", s.provider.TokenHandler())
	}

	if s.provider.UserInfoHandler() != nil {
		s.mux.Handle("/userinfo", s.provider.UserInfoHandler())
	}

	if s.provider.JWKSHandler() != nil {
		s.mux.Handle("/jwks", s.provider.JWKSHandler())
	}
}

// ServeHTTP implements http.Handler for the OIDC Server.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

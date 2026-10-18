package jwks

import (
	"encoding/json"
	"net/http"

	"github.com/davfer/gorfc/rfc7517"
	"github.com/davfer/gorfc/rfc9110"
)

type ErrorHandler func(http.ResponseWriter, error)

// Handler serves the JWKS endpoint using a KeyProvider.
type Handler struct {
	provider     KeyProvider
	errorHandler ErrorHandler
}

// NewHandler creates a new JWKS HTTP handler.
func NewHandler(provider KeyProvider, errorHandler ErrorHandler) *Handler {
	if errorHandler == nil {
		errorHandler = func(w http.ResponseWriter, err error) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
	return &Handler{
		provider:     provider,
		errorHandler: errorHandler,
	}
}

// ServeHTTP implements the http.Handler interface.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	keys, err := h.provider.GetKeys(r.Context())
	if err != nil {
		h.errorHandler(w, err)
		return
	}

	if keys == nil {
		keys = make([]rfc7517.JWK, 0)
	}

	response := rfc7517.JWKS{
		Keys: keys,
	}

	// Set the correct content type as per RFC 7517 Section 8.5.
	w.Header().Set(rfc9110.HeaderContentType, rfc7517.ContentTypeJWKSetJSON)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.errorHandler(w, err)
	}
}

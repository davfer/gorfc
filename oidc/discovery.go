package oidc

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/davfer/gorfc/rfc6749"
	"github.com/davfer/gorfc/rfc9110"
)

type MetadataProvider func(ctx context.Context) (ProviderMetadata, error)
type ErrorHandler func(http.ResponseWriter, error)

type DiscoveryHandler struct {
	provider     MetadataProvider
	errorHandler ErrorHandler
}

func NewDiscoveryHandler(provider MetadataProvider, errorHandler ErrorHandler) *DiscoveryHandler {
	if errorHandler == nil {
		errorHandler = func(w http.ResponseWriter, err error) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
	return &DiscoveryHandler{
		provider:     provider,
		errorHandler: errorHandler,
	}
}

func (h *DiscoveryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	metadata, err := h.provider(r.Context())
	if err != nil {
		h.errorHandler(w, err)
		return
	}

	w.Header().Set(rfc9110.HeaderContentType, rfc6749.ContentTypeJSONOnly)
	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		h.errorHandler(w, err)
	}
}

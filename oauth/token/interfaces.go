package token

import (
	"context"
	"net/http"

	"github.com/davfer/gorfc/oauth/client"
	"github.com/davfer/gorfc/rfc6749"
)

// ClientAuthenticator abstracts client authentication (e.g., via Basic Auth or POST body).
type ClientAuthenticator interface {
	AuthenticateClient(ctx context.Context, r *http.Request) (client.Client, error)
}

// ErrorHandler manages token error responses conforming to RFC 6749.
type ErrorHandler interface {
	WriteTokenError(w http.ResponseWriter, r *http.Request, errResp rfc6749.ErrorResponse)
}

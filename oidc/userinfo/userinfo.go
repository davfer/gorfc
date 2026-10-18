package userinfo

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/davfer/gorfc/oidc/authorize"
	"github.com/davfer/gorfc/oidc/identity"
	"github.com/davfer/gorfc/rfc9110"
)

// UserInfoRequest is typically sent via Authorization header, but can be form-encoded.
// Reference: OpenID Connect Core 1.0, Section 5.3.1
type UserInfoRequest struct {
	AccessToken string `json:"access_token,omitempty"`
}

// TokenValidator interface parses and validates an Access Token for UserInfo requests.
type TokenValidator interface {
	ValidateAccessToken(ctx context.Context, tokenStr string) (subject string, scopes []string, err error)
}

// UserInfoHandler handles HTTP requests for the OpenID Connect UserInfo Endpoint.
// Reference: OpenID Connect Core 1.0, Section 5.3
type UserInfoHandler struct {
	tokenValidator   TokenValidator
	userInfoProvider identity.UserInfoProvider
	errorHandler     func(w http.ResponseWriter, statusCode int, errCode string, errDesc string)
}

// NewUserInfoHandler creates a new UserInfoHandler.
func NewUserInfoHandler(validator TokenValidator, provider identity.UserInfoProvider) *UserInfoHandler {
	return &UserInfoHandler{
		tokenValidator:   validator,
		userInfoProvider: provider,
		errorHandler: func(w http.ResponseWriter, statusCode int, errCode string, errDesc string) {
			w.Header().Set("WWW-Authenticate", `Bearer error="`+errCode+`", error_description="`+errDesc+`"`)
			http.Error(w, errDesc, statusCode)
		},
	}
}

// ServeHTTP implements http.Handler for the UserInfo Endpoint.
func (h *UserInfoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Extract Bearer Token from Authorization Header or Form Body (Section 5.3.1)
	tokenStr := ""
	authHeader := r.Header.Get(rfc9110.HeaderAuthorization)
	if strings.HasPrefix(authHeader, "Bearer ") {
		tokenStr = strings.TrimPrefix(authHeader, "Bearer ")
	} else if r.Method == http.MethodPost {
		_ = r.ParseForm()
		tokenStr = r.FormValue("access_token")
	}

	if tokenStr == "" {
		h.errorHandler(w, http.StatusUnauthorized, "invalid_token", "Access token is required")
		return
	}

	// 2. Validate Access Token
	if h.tokenValidator == nil {
		http.Error(w, "Token Validator Unavailable", http.StatusInternalServerError)
		return
	}

	subject, scopes, err := h.tokenValidator.ValidateAccessToken(r.Context(), tokenStr)
	if err != nil || subject == "" {
		h.errorHandler(w, http.StatusUnauthorized, "invalid_token", "Invalid or expired access token")
		return
	}

	// 3. Fetch UserInfo claims
	if h.userInfoProvider == nil {
		http.Error(w, "UserInfo Provider Unavailable", http.StatusInternalServerError)
		return
	}

	claims, err := h.userInfoProvider.GetUserInfo(r.Context(), subject, scopes)
	if err != nil || claims == nil {
		h.errorHandler(w, http.StatusNotFound, "invalid_request", "UserInfo not found for subject")
		return
	}

	// Ensure sub claim is set (REQUIRED)
	if claims.Subject == "" {
		claims.Subject = subject
	}

	// Filter claims according to granted scopes (Section 5.4)
	filteredClaims := filterClaimsByScope(claims, scopes)

	// 4. Return UserInfo Response (Section 5.3.2)
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(filteredClaims)
}

// Filter claims according to requested/granted scopes (Section 5.4)
func filterClaimsByScope(claims *identity.StandardClaims, scopes []string) *identity.StandardClaims {
	scopeSet := make(map[string]bool)
	for _, s := range scopes {
		scopeSet[s] = true
	}

	res := &identity.StandardClaims{
		Subject: claims.Subject,
	}

	if scopeSet[authorize.ScopeProfile] {
		res.Name = claims.Name
		res.GivenName = claims.GivenName
		res.FamilyName = claims.FamilyName
		res.MiddleName = claims.MiddleName
		res.Nickname = claims.Nickname
		res.PreferredUsername = claims.PreferredUsername
		res.Profile = claims.Profile
		res.Picture = claims.Picture
		res.Website = claims.Website
		res.Gender = claims.Gender
		res.Birthdate = claims.Birthdate
		res.ZoneInfo = claims.ZoneInfo
		res.Locale = claims.Locale
		res.UpdatedAt = claims.UpdatedAt
	}

	if scopeSet[authorize.ScopeEmail] {
		res.Email = claims.Email
		res.EmailVerified = claims.EmailVerified
	}

	if scopeSet[authorize.ScopeAddress] {
		res.Address = claims.Address
	}

	if scopeSet[authorize.ScopePhone] {
		res.PhoneNumber = claims.PhoneNumber
		res.PhoneNumberVerified = claims.PhoneNumberVerified
	}

	return res
}

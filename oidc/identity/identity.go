package identity

import (
	"context"
	"net/http"
)

// StandardClaims represents the standard UserInfo claims.
// Reference: OpenID Connect Core 1.0, Section 5.1
type StandardClaims struct {
	Subject             string        `json:"sub"` // REQUIRED
	Name                string        `json:"name,omitempty"`
	GivenName           string        `json:"given_name,omitempty"`
	FamilyName          string        `json:"family_name,omitempty"`
	MiddleName          string        `json:"middle_name,omitempty"`
	Nickname            string        `json:"nickname,omitempty"`
	PreferredUsername   string        `json:"preferred_username,omitempty"`
	Profile             string        `json:"profile,omitempty"`
	Picture             string        `json:"picture,omitempty"`
	Website             string        `json:"website,omitempty"`
	Email               string        `json:"email,omitempty"`
	EmailVerified       bool          `json:"email_verified,omitempty"`
	Gender              string        `json:"gender,omitempty"`
	Birthdate           string        `json:"birthdate,omitempty"`
	ZoneInfo            string        `json:"zoneinfo,omitempty"`
	Locale              string        `json:"locale,omitempty"`
	PhoneNumber         string        `json:"phone_number,omitempty"`
	PhoneNumberVerified bool          `json:"phone_number_verified,omitempty"`
	Address             *AddressClaim `json:"address,omitempty"`
	UpdatedAt           int64         `json:"updated_at,omitempty"`
}

// AddressClaim represents the address claim within StandardClaims.
// Reference: OpenID Connect Core 1.0, Section 5.1.1
type AddressClaim struct {
	Formatted     string `json:"formatted,omitempty"`
	StreetAddress string `json:"street_address,omitempty"`
	Locality      string `json:"locality,omitempty"`
	Region        string `json:"region,omitempty"`
	PostalCode    string `json:"postal_code,omitempty"`
	Country       string `json:"country,omitempty"`
}

// Session represents the base interface for an authenticated OIDC subject/identity session.
// Reference: OpenID Connect Core 1.0, Section 2 & Section 3.1.2.1
type Session interface {
	Subject() string
}

// AuthenticatedSession is an optional composition interface for sessions tracking an authentication timestamp.
type AuthenticatedSession interface {
	Session
	AuthTime() int64
}

// ACRSession is an optional composition interface for sessions carrying ACR and AMR claims.
type ACRSession interface {
	Session
	ACR() string
	AMR() []string
}

// ClaimsSession is an optional composition interface for sessions carrying StandardClaims.
type ClaimsSession interface {
	Session
	Claims() *StandardClaims
}

// DefaultSession provides a concrete struct implementing all Session composition interfaces for convenience.
type DefaultSession struct {
	Sub        string          `json:"sub"`
	AuthT      int64           `json:"auth_time,omitempty"`
	ACRVal     string          `json:"acr,omitempty"`
	AMRVal     []string        `json:"amr,omitempty"`
	UserClaims *StandardClaims `json:"claims,omitempty"`
}

func (s *DefaultSession) Subject() string          { return s.Sub }
func (s *DefaultSession) AuthTime() int64         { return s.AuthT }
func (s *DefaultSession) ACR() string             { return s.ACRVal }
func (s *DefaultSession) AMR() []string           { return s.AMRVal }
func (s *DefaultSession) Claims() *StandardClaims { return s.UserClaims }

// GetAuthTime returns the auth_time for a Session, or 0 if not implemented.
func GetAuthTime(s Session) int64 {
	if a, ok := s.(AuthenticatedSession); ok {
		return a.AuthTime()
	}
	return 0
}

// GetACR returns the ACR value for a Session, or "" if not implemented.
func GetACR(s Session) string {
	if a, ok := s.(ACRSession); ok {
		return a.ACR()
	}
	return ""
}

// GetAMR returns the AMR values for a Session, or nil if not implemented.
func GetAMR(s Session) []string {
	if a, ok := s.(ACRSession); ok {
		return a.AMR()
	}
	return nil
}

// GetClaims returns the StandardClaims for a Session, or nil if not implemented.
func GetClaims(s Session) *StandardClaims {
	if c, ok := s.(ClaimsSession); ok {
		return c.Claims()
	}
	return nil
}

// IdentityProvider is the interface for looking up or authenticating a session during authorization.
// Reference: OpenID Connect Core 1.0, Section 3.1.2.1
type IdentityProvider interface {
	// GetSession retrieves the active identity session for the current request.
	// Returns nil if the identity is not authenticated.
	GetSession(ctx context.Context, r *http.Request) (Session, error)
}

// UserInfoProvider is the interface for retrieving UserInfo claims for a subject.
// Reference: OpenID Connect Core 1.0, Section 5.3
type UserInfoProvider interface {
	// GetUserInfo retrieves claims for the given subject filtered by granted scopes.
	GetUserInfo(ctx context.Context, subject string, scopes []string) (*StandardClaims, error)
}

type sessionKey struct{}

// WithContext returns a new context carrying the given Session interface.
func WithContext(ctx context.Context, session Session) context.Context {
	return context.WithValue(ctx, sessionKey{}, session)
}

// FromContext extracts the Session interface from context, if present.
func FromContext(ctx context.Context) (Session, bool) {
	session, ok := ctx.Value(sessionKey{}).(Session)
	return session, ok
}

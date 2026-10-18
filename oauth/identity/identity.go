package identity

// Identity represents an authenticated principal (e.g. user, service account, or machine).
type Identity interface {
	Subject() string
}

// SimpleIdentity provides a basic implementation of Identity wrapping a subject string.
type SimpleIdentity struct {
	Sub string `json:"sub"`
}

func (s SimpleIdentity) Subject() string {
	return s.Sub
}

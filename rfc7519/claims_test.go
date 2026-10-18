package rfc7519_test

import (
	"testing"

	"github.com/davfer/gorfc/rfc7519"
	"github.com/stretchr/testify/assert"
)

func TestClaimConstants(t *testing.T) {
	tests := []struct {
		constant string
		expected string
	}{
		// RFC 7519 Standard Registered Claims
		{constant: rfc7519.ClaimIss, expected: "iss"},
		{constant: rfc7519.ClaimSub, expected: "sub"},
		{constant: rfc7519.ClaimAud, expected: "aud"},
		{constant: rfc7519.ClaimExp, expected: "exp"},
		{constant: rfc7519.ClaimNbf, expected: "nbf"},
		{constant: rfc7519.ClaimIat, expected: "iat"},
		{constant: rfc7519.ClaimJti, expected: "jti"},

		// OIDC Standard Claims
		{constant: rfc7519.ClaimName, expected: "name"},
		{constant: rfc7519.ClaimGivenName, expected: "given_name"},
		{constant: rfc7519.ClaimFamilyName, expected: "family_name"},
		{constant: rfc7519.ClaimMiddleName, expected: "middle_name"},
		{constant: rfc7519.ClaimNickname, expected: "nickname"},
		{constant: rfc7519.ClaimPreferredUsername, expected: "preferred_username"},
		{constant: rfc7519.ClaimProfile, expected: "profile"},
		{constant: rfc7519.ClaimPicture, expected: "picture"},
		{constant: rfc7519.ClaimWebsite, expected: "website"},
		{constant: rfc7519.ClaimEmail, expected: "email"},
		{constant: rfc7519.ClaimEmailVerified, expected: "email_verified"},
		{constant: rfc7519.ClaimGender, expected: "gender"},
		{constant: rfc7519.ClaimBirthdate, expected: "birthdate"},
		{constant: rfc7519.ClaimZoneinfo, expected: "zoneinfo"},
		{constant: rfc7519.ClaimLocale, expected: "locale"},
		{constant: rfc7519.ClaimPhoneNumber, expected: "phone_number"},
		{constant: rfc7519.ClaimPhoneNumberVerified, expected: "phone_number_verified"},
		{constant: rfc7519.ClaimAddress, expected: "address"},
		{constant: rfc7519.ClaimUpdatedAt, expected: "updated_at"},
		{constant: rfc7519.ClaimAzp, expected: "azp"},
		{constant: rfc7519.ClaimNonce, expected: "nonce"},
		{constant: rfc7519.ClaimAuthTime, expected: "auth_time"},
		{constant: rfc7519.ClaimAtHash, expected: "at_hash"},
		{constant: rfc7519.ClaimCHash, expected: "c_hash"},
		{constant: rfc7519.ClaimAcr, expected: "acr"},
		{constant: rfc7519.ClaimAmr, expected: "amr"},
		{constant: rfc7519.ClaimSubJwk, expected: "sub_jwk"},

		// DPoP RFC 9449 & OAuth Claims
		{constant: rfc7519.ClaimHtm, expected: "htm"},
		{constant: rfc7519.ClaimHtu, expected: "htu"},
		{constant: rfc7519.ClaimAth, expected: "ath"},
		{constant: rfc7519.ClaimCnf, expected: "cnf"},
		{constant: rfc7519.ClaimClientId, expected: "client_id"},
		{constant: rfc7519.ClaimScope, expected: "scope"},
		{constant: rfc7519.ClaimAct, expected: "act"},
		{constant: rfc7519.ClaimMayAct, expected: "may_act"},
		{constant: rfc7519.ClaimRoles, expected: "roles"},
		{constant: rfc7519.ClaimGroups, expected: "groups"},
		{constant: rfc7519.ClaimEntitlements, expected: "entitlements"},

		// OpenID Federation & Identity Assurance
		{constant: rfc7519.ClaimJwks, expected: "jwks"},
		{constant: rfc7519.ClaimMetadata, expected: "metadata"},
		{constant: rfc7519.ClaimVerifiedClaims, expected: "verified_claims"},
		{constant: rfc7519.ClaimPlaceOfBirth, expected: "place_of_birth"},
		{constant: rfc7519.ClaimNationalities, expected: "nationalities"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}
}

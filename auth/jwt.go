package auth

import (
	"context"
	"errors"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var (
	ErrEmptyIssuer   = errors.New("issuer cannot be empty")
	ErrEmptyAudience = errors.New("audience cannot be empty")
	ErrJwksFetch     = errors.New("failed to fetch JWKS")
)

const (
	// This is a custom claim, used to indicate whether the user's email address
	// has been verified. The claim is validated to enforce that only verified
	// users can access the service.
	emailVerifiedClaim = "email_verified"
)

// JWTAuthenticator is an Authenticator that authenticates requests where
// API credentials in the form of JSON Web Tokens (JWTs) are provided using the
// "bearer" authentication scheme, such as those defined by RFC 6750.
type JWTAuthenticator struct {
	issuer, audience string
	jwks             jwk.Set
}

// JWTAuthenticator implements Authenticator
var _ Authenticator = (*JWTAuthenticator)(nil)

// NewJWTAuthenticator is the constructor for JWTAuthenticator. The issuer and
// audience parameters are used to validate tokens, and the jwksUri parameter
// is the URI of the JSON Web Key Set (JWKS) that contains the public jwks used
// to verify the tokens. The JWKS is fetched and cached by the authenticator at
// construction time.
func NewJWTAuthenticator(ctx context.Context, issuer, audience, jwksUri string) (*JWTAuthenticator, error) {
	if issuer == "" {
		return nil, ErrEmptyIssuer
	}
	if audience == "" {
		return nil, ErrEmptyAudience
	}
	jwks, err := jwk.Fetch(ctx, jwksUri)
	if err != nil {
		return nil, errors.Join(ErrJwksFetch, err)
	}
	return &JWTAuthenticator{issuer: issuer, audience: audience, jwks: jwks}, nil
}

// Authenticate attempts to authenticate the given JWT token and returns the
// result, or any error that occurred. The creds parameter is expected to be a
// valid JWT token signed by one of the jwks in the authenticator's key set.
// Additionally, the following claims are expected to be present in the token:
//   - "iss" (issuer): The issuer of the token.
//   - "aud" (audience): The audience for the token.
//   - "email_verified": A custom claim indicating whether the user's email
//     address has been verified.
//
// The "iss" and "aud" claims are used to validate the token, and they must
// match the authenticator's issuer and audience, respectively. The custom
// "email_verified" claim is used to enforce that only verified users can access
// the service. The time-based claims ("exp", "nbf", "iat") are also validated
// by the authenticator if they are present in the token.
func (a *JWTAuthenticator) Authenticate(_ context.Context, creds string) (*Authentication, error) {
	tok, err := jwt.Parse(
		[]byte(creds),
		// Passing the JWKS here will cause the token's signature to be verified
		// during parse.
		jwt.WithKeySet(a.jwks),
		jwt.WithIssuer(a.issuer),
		jwt.WithAudience(a.audience),
		// This is a custom claim, used to indicate whether the user's email
		// address has been verified. The claim is validated to enforce that
		// only verified users can access the service.
		jwt.WithClaimValue(emailVerifiedClaim, true),
	)
	if err != nil {
		// Any error during token parsing is considered an authentication
		// failure.
		return &Authentication{}, nil
	}
	// Success! The user is authenticated.
	return &Authentication{
		Principal:       tok.Subject(),
		IsAuthenticated: true,
	}, nil
}

func (a *JWTAuthenticator) Scheme() string {
	return "bearer"
}

package auth

import "context"

// Authenticator represents a type that can authenticate some credentials for
// some defined scheme.
type Authenticator interface {
	// Authenticate attempts to authenticate the given credentials and returns
	// the result, or any error that occurred.
	Authenticate(ctx context.Context, creds string) (*Authentication, error)
	// Scheme returns the authentication scheme that this authenticator can
	// handle.
	Scheme() string
}

// Authentication represents the result of an authentication attempt.
type Authentication struct {
	// Principal is the authenticated entity, such as a user ID or client ID.
	Principal string
	// IsAuthenticated is true if the authentication attempt was successful.
	IsAuthenticated bool
}

package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// BasicAuthenticator is an Authenticator that authenticates requests where the
// credentials are provided using the "basic" authentication scheme.
type BasicAuthenticator struct {
	store UserStore
}

// NewBasicAuthenticator is the constructor for BasicAuthenticator.
func NewBasicAuthenticator(store UserStore) *BasicAuthenticator {
	return &BasicAuthenticator{store: store}
}

// BasicAuthenticator implements Authenticator
var _ Authenticator = (*BasicAuthenticator)(nil)

// Authenticate attempts to authenticate the given HTTP basic auth credentials
// and returns the result, or any error that occurred. The credentials are
// expected to be in the form "username:password" (base64 encoded), according to
// the HTTP basic auth specification RFC 7617. The user ID is used to look up
// the user in the user store (database, etc.), and the password is compared to
// the user's stored password hash. The user ID is returned as the principal
// in the Authentication result.
func (a *BasicAuthenticator) Authenticate(ctx context.Context, creds string) (*Authentication, error) {
	id, password, err := parseBasicAuth(creds)
	if err != nil {
		// The credentials are not properly formatted HTTP basic auth (i.e.
		// base64 "userID:password"), so we can't parse them. We don't consider
		// this an error - it just means the client isn't authenticated.
		return &Authentication{}, nil
	}
	// Look up the user in the store by their ID.
	user, err := a.store.FindUserByID(ctx, id)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			// The client was not found in the store. This isn't an error -
			// it just means the client isn't authenticated.
			return &Authentication{}, nil
		}
		// This is probably an internal error, e.g. we can't connect to the
		// underlying database, or the data is corrupted somehow. The caller
		// probably wants to know about this, so we return an error.
		return nil, fmt.Errorf("failed to find user: %w", err)
	}
	// Compare the provided password to the user's stored password hash.
	if err := bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(password)); err != nil {
		// An error is only returned if the passwords don't match. This means
		// the client isn't authenticated.
		return &Authentication{}, nil
	}
	// Success! The user is authenticated.
	return &Authentication{
		Principal:       id,
		IsAuthenticated: true,
	}, nil
}

func (a *BasicAuthenticator) Scheme() string {
	return "basic"
}

func parseBasicAuth(auth string) (string, string, error) {
	creds, err := base64.StdEncoding.DecodeString(auth)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode basic auth: %w", err)
	}
	parts := strings.SplitN(string(creds), ":", 2)
	if len(parts) != 2 {
		return "", "", errors.New("invalid basic auth")
	}
	return parts[0], parts[1], nil
}

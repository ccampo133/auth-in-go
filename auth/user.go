package auth

import (
	"context"
	"errors"
)

var (
	ErrUserNotFound = errors.New("user not found")
)

// User represents a user account in the system.
type User struct {
	ID           string
	PasswordHash []byte
	// Other details, perhaps such as name, email, roles, locked status, etc.
}

// UserStore is a data access type can look up user details by their unique ID.
type UserStore interface {
	// FindUserByID looks up a user by their unique ID and returns the user, or
	// an error if the user could not be found.
	FindUserByID(ctx context.Context, id string) (*User, error)
}

// InMemoryUserStore is a simple in-memory implementation of UserStore.
type InMemoryUserStore struct {
	users map[string]*User
}

// NewInMemoryUserStore is the constructor for InMemoryUserStore.
func NewInMemoryUserStore() *InMemoryUserStore {
	return &InMemoryUserStore{users: make(map[string]*User)}
}

// FindUserByID looks up a user by their unique ID and returns the user, or an
// error if the user could not be found.
func (s *InMemoryUserStore) FindUserByID(_ context.Context, id string) (*User, error) {
	if user, ok := s.users[id]; ok {
		return user, nil
	}
	return nil, ErrUserNotFound
}

// AddUser adds a user to the in-memory store.
func (s *InMemoryUserStore) AddUser(user *User) {
	s.users[user.ID] = user
}

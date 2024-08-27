package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func TestAuthenticationInterceptor_Authenticate(t *testing.T) {
	interceptor := NewAuthenticationInterceptor().
		AddAuthenticator(&MockAuthenticator{})

	tests := []struct {
		name          string
		method        string
		authHeader    string
		expectedError error
	}{
		{
			name:       "Successful authentication",
			method:     "/service.Method",
			authHeader: "Bearer token",
		},
		{
			name:          "Unsuccessful authentication",
			method:        "/service.Method",
			authHeader:    "Bearer unauthenticated",
			expectedError: ErrUnauthenticated,
		},
		{
			name:          "Missing metadata",
			method:        "/service.Method",
			expectedError: ErrMissingMetadata,
		},
		{
			name:          "Unauthenticated due to invalid authorization header",
			method:        "/service.Method",
			authHeader:    "Invalid",
			expectedError: ErrUnauthenticated,
		},
		{
			name:          "Unauthenticated due to unsupported scheme",
			method:        "/service.Method",
			authHeader:    "Unknown token",
			expectedError: ErrUnauthenticated,
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				ctx := context.Background()
				if tt.authHeader != "" {
					md := metadata.Pairs("authorization", tt.authHeader)
					ctx = metadata.NewIncomingContext(ctx, md)
				}
				handlerCalled := false
				_, err := interceptor.Authenticate(
					ctx,
					nil,
					&grpc.UnaryServerInfo{FullMethod: "/service.Method"},
					// The context passed to the handler should have the
					// principal. Note that this won't be called if an error
					// occurs.
					func(ctx context.Context, _ any) (any, error) {
						handlerCalled = true
						gotMd, ok := metadata.FromIncomingContext(ctx)
						require.True(t, ok)
						// The principal "principal" is returned by
						// MockAuthenticator.
						require.Equal(t, gotMd.Get("principal"), []string{"principal"})
						return nil, nil
					},
				)
				if tt.expectedError != nil {
					require.Falsef(t, handlerCalled, "handler should not have been called")
					require.ErrorIs(t, err, tt.expectedError)
				} else {
					require.Truef(t, handlerCalled, "handler should have been called")
					require.NoError(t, err)
				}
			},
		)
	}
}

func TestAuthenticationInterceptor_Authenticate_OverwritesPrincipalInMetadata(t *testing.T) {
	interceptor := NewAuthenticationInterceptor().
		AddAuthenticator(&MockAuthenticator{})
	md := metadata.Pairs(
		"authorization", "Bearer token",
		// Explicitly set the principal here. We expect it to be overwritten by
		// the interceptor to the value returned by the authenticator.
		"principal", "overwrite-me",
	)
	handlerCalled := false
	ctx := metadata.NewIncomingContext(context.Background(), md)
	_, err := interceptor.Authenticate(
		ctx,
		nil,
		&grpc.UnaryServerInfo{FullMethod: "dummy"},
		// The context passed to the handler should have the principal
		// overwritten.
		func(ctx context.Context, _ any) (any, error) {
			handlerCalled = true
			gotMd, ok := metadata.FromIncomingContext(ctx)
			require.True(t, ok)
			// The principal "principal" is returned by MockAuthenticator.
			require.Equal(t, gotMd.Get("principal"), []string{"principal"})
			return nil, nil
		},
	)
	require.NoError(t, err)
	require.Truef(t, handlerCalled, "handler should have been called")
}

func TestAuthenticationInterceptor_PermittedMethod(t *testing.T) {
	interceptor := NewAuthenticationInterceptor().
		AddPermittedMethod("/service.Method")
	ctx := context.Background()
	_, err := interceptor.Authenticate(
		ctx,
		nil,
		&grpc.UnaryServerInfo{FullMethod: "/service.Method"},
		dummyUnaryHandler,
	)
	require.NoError(t, err)
}

func TestAuthenticationInterceptor_AddPermittedMethod_Failure(t *testing.T) {
	interceptor := NewAuthenticationInterceptor().
		AddPermittedMethod("/service.Method")
	ctx := context.Background()
	_, err := interceptor.Authenticate(
		ctx,
		nil,
		&grpc.UnaryServerInfo{FullMethod: "/service.NonPermittedMethod"},
		dummyUnaryHandler,
	)
	require.Error(t, err)
}

func dummyUnaryHandler(_ context.Context, _ any) (any, error) {
	return nil, nil
}

type MockAuthenticator struct{}

func (a *MockAuthenticator) Authenticate(_ context.Context, creds string) (*Authentication, error) {
	if creds == "token" {
		return &Authentication{
			Principal:       "principal",
			IsAuthenticated: true,
		}, nil
	}
	if creds == "unauthenticated" {
		return &Authentication{
			IsAuthenticated: false,
		}, nil
	}
	return nil, ErrUnauthenticated
}

func (a *MockAuthenticator) Scheme() string {
	return "Bearer"
}

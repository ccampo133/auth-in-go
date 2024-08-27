package auth

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	log "github.com/sirupsen/logrus"
)

var (
	ErrMissingMetadata = status.Errorf(codes.InvalidArgument, "missing metadata")
	ErrUnauthenticated = status.Error(codes.Unauthenticated, "unauthenticated")
)

// AuthenticationInterceptor is a grpc.UnaryServerInterceptor which
// authenticates requests based on the "authorization" header in the incoming
// context's metadata. It uses a map of Authenticator (keyed by scheme) to
// authenticate the scheme and credentials contained in the header.
// Additionally, it can be configured to skip authentication for certain gRPC
// methods by adding them to a list of permitted methods.
type AuthenticationInterceptor struct {
	authenticators   map[string]Authenticator
	permittedMethods map[string]struct{}
}

// NewAuthenticationInterceptor is the constructor for
// AuthenticationInterceptor.
func NewAuthenticationInterceptor() *AuthenticationInterceptor {
	return &AuthenticationInterceptor{
		authenticators:   make(map[string]Authenticator),
		permittedMethods: make(map[string]struct{}),
	}
}

// AddAuthenticator adds an Authenticator to the interceptor. It returns the
// interceptor to allow for chaining.
func (a *AuthenticationInterceptor) AddAuthenticator(authenticator Authenticator) *AuthenticationInterceptor {
	a.authenticators[strings.ToLower(authenticator.Scheme())] = authenticator
	return a
}

// AddPermittedMethod adds a gRPC method name the list of permitted methods.
// These methods will not be authenticated by the interceptor. Methods are
// case-sensitive and are typically in the format "/package.Service/Method". The
// interceptor is returned to allow for chaining.
func (a *AuthenticationInterceptor) AddPermittedMethod(method string) *AuthenticationInterceptor {
	a.permittedMethods[method] = struct{}{}
	return a
}

// Authenticate attempts to authenticate current the request based on the
// "authorization" header in the incoming context's metadata. It returns the
// result of the authentication attempt, or any error that occurred.
func (a *AuthenticationInterceptor) Authenticate(
	ctx context.Context,
	req any,
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (any, error) {
	// If the current gRPC method is in the list of permitted methods, skip
	// auth. This is useful for methods that do not require auth, for example,
	// health check endpoints.
	if _, ok := a.permittedMethods[info.FullMethod]; ok {
		log.Debugf("skipping auth for method %s", info.FullMethod)
		return handler(ctx, req)
	}

	// Extract the "authorization" header from the incoming context's metadata.
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		// Not sure how this could happen, but it's worth checking.
		return nil, ErrMissingMetadata
	}
	// The keys within metadata.MD are normalized to lowercase.
	// See: https://godoc.org/google.golang.org/grpc/metadata#New
	authVal := md.Get("authorization")
	if len(authVal) == 0 {
		return nil, ErrUnauthenticated
	}
	authHdr := authVal[0]
	if authHdr == "" {
		return nil, ErrUnauthenticated
	}
	parts := strings.Split(authHdr, " ")
	if len(parts) != 2 {
		return nil, ErrUnauthenticated
	}

	// Find the authenticator for the requested auth scheme.
	scheme, creds := strings.ToLower(parts[0]), parts[1]
	authenticator, ok := a.authenticators[scheme]
	if !ok {
		log.Debugf("no authenticator for scheme %s", scheme)
		return nil, ErrUnauthenticated
	}

	// Authenticate the credentials
	auth, err := authenticator.Authenticate(ctx, creds)
	if err != nil {
		// We intentionally don't wrap and return the authenticator's error
		// here, even if it's an internal error and not the fault of the end
		// user, since it may leak sensitive information. Instead, we log the
		// error and return a generic unauthenticated error. Authenticators
		// should only return internal errors, so logging them is appropriate.
		log.WithError(err).Error("error during authentication")
		return nil, ErrUnauthenticated
	}
	if !auth.IsAuthenticated {
		return nil, ErrUnauthenticated
	}
	log.Debugf("Successfully authenticated principal %s", auth.Principal)

	// Authentication was successful. Add the principal to the context's
	// metadata and continue execution of handler. This is useful for RPCs to
	// know who is calling them.
	md.Set("principal", auth.Principal)
	newCtx := metadata.NewIncomingContext(ctx, md)
	return handler(newCtx, req)
}

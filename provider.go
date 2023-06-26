package oauth

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
)

// Provider needs to be implemented for each 3rd party authentication provider
// e.g. Facebook, Twitter, etc...
type Provider interface {
	Name() string
	SetName(name string)
	BeginAuth(state string) (Session, error)
	UnmarshalSession(string) (Session, error)
	FetchUser(Session) (User, error)
	Debug(bool)
	RefreshToken(refreshToken string) (*oauth2.Token, error) // Get new access token based on the refresh token
	RefreshTokenAvailable() bool                             // Refresh token is provided by auth provider or not
}

const NoAuthUrlErrorMessage = "an AuthURL has not been set"

// providers is list of known/available providers.
type Providers map[string]Provider

// ContextForClient provides a context for use with oauth2.
func ContextForClient(h *http.Client) context.Context {
	if h == nil {
		return context.Background()
	}
	return context.WithValue(context.Background(), oauth2.HTTPClient, h)
}

// HTTPClientWithFallBack to be used in all fetch operations.
func HTTPClientWithFallBack(h *http.Client) *http.Client {
	if h != nil {
		return h
	}
	return http.DefaultClient
}

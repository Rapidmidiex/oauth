package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

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

// use only for testing
var DefaultOAuth = New()

type OAuth struct {
	providers Providers
}

func New() *OAuth {
	return &OAuth{
		providers: make(map[string]Provider),
	}
}

var SetState = func(r *http.Request) string {
	state := r.URL.Query().Get("state")
	if len(state) > 0 {
		return state
	}

	// If a state query param is not passed in, generate a random
	// base64-encoded nonce so that the state on the auth URL
	// is unguessable, preventing CSRF attacks, as described in
	//
	// https://auth0.com/docs/protocols/oauth2/oauth-state#keep-reading
	nonceBytes := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, nonceBytes)
	if err != nil {
		panic("gothic: source of randomness unavailable: " + err.Error())
	}
	return base64.URLEncoding.EncodeToString(nonceBytes)
}

func GetState(r *http.Request) string {
	params := r.URL.Query()
	if params.Encode() == "" && r.Method == http.MethodPost {
		return r.FormValue("state")
	}
	return params.Get("state")
}

func ValidateState(r *http.Request, sess Session) error {
	rawAuthURL, err := sess.GetAuthURL()
	if err != nil {
		return err
	}

	authURL, err := url.Parse(rawAuthURL)
	if err != nil {
		return err
	}

	reqState := GetState(r)

	originalState := authURL.Query().Get("state")
	if originalState != "" && (originalState != reqState) {
		return errors.New("state token mismatch")
	}
	return nil
}

// UseProviders adds a list of available providers for use with Goth.
// Can be called multiple times. If you pass the same provider more
// than once, the last will be used.
func (o *OAuth) UseProviders(providers ...Provider) {
	for _, provider := range providers {
		o.providers[provider.Name()] = provider
	}
}

// GetProviders returns a list of all the providers currently in use.
func (o *OAuth) GetProviders() Providers {
	return o.providers
}

// GetProvider returns a previously created provider. If Goth has not
// been told to use the named provider it will return an error.
func (o *OAuth) GetProvider(name string) (Provider, error) {
	provider := o.providers[name]
	if provider == nil {
		return nil, fmt.Errorf("no provider for %s exists", name)
	}
	return provider, nil
}

// ClearProviders will remove all providers currently in use.
// This is useful, mostly, for testing purposes.
func (o *OAuth) ClearProviders() {
	o.providers = Providers{}
}

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

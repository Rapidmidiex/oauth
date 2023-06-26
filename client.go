package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// use only for testing
var DefaultClient = NewClient()

type Client struct {
	providers Providers
}

func NewClient() *Client {
	return &Client{
		providers: make(map[string]Provider),
	}
}

// UseProviders adds a list of available providers for use with Goth.
// Can be called multiple times. If you pass the same provider more
// than once, the last will be used.
func (c *Client) UseProviders(providers ...Provider) {
	for _, provider := range providers {
		c.providers[provider.Name()] = provider
	}
}

// GetProviders returns a list of all the providers currently in use.
func (c *Client) GetProviders() Providers {
	return c.providers
}

// GetProvider returns a previously created provider. If Goth has not
// been told to use the named provider it will return an error.
func (c *Client) GetProvider(name string) (Provider, error) {
	provider := c.providers[name]
	if provider == nil {
		return nil, fmt.Errorf("no provider for %s exists", name)
	}
	return provider, nil
}

// ClearProviders will remove all providers currently in use.
// This is useful, mostly, for testing purposes.
func (c *Client) ClearProviders() {
	c.providers = Providers{}
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

var SessionName = "_rmx_oauth_session"

func SetSession(w http.ResponseWriter, sess Session, exp time.Duration) error {
	bs, err := sess.Marshal()
	if err != nil {
		return err
	}

	cookie := &http.Cookie{
		Name:     SessionName,
		Value:    base64.StdEncoding.EncodeToString([]byte(bs)),
		Expires:  time.Now().UTC().Add(exp),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, cookie)
	return nil
}

func GetSession(r *http.Request) ([]byte, error) {
	cookie, err := r.Cookie(SessionName)
	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(cookie.Value)
}

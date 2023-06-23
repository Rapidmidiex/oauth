package discord

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	rmxOAuth "github.com/rapidmidiex/oauth"
)

// Session stores data during the auth process with Discord
type Session struct {
	AuthURL      string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on
// the Discord provider.
func (s Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New(rmxOAuth.NoAuthUrlErrorMessage)
	}
	return s.AuthURL, nil
}

// Authorize completes the authorization with Discord and returns the access
// token to be stored for future use.
func (s *Session) Authorize(provider rmxOAuth.Provider, params rmxOAuth.Params) (string, error) {
	p := provider.(*Provider)
	token, err := p.config.Exchange(context.Background(), params.Get("code"))
	if err != nil {
		return "", err
	}

	if !token.Valid() {
		return "", errors.New("Invalid token received from provider")
	}

	s.AccessToken = token.AccessToken
	s.RefreshToken = token.RefreshToken
	s.ExpiresAt = token.Expiry
	return token.AccessToken, err
}

// Marshal marshals a session into a JSON string.
func (s Session) Marshal() string {
	j, _ := json.Marshal(s)
	return string(j)
}

// String is equivalent to Marshal. It returns a JSON representation of the
// session.
func (s Session) String() string {
	return s.Marshal()
}

// UnmarshalSession will unmarshal a JSON string into a session.
func (p *Provider) UnmarshalSession(data string) (rmxOAuth.Session, error) {
	s := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(s)
	return s, err
}

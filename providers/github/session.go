package github

import (
	"encoding/json"
	"errors"
	"strings"

	rmxOAuth "github.com/rapidmidiex/oauth"
)

// Session stores data during the auth process with GitHub.
type Session struct {
	AuthURL     string
	AccessToken string
}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on the GitHub provider.
func (s Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New(rmxOAuth.NoAuthUrlErrorMessage)
	}
	return s.AuthURL, nil
}

// Authorize the session with GitHub and return the access token to be stored for future use.
func (s *Session) Authorize(provider rmxOAuth.Provider, params rmxOAuth.Params) (string, error) {
	p := provider.(*Provider)
	token, err := p.config.Exchange(rmxOAuth.ContextForClient(p.Client()), params.Get("code"))
	if err != nil {
		return "", err
	}

	if !token.Valid() {
		return "", errors.New("Invalid token received from provider")
	}

	s.AccessToken = token.AccessToken
	return token.AccessToken, err
}

// Marshal the session into a string
func (s Session) Marshal() (string, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// UnmarshalSession will unmarshal a JSON string into a session.
func (p *Provider) UnmarshalSession(data string) (rmxOAuth.Session, error) {
	sess := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(sess)
	return sess, err
}

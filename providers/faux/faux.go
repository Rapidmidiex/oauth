// Package faux is used exclusively for testing purposes. I would strongly suggest you move along
// as there's nothing to see here.
package faux

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	rmxOAuth "github.com/rapidmidiex/oauth"
	"golang.org/x/oauth2"
)

// Provider is used only for testing.
type Provider struct {
	HTTPClient   *http.Client
	providerName string
}

// Session is used only for testing.
type Session struct {
	ID          string
	Name        string
	Email       string
	AuthURL     string
	AccessToken string
}

// Name is used only for testing.
func (p *Provider) Name() string {
	return "faux"
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

// BeginAuth is used only for testing.
func (p *Provider) BeginAuth(state string) (rmxOAuth.Session, error) {
	c := &oauth2.Config{
		Endpoint: oauth2.Endpoint{
			AuthURL: "http://example.com/auth",
		},
	}
	url := c.AuthCodeURL(state)
	return &Session{
		ID:      "id",
		AuthURL: url,
	}, nil
}

// FetchUser is used only for testing.
func (p *Provider) FetchUser(session rmxOAuth.Session) (rmxOAuth.User, error) {
	sess := session.(*Session)
	user := rmxOAuth.User{
		UserID:      sess.ID,
		Name:        sess.Name,
		Email:       sess.Email,
		Provider:    p.Name(),
		AccessToken: sess.AccessToken,
	}

	if user.AccessToken == "" {
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}
	return user, nil
}

// UnmarshalSession is used only for testing.
func (p *Provider) UnmarshalSession(data string) (rmxOAuth.Session, error) {
	sess := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(sess)
	return sess, err
}

func (p *Provider) Client() *http.Client {
	return rmxOAuth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is used only for testing.
func (p *Provider) Debug(debug bool) {}

// RefreshTokenAvailable is used only for testing
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}

// RefreshToken is used only for testing
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, nil
}

// Authorize is used only for testing.
func (s *Session) Authorize(provider rmxOAuth.Provider, params rmxOAuth.Params) (string, error) {
	s.AccessToken = "access"
	return s.AccessToken, nil
}

// Marshal is used only for testing.
func (s Session) Marshal() (string, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// GetAuthURL is used only for testing.
func (s *Session) GetAuthURL() (string, error) {
	return s.AuthURL, nil
}

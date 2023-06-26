package discord

import (
	"testing"

	rmxOAuth "github.com/rapidmidiex/oauth"
	"github.com/stretchr/testify/assert"
)

func Test_ImplementsSession(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &Session{}
	a.Implements((*rmxOAuth.Session)(nil), s)
}

func Test_GetAuthURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &Session{}

	_, err := s.GetAuthURL()
	a.Error(err)

	s.AuthURL = "/foo"

	url, _ := s.GetAuthURL()
	a.Equal(url, "/foo")
}

func Test_ToJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &Session{}

	data, _ := s.Marshal()
	a.Equal(data, `{"AuthURL":"","AccessToken":"","RefreshToken":"","ExpiresAt":"0001-01-01T00:00:00Z"}`)
}

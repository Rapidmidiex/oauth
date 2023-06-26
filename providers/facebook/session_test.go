package facebook_test

import (
	"testing"

	rmxOAuth "github.com/rapidmidiex/oauth"
	"github.com/rapidmidiex/oauth/providers/facebook"
	"github.com/stretchr/testify/assert"
)

func Test_Implements_Session(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &facebook.Session{}

	a.Implements((*rmxOAuth.Session)(nil), s)
}

func Test_GetAuthURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &facebook.Session{}

	_, err := s.GetAuthURL()
	a.Error(err)

	s.AuthURL = "/foo"

	url, _ := s.GetAuthURL()
	a.Equal(url, "/foo")
}

func Test_ToJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &facebook.Session{}

	data, _ := s.Marshal()
	a.Equal(data, `{"AuthURL":"","AccessToken":"","ExpiresAt":"0001-01-01T00:00:00Z"}`)
}

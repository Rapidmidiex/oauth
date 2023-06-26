package oauth_test

import (
	"testing"

	"github.com/rapidmidiex/oauth"
	"github.com/rapidmidiex/oauth/providers/faux"
	"github.com/stretchr/testify/assert"
)

func Test_UseProviders(t *testing.T) {
	a := assert.New(t)

	provider := &faux.Provider{}
	oauth.DefaultOAuth.UseProviders(provider)
	a.Equal(len(oauth.DefaultOAuth.GetProviders()), 1)
	a.Equal(oauth.DefaultOAuth.GetProviders()[provider.Name()], provider)
	oauth.DefaultOAuth.ClearProviders()
}

func Test_GetProvider(t *testing.T) {
	a := assert.New(t)

	provider := &faux.Provider{}
	oauth.DefaultOAuth.UseProviders(provider)

	p, err := oauth.DefaultOAuth.GetProvider(provider.Name())
	a.NoError(err)
	a.Equal(p, provider)

	_, err = oauth.DefaultOAuth.GetProvider("unknown")
	a.Error(err)
	a.Equal(err.Error(), "no provider for unknown exists")
	oauth.DefaultOAuth.ClearProviders()
}

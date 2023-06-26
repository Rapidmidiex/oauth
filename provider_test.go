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
	oauth.DefaultClient.UseProviders(provider)
	a.Equal(len(oauth.DefaultClient.GetProviders()), 1)
	a.Equal(oauth.DefaultClient.GetProviders()[provider.Name()], provider)
	oauth.DefaultClient.ClearProviders()
}

func Test_GetProvider(t *testing.T) {
	a := assert.New(t)

	provider := &faux.Provider{}
	oauth.DefaultClient.UseProviders(provider)

	p, err := oauth.DefaultClient.GetProvider(provider.Name())
	a.NoError(err)
	a.Equal(p, provider)

	_, err = oauth.DefaultClient.GetProvider("unknown")
	a.Error(err)
	a.Equal(err.Error(), "no provider for unknown exists")
	oauth.DefaultClient.ClearProviders()
}

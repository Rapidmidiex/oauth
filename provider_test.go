package oauth_test

import (
	"testing"

	rmxOAuth "github.com/rapidmidiex/oauth"
	"github.com/rapidmidiex/oauth/providers/github"
	"github.com/stretchr/testify/assert"
)

func Test_UseProviders(t *testing.T) {
	a := assert.New(t)

	provider := &github.Provider{}
	rmxOAuth.UseProviders(provider)
	a.Equal(len(rmxOAuth.GetProviders()), 1)
	a.Equal(rmxOAuth.GetProviders()[provider.Name()], provider)
	rmxOAuth.ClearProviders()
}

func Test_GetProvider(t *testing.T) {
	a := assert.New(t)

	provider := &github.Provider{}
	rmxOAuth.UseProviders(provider)

	p, err := rmxOAuth.GetProvider(provider.Name())
	a.NoError(err)
	a.Equal(p, provider)

	_, err = rmxOAuth.GetProvider("unknown")
	a.Error(err)
	a.Equal(err.Error(), "no provider for unknown exists")
	rmxOAuth.ClearProviders()
}

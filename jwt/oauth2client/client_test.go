package oauth2client_test

import (
	"testing"

	"github.com/effective-security/xpki/jwt/oauth2client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Config(t *testing.T) {
	_, err := oauth2client.LoadConfig("testdata/missing.yaml")
	require.Error(t, err)
	assert.Equal(t, "open testdata/missing.yaml: no such file or directory", err.Error())

	_, err = oauth2client.LoadConfig("testdata/oauth_corrupted.1.yaml")
	require.Error(t, err)
	assert.Equal(t, `unable to unmarshal "testdata/oauth_corrupted.1.yaml": yaml: line 2: mapping values are not allowed in this context`, err.Error())

	_, err = oauth2client.LoadConfig("testdata/oauth_corrupted.2.yaml")
	require.Error(t, err)
	assert.Equal(t, `unable to unmarshal "testdata/oauth_corrupted.2.yaml": yaml: line 5: did not find expected key`, err.Error())

	cfg, err := oauth2client.LoadConfig("testdata/oauth.yaml")
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.Len(t, cfg.Clients, 2)
	cliCfg := cfg.Clients[0]
	assert.Equal(t, 2, len(cliCfg.Scopes))
	assert.Equal(t, "github", cliCfg.ProviderID)
	assert.Equal(t, "client5678", cliCfg.ClientID)
	assert.Equal(t, "secret6789", cliCfg.ClientSecret)
	assert.Equal(t, "https://github.com/login/oauth/authorize", cliCfg.AuthURL)

	p, err := oauth2client.New(&oauth2client.ClientConfig{})
	require.NoError(t, err)
	assert.NotNil(t, p.Config())
	p.SetPubKey(nil)
	p.SetClientSecret("foo")

	_, err = oauth2client.New(&oauth2client.ClientConfig{
		PubKey: "invalid",
	})
	require.Error(t, err)
	assert.Equal(t, `unable to parse Public Key: "invalid": key must be PEM encoded`, err.Error())
}

func Test_Load(t *testing.T) {
	_, err := oauth2client.Load("testdata/missing.yaml")
	require.Error(t, err)
	assert.Equal(t, "open testdata/missing.yaml: no such file or directory", err.Error())

	_, err = oauth2client.Load("testdata/oauth_corrupted.1.yaml")
	require.Error(t, err)

	_, err = oauth2client.Load("testdata/oauth_corrupted.2.yaml")
	require.Error(t, err)

	_, err = oauth2client.Load("testdata/oauth.yaml")
	require.NoError(t, err)

	_, err = oauth2client.Load("")
	require.NoError(t, err)
}

func Test_LoadClient(t *testing.T) {
	_, err := oauth2client.LoadClient("testdata/missing.yaml")
	assert.EqualError(t, err, "open testdata/missing.yaml: no such file or directory")

	c, err := oauth2client.LoadClient("testdata/client.yaml")
	require.NoError(t, err)
	assert.Equal(t, "github", c.Config().ProviderID)
}

func TestProvider(t *testing.T) {
	p, err := oauth2client.LoadProvider("testdata/oauth.yaml")
	require.NoError(t, err)

	assert.NotEmpty(t, p.ClientNames())

	for _, c := range p.ClientNames() {
		cli := p.Client(c)
		if cli != nil {
			assert.Empty(t, cli.Config().Domains)
		}
	}
	assert.NotNil(t, p.ClientForDomain("custom.com"))
	assert.Nil(t, p.ClientForDomain("foo.com"))
}

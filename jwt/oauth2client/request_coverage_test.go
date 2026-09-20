package oauth2client_test

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/effective-security/xpki/jwt/oauth2client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestTokenRequestAuthStyles(t *testing.T) {
	const clientID = "client:name &"
	const secret = "secret:+ &"
	client, err := oauth2client.New(&oauth2client.ClientConfig{
		ClientID:     clientID,
		ClientSecret: secret,
		TokenURL:     "https://issuer.example.test/token",
	})
	require.NoError(t, err)
	for _, style := range []oauth2.AuthStyle{oauth2.AuthStyleInHeader, oauth2.AuthStyleInParams, oauth2.AuthStyleAutoDetect} {
		values := url.Values{
			"grant_type": {"authorization_code"},
			"scope":      {"openid", "email"},
		}
		original := url.Values{
			"grant_type": {"authorization_code"},
			"scope":      {"openid", "email"},
		}
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		request, err := client.CreateTokenRequestWithContext(ctx, values, style)
		require.NoError(t, err)
		assert.Same(t, ctx, request.Context())
		assert.Equal(t, http.MethodPost, request.Method)
		assert.Equal(t, "https://issuer.example.test/token", request.URL.String())
		assert.Equal(t, "application/x-www-form-urlencoded", request.Header.Get("Content-Type"))
		body, err := io.ReadAll(request.Body)
		require.NoError(t, err)
		require.NoError(t, request.Body.Close())
		parsed, err := url.ParseQuery(string(body))
		require.NoError(t, err)
		assert.Equal(t, original, values, "caller-owned form must not be mutated")
		if style == oauth2.AuthStyleInParams {
			assert.Equal(t, clientID, parsed.Get("client_id"))
			assert.Equal(t, secret, parsed.Get("client_secret"))
		} else {
			assert.NotContains(t, parsed, "client_id")
			assert.NotContains(t, parsed, "client_secret")
		}
		if style == oauth2.AuthStyleInHeader {
			user, password, ok := request.BasicAuth()
			require.True(t, ok)
			assert.Equal(t, url.QueryEscape(clientID), user)
			assert.Equal(t, url.QueryEscape(secret), password)
		} else {
			assert.Empty(t, request.Header.Get("Authorization"))
		}
		assert.Equal(t, values["scope"], parsed["scope"])
		cancel()
		require.ErrorIs(t, request.Context().Err(), context.Canceled)
	}
	request, err := client.CreateTokenRequest(nil, oauth2.AuthStyleInParams)
	require.NoError(t, err)
	require.NoError(t, request.Body.Close())
	client.Config().TokenURL = "://invalid"
	_, err = client.CreateTokenRequest(nil, oauth2.AuthStyleInParams)
	require.Error(t, err)
}

func TestProviderRegistrationConflicts(t *testing.T) {
	const providerID = "provider"
	initial := &oauth2client.ClientConfig{
		ProviderID: providerID,
		Domains:    []string{"example.test"},
		Emails:     []string{"user@other.test"},
	}
	provider, err := oauth2client.NewProvider(&oauth2client.Config{Clients: []*oauth2client.ClientConfig{initial, {
		ProviderID: "disabled",
		Disabled:   true,
	}}})
	require.NoError(t, err)
	assert.Nil(t, provider.ClientForProvider("disabled"))
	assert.Nil(t, provider.Client(providerID))
	require.NotNil(t, provider.ClientForProvider(providerID))
	for _, tc := range []struct {
		cfg  *oauth2client.ClientConfig
		want string
	}{
		{&oauth2client.ClientConfig{
			ProviderID: "email-conflict",
			Emails:     []string{"user@other.test"},
		}, "OAuth client email already registered: user@other.test"},
		{&oauth2client.ClientConfig{
			ProviderID: "domain-conflict",
			Domains:    []string{"example.test"},
		}, "OAuth client domain already registered: example.test"},
		{&oauth2client.ClientConfig{ProviderID: providerID}, "OAuth provider already registered: provider"},
		{&oauth2client.ClientConfig{
			ProviderID: "bad-key",
			PubKey:     "invalid",
		}, "unable to parse Public Key"},
	} {
		require.ErrorContains(t, provider.RegisterClient(tc.cfg, false), tc.want)
	}
	replacement := &oauth2client.ClientConfig{
		ProviderID: providerID,
		Domains:    initial.Domains,
		Emails:     initial.Emails,
		ClientID:   "replacement",
	}
	require.NoError(t, provider.RegisterClient(replacement, true))
	assert.Same(t, replacement, provider.ClientForProvider(providerID).Config())
	assert.Same(t, replacement, provider.ClientForDomain("example.test").Config())
	assert.Same(t, replacement, provider.ClientForEmail("user@other.test").Config())
	_, err = oauth2client.NewProvider(&oauth2client.Config{Clients: []*oauth2client.ClientConfig{initial, initial}})
	require.Error(t, err)
	_, err = oauth2client.LoadProvider(filepath.Join(t.TempDir(), "missing"))
	require.Error(t, err)
}

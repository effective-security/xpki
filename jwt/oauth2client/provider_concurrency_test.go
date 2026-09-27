package oauth2client_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/jwt/oauth2client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func publicKeyPEM(t *testing.T, key *rsa.PublicKey) string {
	t.Helper()
	pem, err := certutil.EncodePublicKeyToPEM(key)
	require.NoError(t, err)
	return string(pem)
}

// awaitBarrier releases every goroutine waiting on start at once and waits
// for done, failing the test after a bounded time instead of hanging.
func awaitBarrier(t *testing.T, start chan struct{}, done *sync.WaitGroup) {
	t.Helper()
	close(start)
	finished := make(chan struct{})
	go func() {
		done.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(30 * time.Second):
		t.Fatal("goroutines did not finish")
	}
}

func testConfig(id string, domains, emails []string) *oauth2client.ClientConfig {
	return &oauth2client.ClientConfig{
		ProviderID:   id,
		ClientID:     "client-" + id,
		ClientSecret: "secret-" + id,
		TokenURL:     "https://" + id + ".example.test/token",
		Domains:      domains,
		Emails:       emails,
	}
}

// TestProviderRegistrationAtomic covers XPKI-081: a rejected registration
// leaves every index unchanged, and an override removes the previous
// client's entries from every index.
func TestProviderRegistrationAtomic(t *testing.T) {
	t.Parallel()
	provider, err := oauth2client.NewProvider(&oauth2client.Config{Clients: []*oauth2client.ClientConfig{
		testConfig("a", []string{"a.test"}, []string{"user@a.test"}),
		testConfig("b", nil, nil),
	}})
	require.NoError(t, err)
	snapshot := func() (names, domains, emails []string) {
		names, domains, emails = provider.ClientNames(), provider.Domains(), provider.Emails()
		sort.Strings(names)
		sort.Strings(domains)
		sort.Strings(emails)
		return
	}
	names, domains, emails := snapshot()
	assert.Equal(t, []string{"b"}, names)
	assert.Equal(t, []string{"a.test"}, domains)
	assert.Equal(t, []string{"user@a.test"}, emails)

	// the conflict is found after other entries would have been written
	for _, cfg := range []*oauth2client.ClientConfig{
		testConfig("c", []string{"c.test"}, []string{"user@c.test", "user@a.test"}),
		testConfig("c", []string{"c.test", "a.test"}, []string{"user@c.test"}),
		testConfig("a", []string{"c.test"}, []string{"user@c.test"}),
	} {
		require.Error(t, provider.RegisterClient(cfg, false))
		n, d, e := snapshot()
		assert.Equal(t, names, n)
		assert.Equal(t, domains, d)
		assert.Equal(t, emails, e)
		assert.Nil(t, provider.ClientForProvider("c"))
		assert.Nil(t, provider.ClientForDomain("c.test"))
		assert.Nil(t, provider.ClientForEmail("user@c.test"))
		assert.Equal(t, "client-a", provider.ClientForDomain("a.test").Config().ClientID)
		assert.Equal(t, "client-a", provider.ClientForEmail("user@a.test").Config().ClientID)
	}

	// an override replaces the whole registration of the provider id
	replacement := testConfig("a", []string{"a2.test"}, []string{"user@a2.test"})
	require.NoError(t, provider.RegisterClient(replacement, true))
	names, domains, emails = snapshot()
	assert.Equal(t, []string{"b"}, names)
	assert.Equal(t, []string{"a2.test"}, domains)
	assert.Equal(t, []string{"user@a2.test"}, emails)
	assert.Nil(t, provider.ClientForDomain("a.test"))
	assert.Nil(t, provider.ClientForEmail("user@a.test"))
	assert.Equal(t, "client-a", provider.ClientForDomain("a2.test").Config().ClientID)
	assert.Equal(t, "client-a", provider.ClientForEmail("user@a2.test").Config().ClientID)

	// an override takes a domain and an email over from another provider
	require.NoError(t, provider.RegisterClient(testConfig("d", []string{"a2.test"}, []string{"user@a2.test"}), true))
	assert.Equal(t, "client-d", provider.ClientForDomain("a2.test").Config().ClientID)
	assert.Equal(t, "client-d", provider.ClientForEmail("user@a2.test").Config().ClientID)
	require.NotNil(t, provider.ClientForProvider("a"))
	assert.Nil(t, provider.Client("a"), "a still has domains and is not a public provider")
	names, _, _ = snapshot()
	assert.Equal(t, []string{"b"}, names)

	// a zero Provider registers and looks up like a constructed one
	var zero oauth2client.Provider
	assert.Nil(t, zero.ClientForProvider("a"))
	assert.Empty(t, zero.ClientNames())
	require.NoError(t, zero.RegisterClient(testConfig("z", nil, nil), false))
	assert.Equal(t, []string{"z"}, zero.ClientNames())
}

// TestProviderConcurrentRegistration registers, overrides, looks up and
// enumerates concurrently (run with -race) and checks that every observation
// is one coherent registration.
func TestProviderConcurrentRegistration(t *testing.T) {
	t.Parallel()
	const (
		writers = 4
		readers = 8
		rounds  = 200
	)
	// two registrations of the same provider id alternate under override
	alt := [2]*oauth2client.ClientConfig{
		testConfig("p", []string{"one.test"}, []string{"user@one.test"}),
		testConfig("p", []string{"two.test"}, []string{"user@two.test"}),
	}
	alt[0].ClientID, alt[1].ClientID = "one", "two"
	provider, err := oauth2client.NewProvider(&oauth2client.Config{Clients: []*oauth2client.ClientConfig{alt[0]}})
	require.NoError(t, err)

	start := make(chan struct{})
	var done sync.WaitGroup
	var incoherent []string
	var mu sync.Mutex
	report := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		if len(incoherent) < 10 {
			incoherent = append(incoherent, fmt.Sprintf(format, args...))
		}
	}

	for w := range writers {
		done.Go(func() {
			<-start
			for i := range rounds {
				if !assert.NoError(t, provider.RegisterClient(alt[(w+i)%2], true)) {
					return
				}
				// distinct providers register without override concurrently
				id := "w" + strconv.Itoa(w) + "-" + strconv.Itoa(i)
				if !assert.NoError(t, provider.RegisterClient(testConfig(id, nil, []string{id + "@x.test"}), false)) {
					return
				}
			}
		})
	}
	for range readers {
		done.Go(func() {
			<-start
			for range rounds {
				p := provider.ClientForProvider("p")
				if p == nil {
					report("provider p missing")
					continue
				}
				cfg := p.Config()
				switch cfg.ClientID {
				case "one", "two":
				default:
					report("unexpected client %q", cfg.ClientID)
				}
				// the client found by domain or email owns that domain or email
				for _, d := range provider.Domains() {
					c := provider.ClientForDomain(d)
					if c == nil {
						continue // removed by an override after Domains
					}
					if got := c.Config().Domains; len(got) != 1 || got[0] != d {
						report("domain %q resolves to a client with domains %v", d, got)
					}
				}
				domains := provider.Domains()
				if len(domains) > 1 {
					// at most one of the alternatives is published at a time
					report("domains %v", domains)
				}
				if c := provider.ClientForEmail("user@one.test"); c != nil && c.Config().ClientID != "one" {
					report("user@one.test resolves to %q", c.Config().ClientID)
				}
				if c := provider.ClientForEmail("user@two.test"); c != nil && c.Config().ClientID != "two" {
					report("user@two.test resolves to %q", c.Config().ClientID)
				}
				_ = provider.ClientNames()
				_ = provider.Emails()
				_ = provider.Client("p")
			}
		})
	}
	awaitBarrier(t, start, &done)
	assert.Empty(t, incoherent)

	// every distinct provider is registered and enumerable
	names := provider.ClientNames()
	assert.Len(t, names, writers*rounds)
	for w := range writers {
		for i := range rounds {
			id := "w" + strconv.Itoa(w) + "-" + strconv.Itoa(i)
			require.NotNil(t, provider.ClientForProvider(id), id)
			require.NotNil(t, provider.ClientForEmail(id+"@x.test"), id)
		}
	}
	assert.Len(t, provider.Emails(), writers*rounds+1)
	assert.Len(t, provider.Domains(), 1)
}

// TestClientConfigOwnership covers XPKI-080: the client owns a copy of its
// configuration, Config returns a copy, and the parsed public key is
// readable.
func TestClientConfigOwnership(t *testing.T) {
	t.Parallel()
	_, err := oauth2client.New(nil)
	require.EqualError(t, err, "client config is nil")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pem := publicKeyPEM(t, &key.PublicKey)
	cfg := testConfig("p", []string{"p.test"}, []string{"user@p.test"})
	cfg.Scopes = []string{"openid"}
	cfg.IDPParam = &oauth2client.IDPParam{Name: "idp", Value: "email"}
	cfg.PubKey = pem
	client, err := oauth2client.New(cfg)
	require.NoError(t, err)
	require.NotNil(t, client.PublicKey())
	assert.True(t, key.PublicKey.Equal(client.PublicKey()))

	// the caller's struct and slices are not shared with the client
	cfg.ClientID = "changed"
	cfg.Scopes[0] = "changed"
	cfg.Domains[0] = "changed"
	cfg.Emails[0] = "changed"
	cfg.IDPParam.Value = "changed"
	got := client.Config()
	assert.Equal(t, "client-p", got.ClientID)
	assert.Equal(t, []string{"openid"}, got.Scopes)
	assert.Equal(t, []string{"p.test"}, got.Domains)
	assert.Equal(t, []string{"user@p.test"}, got.Emails)
	assert.Equal(t, "email", got.IDPParam.Value)
	assert.Equal(t, pem, got.PubKey)

	// nor is a Config copy shared with the client or with another copy
	got.ClientSecret = "changed"
	got.Scopes[0] = "changed"
	got.IDPParam.Value = "changed"
	again := client.Config()
	assert.Equal(t, "secret-p", again.ClientSecret)
	assert.Equal(t, []string{"openid"}, again.Scopes)
	assert.Equal(t, "email", again.IDPParam.Value)
	assert.NotSame(t, got, again)

	// setters are the only way to change the client
	assert.Same(t, client, client.SetClientSecret("rotated"))
	assert.Equal(t, "rotated", client.Config().ClientSecret)
	client.SetPubKey(nil)
	assert.Nil(t, client.PublicKey())
	assert.Equal(t, pem, client.Config().PubKey, "the PEM setting is what was loaded")

	// nil slices stay nil in copies
	plain, err := oauth2client.New(&oauth2client.ClientConfig{ProviderID: "plain"})
	require.NoError(t, err)
	assert.Equal(t, &oauth2client.ClientConfig{ProviderID: "plain"}, plain.Config())
	assert.Nil(t, plain.PublicKey())
}

// TestClientConcurrentSecretRotation rotates the client secret while token
// requests are built (run with -race); every request carries one of the
// secrets that were set.
func TestClientConcurrentSecretRotation(t *testing.T) {
	t.Parallel()
	const (
		writers = 2
		readers = 6
		rounds  = 300
	)
	client, err := oauth2client.New(testConfig("p", nil, nil))
	require.NoError(t, err)
	valid := map[string]bool{"secret-p": true}
	for w := range writers {
		for i := range rounds {
			valid[fmt.Sprintf("secret-%d-%d", w, i)] = true
		}
	}

	start := make(chan struct{})
	var done sync.WaitGroup
	var bad []string
	var mu sync.Mutex
	for w := range writers {
		done.Go(func() {
			<-start
			for i := range rounds {
				client.SetClientSecret(fmt.Sprintf("secret-%d-%d", w, i))
			}
		})
	}
	for r := range readers {
		done.Go(func() {
			<-start
			style := oauth2.AuthStyleInParams
			if r%2 == 1 {
				style = oauth2.AuthStyleInHeader
			}
			for range rounds {
				req, err := client.CreateTokenRequest(url.Values{"grant_type": {"client_credentials"}}, style)
				if !assert.NoError(t, err) {
					return
				}
				var secret string
				if style == oauth2.AuthStyleInParams {
					body, err := io.ReadAll(req.Body)
					if !assert.NoError(t, err) {
						return
					}
					form, err := url.ParseQuery(string(body))
					if !assert.NoError(t, err) {
						return
					}
					secret = form.Get("client_secret")
				} else {
					_, password, ok := req.BasicAuth()
					if !assert.True(t, ok) {
						return
					}
					secret, err = url.QueryUnescape(password)
					if !assert.NoError(t, err) {
						return
					}
				}
				if !valid[secret] {
					mu.Lock()
					bad = append(bad, secret)
					mu.Unlock()
				}
				_ = client.Config()
			}
		})
	}
	awaitBarrier(t, start, &done)
	assert.Empty(t, bad)
	// the final secret is the last one set by one of the writers
	final := client.Config().ClientSecret
	lastOfWriter := map[string]bool{}
	for w := range writers {
		lastOfWriter[fmt.Sprintf("secret-%d-%d", w, rounds-1)] = true
	}
	assert.True(t, lastOfWriter[final], final)
}

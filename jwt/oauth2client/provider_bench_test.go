package oauth2client_test

import (
	"net/url"
	"strconv"
	"testing"

	"github.com/effective-security/xpki/jwt/oauth2client"
	"golang.org/x/oauth2"
)

func benchProvider(b *testing.B, clients int) *oauth2client.Provider {
	b.Helper()
	cfg := &oauth2client.Config{}
	for i := range clients {
		id := "p" + strconv.Itoa(i)
		cfg.Clients = append(cfg.Clients, &oauth2client.ClientConfig{
			ProviderID:   id,
			ClientID:     "client-" + id,
			ClientSecret: "secret-" + id,
			TokenURL:     "https://" + id + ".example.test/token",
			Domains:      []string{id + ".test"},
			Emails:       []string{"user@" + id + ".test"},
		})
	}
	p, err := oauth2client.NewProvider(cfg)
	if err != nil {
		b.Fatal(err)
	}
	return p
}

// BenchmarkProviderLookup measures registry lookups by email and domain
// from parallel goroutines.
func BenchmarkProviderLookup(b *testing.B) {
	p := benchProvider(b, 100)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			id := "p" + strconv.Itoa(i%100)
			if p.ClientForEmail("other@"+id+".test") == nil || p.ClientForDomain(id+".test") == nil {
				// FailNow must not run on a RunParallel worker
				b.Error("missing")
				return
			}
			i++
		}
	})
}

// BenchmarkProviderEnumerate measures ClientNames and Domains.
func BenchmarkProviderEnumerate(b *testing.B) {
	p := benchProvider(b, 100)
	b.ReportAllocs()
	for b.Loop() {
		_ = p.ClientNames()
		_ = p.Domains()
	}
}

// BenchmarkCreateTokenRequest measures request building from parallel
// goroutines, with the client secret rotated occasionally.
func BenchmarkCreateTokenRequest(b *testing.B) {
	client, err := oauth2client.New(&oauth2client.ClientConfig{
		ClientID:     "client",
		ClientSecret: "secret",
		TokenURL:     "https://issuer.example.test/token",
	})
	if err != nil {
		b.Fatal(err)
	}
	values := url.Values{"grant_type": {"client_credentials"}}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if i%1000 == 0 {
				client.SetClientSecret("secret-" + strconv.Itoa(i))
			}
			if _, err := client.CreateTokenRequest(values, oauth2.AuthStyleInHeader); err != nil {
				b.Error(err)
				return
			}
			i++
		}
	})
}

// BenchmarkClientConfig measures Config, which returns a copy.
func BenchmarkClientConfig(b *testing.B) {
	client, err := oauth2client.New(&oauth2client.ClientConfig{
		ProviderID: "p",
		ClientID:   "client",
		Scopes:     []string{"openid", "email"},
		Domains:    []string{"p.test"},
		IDPParam:   &oauth2client.IDPParam{Name: "idp", Value: "email"},
	})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = client.Config().ProviderID
	}
}

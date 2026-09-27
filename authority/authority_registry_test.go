package authority

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/effective-security/xpki/csr"
	"github.com/effective-security/xpki/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// registryTestIssuer returns an issuer named label that serves the named
// non-wildcard profiles.
func registryTestIssuer(t testing.TB, label string, profiles ...string) *Issuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	entity := testca.NewEntity(
		testca.Subject(pkix.Name{CommonName: label}),
		testca.PrivateKey(key),
		testca.Authority,
		testca.KeyUsage(x509.KeyUsageCertSign|x509.KeyUsageCRLSign),
	)
	cfg := &IssuerConfig{
		Label:    label,
		Profiles: map[string]*CertProfile{},
	}
	for _, name := range profiles {
		cfg.Profiles[name] = &CertProfile{
			IssuerLabel: label,
			Usage:       []string{"digital signature"},
			Expiry:      csr.Duration(time.Hour),
		}
	}
	issuer, err := CreateIssuer(cfg, testca.ToPEM(entity.Certificate), nil, nil, key)
	require.NoError(t, err)
	return issuer
}

// awaitBarrier waits for wg with a deadline, so a deadlock fails the test
// instead of hanging the suite.
func awaitBarrier(t *testing.T, wg *sync.WaitGroup) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("goroutines did not finish")
	}
}

// TestAuthorityConcurrentRegistry overlaps issuer and profile registration
// with every lookup and enumeration (XPKI-055). Run with -race.
func TestAuthorityConcurrentRegistry(t *testing.T) {
	t.Parallel()
	ca := &Authority{}
	first := registryTestIssuer(t, "issuer-0", "profile-0")
	require.NoError(t, ca.AddIssuer(first))

	const writers, readers, rounds = 4, 8, 12
	issuers := make([][]*Issuer, writers)
	for w := range writers {
		for i := range rounds {
			label := fmt.Sprintf("issuer-%d-%d", w, i)
			issuers[w] = append(issuers[w], registryTestIssuer(t, label, "profile-"+label))
		}
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make([]error, writers)
	for w := range writers {
		wg.Go(func() {
			<-start
			for i, issuer := range issuers[w] {
				if err := ca.AddIssuer(issuer); err != nil {
					errs[w] = err
					return
				}
				ca.AddProfile(fmt.Sprintf("wildcard-%d-%d", w, i), &CertProfile{IssuerLabel: wildcardIssuer})
				for _, is := range ca.Issuers() {
					is.AddProfile(fmt.Sprintf("extra-%d-%d", w, i), &CertProfile{})
				}
			}
		})
	}
	for range readers {
		wg.Go(func() {
			<-start
			for range rounds * 4 {
				is, err := ca.GetIssuerByLabel("issuer-0")
				assert.NoError(t, err)
				assert.Same(t, first, is)
				is, err = ca.GetIssuerByKeyID(first.SubjectKID())
				assert.NoError(t, err)
				assert.Same(t, first, is)
				is, err = ca.GetIssuerByProfile("profile-0")
				assert.NoError(t, err)
				assert.Same(t, first, is)
				_, _ = ca.GetIssuerByKeyHash(crypto.SHA1, first.KeyHash(crypto.SHA1))
				_, _ = ca.GetIssuerByNameHash(crypto.SHA1, first.NameHash(crypto.SHA1))
				for _, is := range ca.Issuers() {
					for name := range is.Profiles() {
						assert.NotNil(t, is.Profile(name))
					}
				}
				for name, p := range ca.Profiles() {
					assert.NotNil(t, p, name)
					assert.Same(t, p, ca.Profile(name))
				}
			}
		})
	}
	close(start)
	awaitBarrier(t, &wg)

	for w := range writers {
		require.NoError(t, errs[w])
	}
	assert.Len(t, ca.Issuers(), 1+writers*rounds)
	assert.Len(t, ca.Profiles(), writers*rounds)
	for w := range writers {
		for _, issuer := range issuers[w] {
			is, err := ca.GetIssuerByLabel(issuer.Label())
			require.NoError(t, err)
			assert.Same(t, issuer, is)
			is, err = ca.GetIssuerByProfile("profile-" + issuer.Label())
			require.NoError(t, err)
			assert.Same(t, issuer, is)
		}
	}
}

// TestAuthorityProfilesSnapshot checks that the maps returned by Profiles
// are copies: changing them does not change the registry (XPKI-055).
func TestAuthorityProfilesSnapshot(t *testing.T) {
	t.Parallel()
	ca := &Authority{}
	wildcard := &CertProfile{IssuerLabel: wildcardIssuer}
	ca.AddProfile("wildcard", wildcard)
	issuer := registryTestIssuer(t, "snapshot", "leaf")
	require.NoError(t, ca.AddIssuer(issuer))

	profiles := ca.Profiles()
	require.Len(t, profiles, 1)
	assert.Same(t, wildcard, profiles["wildcard"])
	profiles["added"] = &CertProfile{}
	assert.Same(t, wildcard, ca.Profile("wildcard"))
	assert.Nil(t, ca.Profile("added"))
	assert.Len(t, ca.Profiles(), 1)

	leaf := issuer.Profile("leaf")
	require.NotNil(t, leaf)
	ip := issuer.Profiles()
	require.Len(t, ip, 1)
	assert.Same(t, leaf, ip["leaf"])
	delete(ip, "leaf")
	ip["added"] = &CertProfile{}
	assert.Same(t, leaf, issuer.Profile("leaf"))
	assert.Nil(t, issuer.Profile("added"))
	assert.Len(t, issuer.Profiles(), 1)

	// the registered profile keeps its identity
	replacement := &CertProfile{IssuerLabel: wildcardIssuer, Description: "v2"}
	ca.AddProfile("wildcard", replacement)
	assert.Same(t, replacement, ca.Profile("wildcard"))
	assert.Same(t, wildcard, profiles["wildcard"], "the snapshot is unchanged")
}

// TestAuthorityAddIssuerConflict checks that a rejected AddIssuer leaves the
// registry unchanged (XPKI-055).
func TestAuthorityAddIssuerConflict(t *testing.T) {
	t.Parallel()
	ca := &Authority{}
	first := registryTestIssuer(t, "first", "shared", "only-first")
	require.NoError(t, ca.AddIssuer(first))
	second := registryTestIssuer(t, "second", "shared", "only-second")

	err := ca.AddIssuer(second)
	require.EqualError(t, err, `profile "shared" is already registered by "first" issuer`)
	_, err = ca.GetIssuerByLabel("second")
	assert.EqualError(t, err, "issuer not found: second")
	_, err = ca.GetIssuerByKeyID(second.SubjectKID())
	assert.Error(t, err)
	_, err = ca.GetIssuerByProfile("only-second")
	assert.EqualError(t, err, "issuer not found for profile: only-second")
	is, err := ca.GetIssuerByProfile("shared")
	require.NoError(t, err)
	assert.Same(t, first, is)
	assert.Len(t, ca.Issuers(), 1)

	// the same issuer, or another one with its label, is rejected and the
	// registered one stays
	err = ca.AddIssuer(first)
	require.EqualError(t, err, `issuer "first" is already registered`)
	renewed := registryTestIssuer(t, "first", "renewed")
	err = ca.AddIssuer(renewed)
	require.EqualError(t, err, `issuer "first" is already registered`)
	is, err = ca.GetIssuerByLabel("first")
	require.NoError(t, err)
	assert.Same(t, first, is)
	_, err = ca.GetIssuerByProfile("renewed")
	assert.EqualError(t, err, "issuer not found for profile: renewed")
	_, err = ca.GetIssuerByKeyID(renewed.SubjectKID())
	assert.Error(t, err)

	// a nil profile is a configuration error, not a served profile
	broken := registryTestIssuer(t, "broken", "ok")
	broken.AddProfile("missing", nil)
	err = ca.AddIssuer(broken)
	require.EqualError(t, err, `profile "missing" of issuer "broken" is nil`)
	_, err = ca.GetIssuerByLabel("broken")
	assert.Error(t, err)
	_, err = ca.GetIssuerByProfile("ok")
	assert.Error(t, err)
	assert.Len(t, ca.Issuers(), 1)

	err = ca.AddIssuer(nil)
	assert.EqualError(t, err, "nil issuer")
}

// TestAuthorityIssuersSorted checks that Issuers is sorted by label.
func TestAuthorityIssuersSorted(t *testing.T) {
	t.Parallel()
	ca := &Authority{}
	for _, label := range []string{"c", "a", "b"} {
		require.NoError(t, ca.AddIssuer(registryTestIssuer(t, label)))
	}
	var labels []string
	for _, is := range ca.Issuers() {
		labels = append(labels, is.Label())
	}
	assert.Equal(t, []string{"a", "b", "c"}, labels)
}

// TestAuthorityZeroValue checks that an Authority without NewAuthority
// answers lookups.
func TestAuthorityZeroValue(t *testing.T) {
	t.Parallel()
	var ca Authority
	assert.Empty(t, ca.Issuers())
	assert.Empty(t, ca.Profiles())
	assert.Nil(t, ca.Profile("x"))
	_, err := ca.GetIssuerByLabel("x")
	assert.EqualError(t, err, "issuer not found: x")
	_, err = ca.GetIssuerByKeyID("x")
	assert.EqualError(t, err, "issuer not found: x")
	_, err = ca.GetIssuerByProfile("x")
	assert.EqualError(t, err, "issuer not found for profile: x")
	_, err = ca.GetIssuerByKeyHash(crypto.SHA1, []byte{1})
	assert.EqualError(t, err, "issuer not found")
	_, err = ca.GetIssuerByNameHash(crypto.SHA1, []byte{1})
	assert.EqualError(t, err, "issuer not found")
}

// BenchmarkAuthorityLookup measures the hot lookups of a Sign request:
// the issuer by profile and the profile itself.
func BenchmarkAuthorityLookup(b *testing.B) {
	ca := &Authority{}
	const issuers = 8
	for i := range issuers {
		label := fmt.Sprintf("issuer-%d", i)
		require.NoError(b, ca.AddIssuer(registryTestIssuer(b, label, "profile-"+label)))
	}
	names := make([]string, issuers)
	for i := range names {
		names[i] = fmt.Sprintf("profile-issuer-%d", i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			name := names[i%issuers]
			i++
			is, err := ca.GetIssuerByProfile(name)
			if err != nil {
				b.Fatal(err)
			}
			if is.Profile(name) == nil {
				b.Fatal("missing profile")
			}
		}
	})
}

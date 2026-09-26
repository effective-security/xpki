package certutil_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bundleWorkers is the number of goroutines per scenario that share one
// Bundler in TestBundlerConcurrentBundle.
const bundleWorkers = 8

// fillerIntermediates returns n CA certificates unrelated to any test chain,
// used to grow a Bundler's intermediate pool.
func fillerIntermediates(t testing.TB, n int) []*x509.Certificate {
	t.Helper()
	root := bundlerCA(t, "Filler Root", nil)
	certs := make([]*x509.Certificate, n)
	for i := range certs {
		certs[i] = bundlerCA(t, fmt.Sprintf("Filler CA %d", i), root).Certificate
	}
	return certs
}

// TestBundlerConcurrentBundle shares one Bundler between goroutines that
// start together: warm-cache hits, and two AIA chains that every worker of
// its scenario must learn (XPKI-035). All fixtures are built before the
// goroutines start.
func TestBundlerConcurrentBundle(t *testing.T) {
	t.Parallel()
	s := newAIAServer(t)
	root := bundlerCA(t, "Root", nil)

	// cached: known from construction, verified without AIA
	cached := bundlerCA(t, "Cached CA", root)
	warmLeaf := cached.Issue(testca.Subject(pkix.Name{CommonName: "warm.example.test"}))

	// two AIA chains: root -> caA1 -> caA2 -> leafA and root -> caB -> leafB
	caA1 := bundlerCA(t, "CA A1", root)
	urlA1 := s.handle("/a1", serveDER(caA1.Certificate))
	caA2 := bundlerCA(t, "CA A2", caA1, testca.IssuingCertificateURL(urlA1))
	urlA2 := s.handle("/a2", serveDER(caA2.Certificate))
	leafA := caA2.Issue(
		testca.Subject(pkix.Name{CommonName: "a.example.test"}),
		testca.IssuingCertificateURL(urlA2),
	)
	caB := bundlerCA(t, "CA B", root)
	urlB := s.handle("/b", serveDER(caB.Certificate))
	leafB := caB.Issue(
		testca.Subject(pkix.Name{CommonName: "b.example.test"}),
		testca.IssuingCertificateURL(urlB),
	)

	b, err := certutil.NewBundler(
		[]*x509.Certificate{root.Certificate},
		[]*x509.Certificate{cached.Certificate},
		certutil.WithAIA(true),
		certutil.WithHTTPClient(s.client()),
	)
	require.NoError(t, err)
	before := b.VerifyOptions()

	scenarios := []struct {
		name string
		leaf *x509.Certificate
		exp  []*x509.Certificate
	}{
		{name: "warm", leaf: warmLeaf.Certificate, exp: []*x509.Certificate{warmLeaf.Certificate, cached.Certificate}},
		{name: "aia depth 2", leaf: leafA.Certificate, exp: []*x509.Certificate{leafA.Certificate, caA2.Certificate, caA1.Certificate}},
		{name: "aia depth 1", leaf: leafB.Certificate, exp: []*x509.Certificate{leafB.Certificate, caB.Certificate}},
	}

	type result struct {
		scenario int
		chain    *certutil.Chain
		err      error
	}
	start := make(chan struct{})
	results := make(chan result, len(scenarios)*bundleWorkers)
	var wg sync.WaitGroup
	for i, sc := range scenarios {
		for range bundleWorkers {
			wg.Go(func() {
				<-start
				chain, err := b.Bundle([]*x509.Certificate{sc.leaf}, nil)
				results <- result{scenario: i, chain: chain, err: err}
			})
		}
	}
	close(start)
	wg.Wait()
	close(results)

	for r := range results {
		sc := scenarios[r.scenario]
		require.NoError(t, r.err, sc.name)
		assert.Equal(t, sc.exp, r.chain.Chain, sc.name)
		assert.Same(t, root.Certificate, r.chain.Root, sc.name)
	}

	// each worker fetches a URL at most once; at least one fetched it
	for _, path := range []string{"/a1", "/a2", "/b"} {
		n := s.count(path)
		assert.GreaterOrEqual(t, n, 1, path)
		assert.LessOrEqual(t, n, bundleWorkers, path)
	}

	// everything learned is cached: no further request
	total := s.total()
	for _, sc := range scenarios {
		chain, err := b.Bundle([]*x509.Certificate{sc.leaf}, nil)
		require.NoError(t, err, sc.name)
		assert.Equal(t, sc.exp, chain.Chain, sc.name)
	}
	assert.Equal(t, total, s.total())
	for _, ca := range []*testca.Entity{cached, caA1, caA2, caB} {
		assert.True(t, b.KnownIssuers[string(ca.Certificate.Signature)], ca.Certificate.Subject.CommonName)
	}

	// options taken before learning are not changed by it
	_, err = leafB.Certificate.Verify(before)
	var unknown x509.UnknownAuthorityError
	require.ErrorAs(t, err, &unknown)
	_, err = leafB.Certificate.Verify(b.VerifyOptions())
	require.NoError(t, err)
}

// TestBundlerLearnMerge publishes intermediates the way two overlapping
// verifyChain calls do: the first installs its private pool, and the second,
// whose snapshot is stale, is merged into a copy of the current pool. No
// published pool is modified (XPKI-035).
func TestBundlerLearnMerge(t *testing.T) {
	t.Parallel()
	root := bundlerCA(t, "Root", nil)
	ca1 := bundlerCA(t, "CA 1", root)
	ca2 := bundlerCA(t, "CA 2", root)
	leaf1 := ca1.Issue(testca.Subject(pkix.Name{CommonName: "one.example.test"}))
	leaf2 := ca2.Issue(testca.Subject(pkix.Name{CommonName: "two.example.test"}))
	b, err := certutil.NewBundler([]*x509.Certificate{root.Certificate}, nil)
	require.NoError(t, err)
	verifies := func(opts x509.VerifyOptions, leaf *testca.Entity) bool {
		_, err := leaf.Certificate.Verify(opts)
		return err == nil
	}

	base := b.VerifyOptions().Intermediates
	first := base.Clone()
	first.AddCert(ca1.Certificate)
	second := base.Clone()
	second.AddCert(ca2.Certificate)

	b.Learn(base, first, []*x509.Certificate{ca1.Certificate})
	afterFirst := b.VerifyOptions()
	assert.Same(t, first, afterFirst.Intermediates, "an up-to-date private pool is installed as is")

	b.Learn(base, second, []*x509.Certificate{ca2.Certificate, ca1.Certificate})
	merged := b.VerifyOptions()
	assert.NotSame(t, first, merged.Intermediates)
	assert.NotSame(t, second, merged.Intermediates)
	assert.True(t, verifies(merged, leaf1))
	assert.True(t, verifies(merged, leaf2))
	assert.False(t, verifies(afterFirst, leaf2), "a published pool is not modified")
	for _, ca := range []*testca.Entity{root, ca1, ca2} {
		assert.True(t, b.KnownIssuers[string(ca.Certificate.Signature)], ca.Certificate.Subject.CommonName)
	}

	// nothing to learn: no new pool
	b.Learn(base, second, nil)
	assert.Same(t, merged.Intermediates, b.VerifyOptions().Intermediates)
}

// TestBundlerLearnNilPool learns over AIA when set-up code cleared
// IntermediatePool and KnownIssuers before the first use.
func TestBundlerLearnNilPool(t *testing.T) {
	t.Parallel()
	s := newAIAServer(t)
	root := bundlerCA(t, "Root", nil)
	ca := bundlerCA(t, "CA", root)
	url := s.handle("/ca", serveDER(ca.Certificate))
	leaf := ca.Issue(
		testca.Subject(pkix.Name{CommonName: aiaLeafName}),
		testca.IssuingCertificateURL(url),
	)
	b, err := certutil.NewBundler([]*x509.Certificate{root.Certificate}, nil,
		certutil.WithAIA(true),
		certutil.WithHTTPClient(s.client()),
	)
	require.NoError(t, err)
	b.IntermediatePool = nil
	b.KnownIssuers = nil

	chain, err := bundleWithin(t, b, []*x509.Certificate{leaf.Certificate})
	require.NoError(t, err)
	assert.Equal(t, []*x509.Certificate{leaf.Certificate, ca.Certificate}, chain.Chain)
	assert.True(t, b.KnownIssuers[string(ca.Certificate.Signature)])
	_, err = bundleWithin(t, b, []*x509.Certificate{leaf.Certificate})
	require.NoError(t, err)
	assert.Equal(t, 1, s.count("/ca"))
}

// BenchmarkBundle measures Bundle on a warm cache (serial and parallel) and
// the cost of learning one AIA intermediate, as the intermediate pool grows
// (XPKI-035).
func BenchmarkBundle(b *testing.B) {
	for _, size := range []int{0, 100, 1000} {
		fillers := fillerIntermediates(b, size)

		b.Run(fmt.Sprintf("warm/pool=%d", size), func(b *testing.B) {
			root := bundlerCA(b, "Root", nil)
			ca := bundlerCA(b, "CA", root)
			leaf := ca.Issue(testca.Subject(pkix.Name{CommonName: aiaLeafName}))
			bundler, err := certutil.NewBundler([]*x509.Certificate{root.Certificate}, append([]*x509.Certificate{ca.Certificate}, fillers...))
			require.NoError(b, err)
			certs := []*x509.Certificate{leaf.Certificate}

			b.Run("serial", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, err := bundler.Bundle(certs, nil); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("parallel", func(b *testing.B) {
				b.ReportAllocs()
				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						if _, err := bundler.Bundle(certs, nil); err != nil {
							b.Error(err)
							return
						}
					}
				})
			})
		})

		// learn: a fresh Bundler (untimed) learns one intermediate over AIA
		b.Run(fmt.Sprintf("learn/pool=%d", size), func(b *testing.B) {
			s := newAIAServer(b)
			root := bundlerCA(b, "Root", nil)
			ca := bundlerCA(b, "CA", root)
			url := s.handle("/ca", func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(ca.Certificate.Raw)
			})
			leaf := ca.Issue(
				testca.Subject(pkix.Name{CommonName: aiaLeafName}),
				testca.IssuingCertificateURL(url),
			)
			roots := []*x509.Certificate{root.Certificate}
			certs := []*x509.Certificate{leaf.Certificate}
			client := s.client()
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				b.StopTimer()
				bundler, err := certutil.NewBundler(roots, fillers,
					certutil.WithAIA(true),
					certutil.WithHTTPClient(client),
				)
				if err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
				if _, err = bundler.Bundle(certs, nil); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

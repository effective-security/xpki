package certutil_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	aiaBadPath     = "/bad"
	aiaLeafName    = "leaf.example.test"
	aiaBodyMarker  = "aia-body-marker-must-not-be-logged"
	aiaTestTimeout = time.Second
	// aiaWatchdog bounds a Bundle call that would otherwise hang.
	aiaWatchdog = 10 * time.Second
)

// aiaServer serves AIA responses per path and counts requests per path.
type aiaServer struct {
	*httptest.Server
	mu       sync.Mutex
	handlers map[string]http.HandlerFunc
	counts   map[string]int
}

func newAIAServer(t testing.TB) *aiaServer {
	t.Helper()
	s := &aiaServer{
		handlers: map[string]http.HandlerFunc{},
		counts:   map[string]int{},
	}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.counts[r.URL.Path]++
		h := s.handlers[r.URL.Path]
		s.mu.Unlock()
		if h == nil {
			http.NotFound(w, r)
			return
		}
		h(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

// handle registers h for path and returns the absolute URL.
func (s *aiaServer) handle(path string, h http.HandlerFunc) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[path] = h
	return s.URL + path
}

func (s *aiaServer) count(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counts[path]
}

func (s *aiaServer) total() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	for _, c := range s.counts {
		n += c
	}
	return n
}

func (s *aiaServer) client() *http.Client {
	c := s.Client()
	c.Timeout = aiaTestTimeout
	return c
}

func serveDER(crt *x509.Certificate) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(crt.Raw)
	}
}

func certPEM(crt *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: crt.Raw,
	})
}

// aiaChain builds root -> ca1 -> ... -> caN -> leaf. Every non-root
// certificate lists bad first and then its issuer's URL, except ca1, whose
// only AIA URL is bad. It returns the root and the leaf.
func aiaChain(t testing.TB, s *aiaServer, depth int, bad string) (*testca.Entity, *testca.Entity) {
	t.Helper()
	root := bundlerCA(t, "Root", nil)
	parent := root
	var parentURL string
	for i := 1; i <= depth; i++ {
		urls := []string{bad}
		if parentURL != "" {
			urls = append(urls, parentURL)
		}
		ca := bundlerCA(t, fmt.Sprintf("CA %d", i), parent, testca.IssuingCertificateURL(urls...))
		parentURL = s.handle(fmt.Sprintf("/ca%d", i), serveDER(ca.Certificate))
		parent = ca
	}
	leaf := parent.Issue(
		testca.Subject(pkix.Name{CommonName: aiaLeafName}),
		testca.IssuingCertificateURL(bad, parentURL),
	)
	return root, leaf
}

// bundleWithin runs Bundle and fails the test if it does not return within
// aiaWatchdog, so a hanging fetch is reported instead of stalling the suite.
func bundleWithin(t *testing.T, b *certutil.Bundler, certs []*x509.Certificate) (*certutil.Chain, error) {
	t.Helper()
	type result struct {
		chain *certutil.Chain
		err   error
	}
	done := make(chan result, 1)
	go func() {
		chain, err := b.Bundle(certs, nil)
		done <- result{chain, err}
	}()
	select {
	case r := <-done:
		return r.chain, r.err
	case <-time.After(aiaWatchdog):
		t.Fatalf("Bundle did not return within %s", aiaWatchdog)
		return nil, nil
	}
}

// XPKI-039: each failing or duplicate AIA URL is requested at most once per
// Bundle call, independent of chain depth and backtracking.
func TestBundlerAIARequestsPerTraversal(t *testing.T) {
	t.Parallel()
	for _, depth := range []int{1, 2, 4} {
		t.Run(fmt.Sprintf("depth %d", depth), func(t *testing.T) {
			t.Parallel()
			s := newAIAServer(t)
			bad := s.handle(aiaBadPath, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
			})
			root, leaf := aiaChain(t, s, depth, bad)
			b, err := certutil.NewBundler([]*x509.Certificate{root.Certificate}, nil,
				certutil.WithAIA(true),
				certutil.WithHTTPClient(s.client()),
			)
			require.NoError(t, err)

			chain, err := bundleWithin(t, b, []*x509.Certificate{leaf.Certificate})
			require.NoError(t, err)
			assert.Len(t, chain.Chain, depth+1)
			assert.Equal(t, 1, s.count(aiaBadPath), "failing URL fetched once per traversal")
			for i := 1; i <= depth; i++ {
				assert.Equal(t, 1, s.count(fmt.Sprintf("/ca%d", i)), "issuer %d fetched once", i)
			}
			assert.Equal(t, depth+1, s.total())

			// The warm cache verifies without any further request.
			_, err = bundleWithin(t, b, []*x509.Certificate{leaf.Certificate})
			require.NoError(t, err)
			assert.Equal(t, depth+1, s.total())
		})
	}
}

// XPKI-039: a URL that failed in one Bundle call is retried by the next one.
func TestBundlerAIARetriesOnNextCall(t *testing.T) {
	t.Parallel()
	s := newAIAServer(t)
	root := bundlerCA(t, "Root", nil)
	var available atomic.Bool
	var intermediate *testca.Entity
	url := s.handle("/flaky", func(w http.ResponseWriter, _ *http.Request) {
		if !available.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write(intermediate.Certificate.Raw)
	})
	intermediate = bundlerCA(t, "Intermediate", root)
	leaf := intermediate.Issue(
		testca.Subject(pkix.Name{CommonName: aiaLeafName}),
		testca.IssuingCertificateURL(url, url),
	)
	b, err := certutil.NewBundler([]*x509.Certificate{root.Certificate}, nil,
		certutil.WithAIA(true),
		certutil.WithHTTPClient(s.client()),
	)
	require.NoError(t, err)

	_, err = bundleWithin(t, b, []*x509.Certificate{leaf.Certificate})
	var unknown x509.UnknownAuthorityError
	require.ErrorAs(t, err, &unknown)
	assert.Equal(t, 1, s.count("/flaky"), "duplicate URL fetched once")

	available.Store(true)
	chain, err := bundleWithin(t, b, []*x509.Certificate{leaf.Certificate})
	require.NoError(t, err)
	assert.Equal(t, []*x509.Certificate{leaf.Certificate, intermediate.Certificate}, chain.Chain)
	assert.Equal(t, 2, s.count("/flaky"))
}

// XPKI-037: only a complete, bounded 200 response is parsed.
func TestBundlerAIAResponseValidation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		// serve returns the AIA handler for the intermediate.
		serve func(crt *x509.Certificate) http.HandlerFunc
		ok    bool
	}{
		{
			name: "200 DER",
			serve: func(crt *x509.Certificate) http.HandlerFunc {
				return serveDER(crt)
			},
			ok: true,
		},
		{
			name: "200 PEM near limit",
			serve: func(crt *x509.Certificate) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					body := certPEM(crt)
					_, _ = w.Write(body)
					_, _ = w.Write(bytes.Repeat([]byte("\n"), certutil.MaxAIAResponseSize-len(body)))
				}
			},
			ok: true,
		},
		{
			name: "500 with valid DER",
			serve: func(crt *x509.Certificate) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write(crt.Raw)
				}
			},
		},
		{
			name: "404 with valid PEM",
			serve: func(crt *x509.Certificate) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write(certPEM(crt))
				}
			},
		},
		{
			name: "oversized chunked PEM",
			serve: func(crt *x509.Certificate) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					_, _ = w.Write(certPEM(crt))
					pad := bytes.Repeat([]byte("\n"), 64*1024)
					for range 2 * certutil.MaxAIAResponseSize / len(pad) {
						if _, err := w.Write(pad); err != nil {
							return
						}
						w.(http.Flusher).Flush()
					}
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newAIAServer(t)
			root := bundlerCA(t, "Root", nil)
			var intermediate *testca.Entity
			var handler http.HandlerFunc
			url := s.handle("/ca", func(w http.ResponseWriter, r *http.Request) {
				handler(w, r)
			})
			intermediate = bundlerCA(t, "Intermediate", root)
			handler = tc.serve(intermediate.Certificate)
			leaf := intermediate.Issue(
				testca.Subject(pkix.Name{CommonName: aiaLeafName}),
				testca.IssuingCertificateURL(url),
			)
			b, err := certutil.NewBundler([]*x509.Certificate{root.Certificate}, nil,
				certutil.WithAIA(true),
				certutil.WithHTTPClient(s.client()),
			)
			require.NoError(t, err)

			chain, err := bundleWithin(t, b, []*x509.Certificate{leaf.Certificate})
			assert.Equal(t, 1, s.count("/ca"))
			if tc.ok {
				require.NoError(t, err)
				assert.Equal(t, []*x509.Certificate{leaf.Certificate, intermediate.Certificate}, chain.Chain)
				return
			}
			var unknown x509.UnknownAuthorityError
			require.ErrorAs(t, err, &unknown)
			assert.Nil(t, chain)
			assert.False(t, b.KnownIssuers[string(intermediate.Certificate.Signature)])
		})
	}
}

// XPKI-037: a configured client without Timeout still gets a finite
// per-request deadline, so a stalled AIA server cannot hang Bundle.
func TestBundlerAIAStalledResponse(t *testing.T) {
	t.Parallel()
	s := newAIAServer(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	url := s.handle("/stall", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	root := bundlerCA(t, "Root", nil)
	intermediate := bundlerCA(t, "Intermediate", root)
	leaf := intermediate.Issue(
		testca.Subject(pkix.Name{CommonName: aiaLeafName}),
		testca.IssuingCertificateURL(url),
	)
	client := s.Client()
	client.Timeout = 0
	b, err := certutil.NewBundler([]*x509.Certificate{root.Certificate}, nil,
		certutil.WithAIA(true),
		certutil.WithHTTPClient(client),
	)
	require.NoError(t, err)

	start := time.Now()
	_, err = bundleWithin(t, b, []*x509.Certificate{leaf.Certificate})
	var unknown x509.UnknownAuthorityError
	require.ErrorAs(t, err, &unknown)
	assert.Less(t, time.Since(start), aiaWatchdog)
	assert.Equal(t, 1, s.count("/stall"))
}

// XPKI-037: cancelling the BundleContext context stops a pending AIA fetch
// and the error reports the cancellation.
func TestBundlerAIACancellation(t *testing.T) {
	t.Parallel()
	s := newAIAServer(t)
	started := make(chan struct{})
	var once sync.Once
	url := s.handle("/stall", func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(started) })
		<-r.Context().Done()
	})
	next := s.handle("/next", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	root := bundlerCA(t, "Root", nil)
	intermediate := bundlerCA(t, "Intermediate", root)
	leaf := intermediate.Issue(
		testca.Subject(pkix.Name{CommonName: aiaLeafName}),
		testca.IssuingCertificateURL(url, next),
	)
	client := s.Client()
	client.Timeout = time.Minute
	b, err := certutil.NewBundler([]*x509.Certificate{root.Certificate}, nil,
		certutil.WithAIA(true),
		certutil.WithHTTPClient(client),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		<-started
		cancel()
	}()
	done := make(chan error, 1)
	go func() {
		_, err := b.BundleContext(ctx, []*x509.Certificate{leaf.Certificate}, nil)
		done <- err
	}()
	select {
	case err = <-done:
	case <-time.After(aiaWatchdog):
		t.Fatalf("BundleContext did not return within %s", aiaWatchdog)
	}
	require.ErrorIs(t, err, context.Canceled)
	assert.ErrorContains(t, err, "unable to verify the certificate chain")
	assert.Zero(t, s.count("/next"), "no further URL is fetched after cancellation")

	// A cancelled context does not matter when no AIA fetch is needed.
	b, err = certutil.NewBundler([]*x509.Certificate{root.Certificate}, []*x509.Certificate{intermediate.Certificate})
	require.NoError(t, err)
	chain, err := b.ChainFromPEMContext(ctx, certPEM(leaf.Certificate), nil, "")
	require.NoError(t, err)
	assert.Equal(t, []*x509.Certificate{leaf.Certificate, intermediate.Certificate}, chain.Chain)
}

// XPKI-044: AIA requests go through the WithHTTPClient transport.
func TestBundlerAIAUsesInjectedClient(t *testing.T) {
	t.Parallel()
	s := newAIAServer(t)
	root := bundlerCA(t, "Root", nil)
	intermediate := bundlerCA(t, "Intermediate", root)
	url := s.handle("/ca", serveDER(intermediate.Certificate))
	leaf := intermediate.Issue(
		testca.Subject(pkix.Name{CommonName: aiaLeafName}),
		testca.IssuingCertificateURL(url),
	)
	var roundTrips atomic.Int32
	client := s.client()
	client.Transport = countingTransport{
		next:  client.Transport,
		count: &roundTrips,
	}
	b, err := certutil.NewBundler([]*x509.Certificate{root.Certificate}, nil,
		certutil.WithAIA(true),
		certutil.WithHTTPClient(client),
	)
	require.NoError(t, err)
	_, err = bundleWithin(t, b, []*x509.Certificate{leaf.Certificate})
	require.NoError(t, err)
	assert.Equal(t, int32(1), roundTrips.Load())
	assert.Equal(t, 1, s.count("/ca"))
}

type countingTransport struct {
	next  http.RoundTripper
	count *atomic.Int32
}

func (c countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.count.Add(1)
	return c.next.RoundTrip(r)
}

// XPKI-037: AIA diagnostics never include the response body. The test
// replaces the global log formatter, so it must not run in parallel.
func TestBundlerAIADoesNotLogBody(t *testing.T) {
	var out bytes.Buffer
	old := xlog.GetFormatter()
	xlog.SetFormatter(xlog.NewStringFormatter(&out))
	xlog.SetPackageLogLevel("github.com/effective-security/xpki", "certutil", xlog.DEBUG)
	t.Cleanup(func() {
		xlog.SetPackageLogLevel("github.com/effective-security/xpki", "certutil", xlog.INFO)
		xlog.SetFormatter(old)
	})

	s := newAIAServer(t)
	url := s.handle("/ca", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(aiaBodyMarker))
	})
	root := bundlerCA(t, "Root", nil)
	intermediate := bundlerCA(t, "Intermediate", root)
	leaf := intermediate.Issue(
		testca.Subject(pkix.Name{CommonName: aiaLeafName}),
		testca.IssuingCertificateURL(url),
	)
	b, err := certutil.NewBundler([]*x509.Certificate{root.Certificate}, nil,
		certutil.WithAIA(true),
		certutil.WithHTTPClient(s.client()),
	)
	require.NoError(t, err)
	_, err = bundleWithin(t, b, []*x509.Certificate{leaf.Certificate})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), aiaBodyMarker)

	logged := out.String()
	assert.Contains(t, logged, url, "the failure is still diagnosable")
	assert.NotContains(t, logged, aiaBodyMarker)
	assert.False(t, strings.Contains(logged, "data="), "no response bytes field")
}

// BenchmarkBundlerAIAFailingURL measures AIA requests per cold Bundle call
// when every certificate lists one failing URL before its issuer (XPKI-039).
func BenchmarkBundlerAIAFailingURL(b *testing.B) {
	for _, depth := range []int{1, 2, 4, 8} {
		b.Run(fmt.Sprintf("depth=%d", depth), func(b *testing.B) {
			s := newAIAServer(b)
			bad := s.handle(aiaBadPath, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
			})
			root, leaf := aiaChain(b, s, depth, bad)
			certs := []*x509.Certificate{leaf.Certificate}
			roots := []*x509.Certificate{root.Certificate}
			client := s.client()
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				bundler, err := certutil.NewBundler(roots, nil,
					certutil.WithAIA(true),
					certutil.WithHTTPClient(client),
				)
				if err != nil {
					b.Fatal(err)
				}
				if _, err = bundler.Bundle(certs, nil); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(s.total())/float64(b.N), "requests/op")
			b.ReportMetric(float64(s.count(aiaBadPath))/float64(b.N), "failed/op")
		})
	}
}

package certutil_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

// inputChain is a root, an intermediate and a leaf for the input tests.
type inputChain struct {
	root, intermediate, leaf *testca.Entity
}

func newInputChain(t *testing.T) *inputChain {
	t.Helper()
	root := bundlerCA(t, "Input Root", nil)
	intermediate := bundlerCA(t, "Input Intermediate", root)
	leaf := intermediate.Issue(testca.Subject(pkix.Name{CommonName: "input.example.test"}))
	return &inputChain{
		root:         root,
		intermediate: intermediate,
		leaf:         leaf,
	}
}

// XPKI-036: Bundle and BundleContext reject input without a certificate
// instead of returning (nil, nil).
func TestBundlerEmptyInput(t *testing.T) {
	t.Parallel()
	c := newInputChain(t)
	force, err := certutil.NewBundler(nil, nil, certutil.WithBundleFlavor(certutil.Force))
	require.NoError(t, err)
	optimal, err := certutil.NewBundler([]*x509.Certificate{c.root.Certificate}, nil)
	require.NoError(t, err)

	for _, tc := range []struct {
		name  string
		certs []*x509.Certificate
		want  string
		empty bool
	}{
		{name: "nil", certs: nil, want: "no certificates", empty: true},
		{name: "empty", certs: []*x509.Certificate{}, want: "no certificates", empty: true},
		{name: "nil leaf", certs: []*x509.Certificate{nil}, want: "nil certificate at index 0"},
		{name: "nil intermediate", certs: []*x509.Certificate{c.leaf.Certificate, nil}, want: "nil certificate at index 1"},
	} {
		for _, flavor := range []struct {
			name string
			b    *certutil.Bundler
		}{
			{name: "force", b: force},
			{name: "optimal", b: optimal},
		} {
			t.Run(tc.name+"/"+flavor.name, func(t *testing.T) {
				t.Parallel()
				chain, err := flavor.b.Bundle(tc.certs, nil)
				require.EqualError(t, err, tc.want)
				assert.Nil(t, chain)
				assert.Equal(t, tc.empty, errors.Is(err, certutil.ErrNoCertificates))

				chain, err = flavor.b.BundleContext(context.Background(), tc.certs, c.leaf.PrivateKey)
				require.EqualError(t, err, tc.want)
				assert.Nil(t, chain)
				assert.Equal(t, tc.empty, errors.Is(err, certutil.ErrNoCertificates))
			})
		}
	}

	// A PEM without certificates keeps its existing parse error.
	_, err = force.ChainFromPEM([]byte("-----BEGIN X-----\nAA==\n-----END X-----\n"), nil, "")
	require.EqualError(t, err, "failed to parse certificates")
}

// XPKI-042: BuildBundle validates the members it dereferences, treats a nil
// Status as empty, and keeps rootless Force chains valid.
func TestBuildBundleInput(t *testing.T) {
	t.Parallel()
	c := newInputChain(t)
	leaf := c.leaf.Certificate

	for _, tc := range []struct {
		name  string
		chain *certutil.Chain
		want  string
	}{
		{name: "nil chain", chain: nil, want: "chain is nil"},
		{name: "nil cert", chain: &certutil.Chain{Chain: []*x509.Certificate{leaf}}, want: "chain has no leaf certificate: no certificates"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			bundle, status, err := certutil.BuildBundle(tc.chain)
			require.EqualError(t, err, tc.want)
			assert.Nil(t, bundle)
			assert.Nil(t, status)
		})
	}

	t.Run("nil status", func(t *testing.T) {
		t.Parallel()
		bundle, status, err := certutil.BuildBundle(&certutil.Chain{
			Chain:   []*x509.Certificate{leaf, c.intermediate.Certificate},
			Cert:    leaf,
			Expires: leaf.NotAfter,
		})
		require.NoError(t, err)
		assert.Equal(t, &certutil.BundleStatus{}, status)
		assert.False(t, status.IsExpiring())
		assert.False(t, status.IsUntrusted())
		assert.Same(t, leaf, bundle.Cert)
		assert.Same(t, c.intermediate.Certificate, bundle.IssuerCert)
		assert.Nil(t, bundle.RootCert)
		assert.Empty(t, bundle.RootCertPEM)
		assert.Equal(t, leaf.NotAfter, bundle.Expires)
	})

	t.Run("force without root", func(t *testing.T) {
		t.Parallel()
		force, err := certutil.NewBundler(nil, nil, certutil.WithBundleFlavor(certutil.Force))
		require.NoError(t, err)
		chain, err := force.Bundle([]*x509.Certificate{leaf, c.intermediate.Certificate}, nil)
		require.NoError(t, err)
		require.Nil(t, chain.Root)
		bundle, status, err := certutil.BuildBundle(chain)
		require.NoError(t, err)
		assert.Equal(t, chain.Status.Code, status.Code)
		assert.Nil(t, bundle.RootCert)
		assert.Empty(t, bundle.RootCertPEM)
		assert.Same(t, c.intermediate.Certificate, bundle.IssuerCert)
		caPEM, err := certutil.EncodeToPEMString(false, c.intermediate.Certificate)
		require.NoError(t, err)
		assert.Equal(t, caPEM, bundle.CACertsPEM)
	})

	t.Run("optimal with root", func(t *testing.T) {
		t.Parallel()
		optimal, err := certutil.NewBundler([]*x509.Certificate{c.root.Certificate}, []*x509.Certificate{c.intermediate.Certificate})
		require.NoError(t, err)
		chain, err := optimal.Bundle([]*x509.Certificate{leaf}, nil)
		require.NoError(t, err)
		bundle, _, err := certutil.BuildBundle(chain)
		require.NoError(t, err)
		assert.Same(t, c.root.Certificate, bundle.RootCert)
		rootPEM, err := certutil.EncodeToPEMString(false, c.root.Certificate)
		require.NoError(t, err)
		assert.Equal(t, rootPEM, bundle.RootCertPEM)
	})
}

// XPKI-038: SortBundlesByExpiration returns a stably sorted copy and leaves
// the caller's slice alone.
func TestSortBundlesByExpirationContract(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	bundle := func(name string, expires time.Duration) *certutil.Bundle {
		return &certutil.Bundle{
			Subject: &pkix.Name{CommonName: name},
			Expires: now.Add(expires),
		}
	}
	a := bundle("a", time.Hour)
	b := bundle("b", 2*time.Hour)
	c := bundle("c", time.Hour)
	d := bundle("d", 2*time.Hour)
	e := bundle("e", 3*time.Hour)

	for _, tc := range []struct {
		name string
		in   []*certutil.Bundle
		want []*certutil.Bundle
	}{
		{name: "nil", in: nil, want: nil},
		{name: "empty", in: []*certutil.Bundle{}, want: []*certutil.Bundle{}},
		{name: "one", in: []*certutil.Bundle{a}, want: []*certutil.Bundle{a}},
		{name: "distinct", in: []*certutil.Bundle{a, e, b}, want: []*certutil.Bundle{e, b, a}},
		{name: "equal keeps input order", in: []*certutil.Bundle{a, b, c, d, e}, want: []*certutil.Bundle{e, b, d, a, c}},
		{name: "equal reversed input", in: []*certutil.Bundle{c, d, a, b}, want: []*certutil.Bundle{d, b, c, a}},
		{name: "nil entries last", in: []*certutil.Bundle{nil, a, nil, e}, want: []*certutil.Bundle{e, a, nil, nil}},
		{name: "adjacent nils", in: []*certutil.Bundle{nil, nil, a}, want: []*certutil.Bundle{a, nil, nil}},
		{name: "nil after bundle", in: []*certutil.Bundle{a, nil, b}, want: []*certutil.Bundle{b, a, nil}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			in := tc.in
			orig := slices.Clone(in)
			sorted := certutil.SortBundlesByExpiration(in)
			assert.Equal(t, tc.want, sorted)
			assert.Equal(t, tc.in == nil, sorted == nil)
			// The caller's slice keeps its order.
			assert.Equal(t, orig, in)
			if len(sorted) > 0 {
				// The result does not share the caller's backing array.
				sorted[0] = nil
				assert.Equal(t, orig, in)
				assert.NotSame(t, &in[0], &sorted[0])
			}
		})
	}
}

// XPKI-103: CreateOCSPRequest rejects missing certificates and an unavailable
// hash instead of panicking.
func TestCreateOCSPRequestInput(t *testing.T) {
	t.Parallel()
	c := newInputChain(t)
	leaf := c.leaf.Certificate
	issuer := c.intermediate.Certificate

	for _, tc := range []struct {
		name        string
		crt, issuer *x509.Certificate
		hash        crypto.Hash
		want        string
	}{
		{name: "nil cert", crt: nil, issuer: issuer, hash: crypto.SHA256, want: "certificate is nil"},
		{name: "nil issuer", crt: leaf, issuer: nil, hash: crypto.SHA256, want: "issuer certificate is nil"},
		{name: "both nil", crt: nil, issuer: nil, hash: crypto.SHA256, want: "certificate is nil"},
		{name: "unavailable hash", crt: leaf, issuer: issuer, hash: crypto.Hash(0), want: "hash algorithm is not available: unknown hash value 0"},
		{name: "mismatch", crt: leaf, issuer: leaf, hash: crypto.SHA256, want: "invalid chain: issuer does not match"},
		{name: "root is not the issuer", crt: leaf, issuer: c.root.Certificate, hash: crypto.SHA256, want: "invalid chain: issuer does not match"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var der []byte
			var err error
			require.NotPanics(t, func() {
				der, err = certutil.CreateOCSPRequest(tc.crt, tc.issuer, tc.hash)
			})
			require.EqualError(t, err, tc.want)
			assert.Nil(t, der)
		})
	}

	for _, hash := range []crypto.Hash{crypto.SHA1, crypto.SHA256} {
		t.Run("valid "+hash.String(), func(t *testing.T) {
			t.Parallel()
			der, err := certutil.CreateOCSPRequest(leaf, issuer, hash)
			require.NoError(t, err)
			req, err := ocsp.ParseRequest(der)
			require.NoError(t, err)
			assert.Equal(t, hash, req.HashAlgorithm)
			assert.Equal(t, 0, leaf.SerialNumber.Cmp(req.SerialNumber))
			// The issuer name hash matches the one a response is built for.
			want, err := ocsp.CreateRequest(leaf, issuer, &ocsp.RequestOptions{Hash: hash})
			require.NoError(t, err)
			wantReq, err := ocsp.ParseRequest(want)
			require.NoError(t, err)
			assert.True(t, bytes.Equal(wantReq.IssuerKeyHash, req.IssuerKeyHash))
		})
	}
}

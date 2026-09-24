package certutil_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// rootsChildEnv selects the subprocess half of TestBundlerSystemRoots.
	rootsChildEnv    = "XPKI_TEST_BUNDLER_SYSTEM_ROOTS"
	rootsSystemEnv   = "XPKI_TEST_SYSTEM_CHAIN"
	rootsExplicitEnv = "XPKI_TEST_EXPLICIT_ROOT"
	rootsOtherEnv    = "XPKI_TEST_EXPLICIT_CHAIN"
	errNoTrustRoots  = "optimal bundle requires trust roots: provide roots or WithSystemRoots"
)

// XPKI-041: the flavor resolves the same way for nil and empty roots in any
// option order, and Optimal never runs without trust roots.
func TestNewBundlerTrustRoots(t *testing.T) {
	t.Parallel()
	root := bundlerCA(t, "Root", nil)
	intermediate := bundlerCA(t, "Intermediate", root)
	leaf := intermediate.Issue(testca.Subject(pkix.Name{CommonName: "leaf"}))
	other := bundlerCA(t, "Other Root", nil)
	otherLeaf := other.Issue(testca.Subject(pkix.Name{CommonName: "other"}))
	input := []*x509.Certificate{leaf.Certificate, intermediate.Certificate}

	force := certutil.WithBundleFlavor(certutil.Force)
	optimal := certutil.WithBundleFlavor(certutil.Optimal)
	rootSets := map[string][]*x509.Certificate{
		"nil":   nil,
		"empty": {},
		"root":  {root.Certificate},
	}
	for _, tc := range []struct {
		name string
		opts []certutil.Option
		// want is the resolved flavor per root set; empty means NewBundler fails.
		want map[string]certutil.BundleFlavor
	}{
		{
			name: "default",
			want: map[string]certutil.BundleFlavor{"nil": certutil.Force, "empty": certutil.Force, "root": certutil.Optimal},
		},
		{
			name: "force",
			opts: []certutil.Option{force},
			want: map[string]certutil.BundleFlavor{"nil": certutil.Force, "empty": certutil.Force, "root": certutil.Force},
		},
		{
			name: "optimal",
			opts: []certutil.Option{optimal},
			want: map[string]certutil.BundleFlavor{"root": certutil.Optimal},
		},
		{
			name: "optimal then force",
			opts: []certutil.Option{optimal, force},
			want: map[string]certutil.BundleFlavor{"nil": certutil.Force, "empty": certutil.Force, "root": certutil.Force},
		},
		{
			name: "force then optimal",
			opts: []certutil.Option{force, optimal},
			want: map[string]certutil.BundleFlavor{"root": certutil.Optimal},
		},
		{
			name: "system roots disabled",
			opts: []certutil.Option{certutil.WithSystemRoots(false), optimal},
			want: map[string]certutil.BundleFlavor{"root": certutil.Optimal},
		},
	} {
		for setName, roots := range rootSets {
			t.Run(tc.name+"/"+setName, func(t *testing.T) {
				t.Parallel()
				b, err := certutil.NewBundler(roots, nil, tc.opts...)
				want, ok := tc.want[setName]
				if !ok {
					require.EqualError(t, err, errNoTrustRoots)
					assert.Nil(t, b)
					return
				}
				require.NoError(t, err)
				assert.NotNil(t, b.VerifyOptions().Roots, "verification never uses nil Roots")

				chain, err := b.Bundle(input, nil)
				require.NoError(t, err)
				_, otherErr := b.Bundle([]*x509.Certificate{otherLeaf.Certificate}, nil)
				switch want {
				case certutil.Force:
					assert.Nil(t, chain.Root)
					assert.Equal(t, input, chain.Chain)
					require.NoError(t, otherErr, "Force checks signatures only")
				case certutil.Optimal:
					assert.Same(t, root.Certificate, chain.Root)
					var unknown x509.UnknownAuthorityError
					require.ErrorAs(t, otherErr, &unknown, "an unknown root fails deterministically")
				}
			})
		}
	}

	t.Run("unsupported flavor", func(t *testing.T) {
		t.Parallel()
		b, err := certutil.NewBundler([]*x509.Certificate{root.Certificate}, nil, certutil.WithBundleFlavor("fastest"))
		require.EqualError(t, err, `unsupported bundle flavor "fastest"`)
		assert.Nil(t, b)
	})

	t.Run("RootPool cleared after construction", func(t *testing.T) {
		t.Parallel()
		b, err := certutil.NewBundler([]*x509.Certificate{root.Certificate}, nil)
		require.NoError(t, err)
		b.RootPool = nil
		chain, err := b.Bundle(input, nil)
		require.EqualError(t, err, "no trust roots configured")
		assert.Nil(t, chain)
		assert.NotNil(t, b.VerifyOptions().Roots)
	})
}

// XPKI-041: system roots are trusted only with WithSystemRoots. The system
// trust store is replaced by a generated root in a subprocess through
// SSL_CERT_FILE and SSL_CERT_DIR, so the result does not depend on this
// machine's roots.
func TestBundlerSystemRoots(t *testing.T) {
	switch runtime.GOOS {
	case "darwin", "ios", "windows":
		t.Skipf("SSL_CERT_FILE does not replace the %s trust store", runtime.GOOS)
	}
	if os.Getenv(rootsChildEnv) != "" {
		systemRootsChild(t)
		return
	}
	t.Parallel()

	dir := t.TempDir()
	system := bundlerCA(t, "System Root", nil)
	systemCA := bundlerCA(t, "System CA", system)
	systemLeaf := systemCA.Issue(testca.Subject(pkix.Name{CommonName: "system"}))
	explicit := bundlerCA(t, "Explicit Root", nil)
	explicitLeaf := explicit.Issue(testca.Subject(pkix.Name{CommonName: "explicit"}))

	files := map[string][]byte{
		"system-root.pem":    certPEM(system.Certificate),
		"system-chain.pem":   append(certPEM(systemLeaf.Certificate), certPEM(systemCA.Certificate)...),
		"explicit-root.pem":  certPEM(explicit.Certificate),
		"explicit-chain.pem": certPEM(explicitLeaf.Certificate),
	}
	for name, data := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), data, 0600))
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestBundlerSystemRoots$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(),
		rootsChildEnv+"=1",
		"SSL_CERT_FILE="+filepath.Join(dir, "system-root.pem"),
		"SSL_CERT_DIR="+t.TempDir(),
		rootsSystemEnv+"="+filepath.Join(dir, "system-chain.pem"),
		rootsExplicitEnv+"="+filepath.Join(dir, "explicit-root.pem"),
		rootsOtherEnv+"="+filepath.Join(dir, "explicit-chain.pem"),
	)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", out)
	assert.Contains(t, string(out), "--- PASS: TestBundlerSystemRoots")
}

func systemRootsChild(t *testing.T) {
	load := func(env string) []*x509.Certificate {
		certs, err := certutil.LoadChainFromPEM(os.Getenv(env))
		require.NoError(t, err)
		return certs
	}
	systemChain := load(rootsSystemEnv)
	explicitRoots := load(rootsExplicitEnv)
	explicitChain := load(rootsOtherEnv)
	var unknown x509.UnknownAuthorityError

	// The generated root is the process trust store...
	pool, err := x509.SystemCertPool()
	require.NoError(t, err)
	_, err = systemChain[0].Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: certPool(systemChain[1:]),
	})
	require.NoError(t, err)

	// ...yet a Bundler without WithSystemRoots never trusts it.
	b, err := certutil.NewBundler(nil, nil, certutil.WithBundleFlavor(certutil.Optimal))
	require.EqualError(t, err, errNoTrustRoots)
	assert.Nil(t, b)
	b, err = certutil.NewBundler(explicitRoots, nil)
	require.NoError(t, err)
	_, err = b.Bundle(systemChain, nil)
	require.ErrorAs(t, err, &unknown)

	// WithSystemRoots defaults to Optimal and anchors on the system root.
	b, err = certutil.NewBundler(nil, nil, certutil.WithSystemRoots(true))
	require.NoError(t, err)
	chain, err := b.Bundle(systemChain, nil)
	require.NoError(t, err)
	assert.Equal(t, "System Root", chain.Root.Subject.CommonName)
	_, err = b.Bundle(explicitChain, nil)
	require.ErrorAs(t, err, &unknown)

	// Explicit roots are added to the system roots.
	b, err = certutil.NewBundler(explicitRoots, nil, certutil.WithSystemRoots(true))
	require.NoError(t, err)
	chain, err = b.Bundle(systemChain, nil)
	require.NoError(t, err)
	assert.Equal(t, "System Root", chain.Root.Subject.CommonName)
	chain, err = b.Bundle(explicitChain, nil)
	require.NoError(t, err)
	assert.Equal(t, "Explicit Root", chain.Root.Subject.CommonName)

	// Force ignores the system roots.
	b, err = certutil.NewBundler(nil, nil, certutil.WithSystemRoots(true), certutil.WithBundleFlavor(certutil.Force))
	require.NoError(t, err)
	chain, err = b.Bundle(systemChain, nil)
	require.NoError(t, err)
	assert.Nil(t, chain.Root)
}

func certPool(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool
}

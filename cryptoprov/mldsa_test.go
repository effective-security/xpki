package cryptoprov_test

import (
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"strconv"
	"strings"
	"testing"

	"github.com/effective-security/xpki/cryptoprov"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMLDSAParameters(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		size int
		want mldsa.Parameters
	}{
		{cryptoprov.MLDSA44, mldsa.MLDSA44()},
		{cryptoprov.MLDSA65, mldsa.MLDSA65()},
		{cryptoprov.MLDSA87, mldsa.MLDSA87()},
	} {
		params, err := cryptoprov.MLDSAParameters(tc.size)
		require.NoError(t, err)
		assert.Equal(t, tc.want, params)
	}
	for _, size := range []int{0, 2, 3, 5, 256, 2048} {
		_, err := cryptoprov.MLDSAParameters(size)
		require.EqualError(t, err, "invalid ML-DSA parameter set (expected 44, 65 or 87): "+strconv.Itoa(size))
	}
}

// TestMLDSASignerOptions tables the D4 signer contract: the message with
// nil, zero-hash or *mldsa.Options, μ with crypto.MLDSAMu, and an error for
// every digest hash.
func TestMLDSASignerOptions(t *testing.T) {
	t.Parallel()
	var nilOptions *mldsa.Options
	var nilPSS *rsa.PSSOptions
	long := strings.Repeat("c", 256)
	for _, tc := range []struct {
		name    string
		opts    crypto.SignerOpts
		mu      bool
		context string
		err     string
	}{
		{name: "nil", opts: nil},
		{name: "typed nil options", opts: nilOptions},
		{name: "typed nil pss", opts: nilPSS, err: "ML-DSA signs a message, not a digest: unsupported signer options *rsa.PSSOptions"},
		{name: "zero hash", opts: crypto.Hash(0)},
		{name: "empty options", opts: &mldsa.Options{}},
		{name: "context", opts: &mldsa.Options{Context: "xpki"}, context: "xpki"},
		{name: "max context", opts: &mldsa.Options{Context: long[:255]}, context: long[:255]},
		{name: "long context", opts: &mldsa.Options{Context: long}, err: "ML-DSA context is too long: 256 bytes (at most 255)"},
		{name: "mu", opts: crypto.MLDSAMu, mu: true},
		{name: "sha256", opts: crypto.SHA256, err: "ML-DSA signs a message, not a digest: unsupported signer options SHA-256"},
		{name: "sha512", opts: crypto.SHA512, err: "ML-DSA signs a message, not a digest: unsupported signer options SHA-512"},
		{name: "pss", opts: &rsa.PSSOptions{Hash: crypto.SHA384}, err: "ML-DSA signs a message, not a digest: unsupported signer options SHA-384"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mu, context, err := cryptoprov.MLDSASignerOptions(tc.opts)
			if tc.err != "" {
				require.EqualError(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.mu, mu)
			assert.Equal(t, tc.context, context)
		})
	}
}

// TestMLDSAMu checks μ against the standard library: a signature over the
// locally computed μ verifies as a signature of the message, with and
// without a context, for every parameter set.
func TestMLDSAMu(t *testing.T) {
	t.Parallel()
	message := []byte("to be signed by an external μ operation")
	for _, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		t.Run(params.String(), func(t *testing.T) {
			t.Parallel()
			priv, err := mldsa.GenerateKey(params)
			require.NoError(t, err)
			pub := priv.PublicKey()

			for _, context := range []string{"", "xpki", strings.Repeat("c", 255)} {
				mu, err := cryptoprov.MLDSAMu(pub, context, message)
				require.NoError(t, err)
				require.Len(t, mu, cryptoprov.MLDSAMuSize)

				sig, err := priv.Sign(rand.Reader, mu, crypto.MLDSAMu)
				require.NoError(t, err)
				require.NoError(t, mldsa.Verify(pub, message, sig, &mldsa.Options{Context: context}), "context %q", context)
				if context != "" {
					require.Error(t, mldsa.Verify(pub, message, sig, nil), "the context is part of μ")
				}
				// the deterministic variant over μ verifies the same way
				sig, err = priv.SignDeterministic(mu, crypto.MLDSAMu)
				require.NoError(t, err)
				require.NoError(t, mldsa.Verify(pub, message, sig, &mldsa.Options{Context: context}))
			}

			other, err := cryptoprov.MLDSAMu(pub, "", []byte("another message"))
			require.NoError(t, err)
			first, err := cryptoprov.MLDSAMu(pub, "", message)
			require.NoError(t, err)
			assert.NotEqual(t, first, other)

			_, err = cryptoprov.MLDSAMu(pub, strings.Repeat("c", 256), message)
			require.EqualError(t, err, "ML-DSA context is too long: 256 bytes (at most 255)")
		})
	}
	_, err := cryptoprov.MLDSAMu(nil, "", message)
	require.EqualError(t, err, "ML-DSA public key is required")
}

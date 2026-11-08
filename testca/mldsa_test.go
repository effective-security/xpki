package testca_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"

	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// TestMLDSAEntity builds a two-level chain with the MLDSAKey option and
// checks the keys, signature algorithms and encodings.
func TestMLDSAEntity(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		params mldsa.Parameters
		want   x509.SignatureAlgorithm
	}{
		{mldsa.MLDSA44(), x509.MLDSA44},
		{mldsa.MLDSA65(), x509.MLDSA65},
		{mldsa.MLDSA87(), x509.MLDSA87},
	} {
		t.Run(tc.want.String(), func(t *testing.T) {
			t.Parallel()
			root := testca.NewEntity(
				testca.Authority,
				testca.MLDSAKey(tc.params),
				testca.Subject(pkix.Name{CommonName: "[TEST] PQ Root"}),
				testca.KeyUsage(x509.KeyUsageCertSign|x509.KeyUsageCRLSign),
			)
			rootKey, ok := root.PrivateKey.(*mldsa.PrivateKey)
			require.True(t, ok, "%T", root.PrivateKey)
			assert.Equal(t, tc.params, rootKey.PublicKey().Parameters())
			assert.Equal(t, tc.want, root.Certificate.SignatureAlgorithm)
			assert.Equal(t, x509.MLDSA, root.Certificate.PublicKeyAlgorithm)
			require.NoError(t, root.Certificate.CheckSignatureFrom(root.Certificate))

			// an ML-DSA leaf of another set and an ECDSA leaf, both signed by the root
			leaf := root.Issue(testca.MLDSAKey(mldsa.MLDSA44()), testca.DNSName("pq.example.com"))
			assert.Equal(t, tc.want, leaf.Certificate.SignatureAlgorithm)
			assert.Equal(t, x509.MLDSA, leaf.Certificate.PublicKeyAlgorithm)
			ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			ecLeaf := root.Issue(testca.PrivateKey(ecKey), testca.DNSName("ec.example.com"))
			assert.Equal(t, tc.want, ecLeaf.Certificate.SignatureAlgorithm)
			assert.Equal(t, x509.ECDSA, ecLeaf.Certificate.PublicKeyAlgorithm)

			roots := x509.NewCertPool()
			roots.AddCert(root.Certificate)
			for _, e := range []*testca.Entity{leaf, ecLeaf} {
				_, err := e.Certificate.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
				require.NoError(t, err)
				assert.True(t, certutil.IsPostQuantumCertificate(e.Certificate))
			}

			// a PrivateKey option wins over MLDSAKey
			fixed := testca.NewEntity(testca.PrivateKey(ecKey), testca.MLDSAKey(tc.params))
			assert.Same(t, ecKey, fixed.PrivateKey)

			// encodings
			block, _ := pem.Decode(testca.PrivKeyToPEM(rootKey))
			require.NotNil(t, block)
			assert.Equal(t, "PRIVATE KEY", block.Type)
			parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			require.NoError(t, err)
			assert.True(t, rootKey.Equal(parsed))
			assert.Equal(t, block.Bytes, testca.ToDER(rootKey))
			assert.Equal(t, testca.PrivKeyToPEM(rootKey), testca.ToPKCS8(rootKey))
			pfxKey, pfxCert, err := pkcs12.Decode(testca.ToPFX(root.Certificate, rootKey, "pass"), "pass")
			require.NoError(t, err)
			assert.True(t, rootKey.Equal(pfxKey))
			assert.True(t, root.Certificate.Equal(pfxCert))

			dir := t.TempDir()
			require.NoError(t, root.SaveCertAndKey(dir+"/pq.pem", dir+"/pq.key", false))
			signer, err := certutil.ParsePrivateKeyPEM(testca.PrivKeyToPEM(rootKey))
			require.NoError(t, err)
			assert.True(t, rootKey.Equal(signer))
		})
	}
}

func TestGenerateMLDSAKeyInPEM(t *testing.T) {
	t.Parallel()
	pemKey, err := testca.GenerateMLDSAKeyInPEM(mldsa.MLDSA65())
	require.NoError(t, err)
	signer, err := certutil.ParsePrivateKeyPEM(pemKey)
	require.NoError(t, err)
	key, ok := signer.(*mldsa.PrivateKey)
	require.True(t, ok, "%T", signer)
	assert.Equal(t, mldsa.MLDSA65(), key.PublicKey().Parameters())
}

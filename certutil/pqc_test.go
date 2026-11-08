package certutil_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pqcTestdata holds the OpenSSL 3.5 ML-DSA interoperability vectors; see
// its README.md for the commands that generated them.
const pqcTestdata = "testdata/pqc"

// pqcVector reads a PEM vector of the parameter set size: "key", "pub",
// "csr" or "crt".
func pqcVector(t *testing.T, size int, kind string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(pqcTestdata, "mldsa"+strconv.Itoa(size)+"."+kind))
	require.NoError(t, err)
	return data
}

func TestIsPostQuantumKey(t *testing.T) {
	t.Parallel()
	mlKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	var nilPub *mldsa.PublicKey
	var nilPriv *mldsa.PrivateKey

	for _, tc := range []struct {
		name string
		key  any
		want bool
	}{
		{"mldsa private", mlKey, true},
		{"mldsa public", mlKey.PublicKey(), true},
		{"mldsa public as crypto.PublicKey", mlKey.Public(), true},
		{"opaque mldsa signer", opaqueSigner{mlKey}, true},
		{"rsa private", rsaKey, false},
		{"rsa public", rsaKey.Public(), false},
		{"opaque rsa signer", opaqueSigner{rsaKey}, false},
		{"opaque rsa decrypter", opaqueDecrypter{rsaKey}, false},
		{"ecdsa private", ecKey, false},
		{"ecdsa public", ecKey.Public(), false},
		{"nil", nil, false},
		{"typed nil public", nilPub, false},
		{"typed nil private", nilPriv, false},
		{"string", "not a key", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, certutil.IsPostQuantumKey(tc.key))
		})
	}
}

func TestIsPostQuantumSignatureAlgorithm(t *testing.T) {
	t.Parallel()
	for _, algo := range []x509.SignatureAlgorithm{x509.MLDSA44, x509.MLDSA65, x509.MLDSA87} {
		assert.True(t, certutil.IsPostQuantumSignatureAlgorithm(algo), algo.String())
	}
	for _, algo := range []x509.SignatureAlgorithm{
		x509.UnknownSignatureAlgorithm, x509.SHA256WithRSA, x509.SHA384WithRSAPSS,
		x509.ECDSAWithSHA256, x509.ECDSAWithSHA512, x509.PureEd25519,
	} {
		assert.False(t, certutil.IsPostQuantumSignatureAlgorithm(algo), algo.String())
	}
}

// TestIsPostQuantumCertificate uses the OpenSSL vectors (ML-DSA key and
// signature), a classical testca certificate, and mixed chains built here:
// an ML-DSA CA signing an ECDSA leaf and an ECDSA CA signing an ML-DSA leaf
// are both post-quantum at one end.
func TestIsPostQuantumCertificate(t *testing.T) {
	t.Parallel()
	for _, size := range []int{44, 65, 87} {
		crt, err := certutil.ParseFromPEM(pqcVector(t, size, "crt"))
		require.NoError(t, err)
		assert.True(t, certutil.IsPostQuantumCertificate(crt))
		assert.Equal(t, x509.MLDSA, crt.PublicKeyAlgorithm)
	}

	classical := testca.NewEntity(testca.Authority)
	assert.False(t, certutil.IsPostQuantumCertificate(classical.Certificate))
	assert.False(t, certutil.IsPostQuantumCertificate(nil))

	pqKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pqCA := testca.NewEntity(testca.Authority, testca.PrivateKey(pqKey), testca.KeyUsage(x509.KeyUsageCertSign))
	assert.True(t, certutil.IsPostQuantumCertificate(pqCA.Certificate))
	ecLeaf := pqCA.Issue(testca.PrivateKey(ecKey), testca.DNSName("ec.example.com"))
	assert.Equal(t, x509.ECDSA, ecLeaf.Certificate.PublicKeyAlgorithm)
	assert.Equal(t, x509.MLDSA65, ecLeaf.Certificate.SignatureAlgorithm)
	assert.True(t, certutil.IsPostQuantumCertificate(ecLeaf.Certificate), "signed by an ML-DSA key")

	ecCA := testca.NewEntity(testca.Authority, testca.PrivateKey(ecKey), testca.KeyUsage(x509.KeyUsageCertSign))
	pqLeaf := ecCA.Issue(testca.PrivateKey(pqKey), testca.DNSName("pq.example.com"))
	assert.Equal(t, x509.MLDSA, pqLeaf.Certificate.PublicKeyAlgorithm)
	assert.Equal(t, x509.ECDSAWithSHA256, pqLeaf.Certificate.SignatureAlgorithm)
	assert.True(t, certutil.IsPostQuantumCertificate(pqLeaf.Certificate), "ML-DSA public key")
	require.NoError(t, pqLeaf.Certificate.CheckSignatureFrom(ecCA.Certificate))
	require.NoError(t, ecLeaf.Certificate.CheckSignatureFrom(pqCA.Certificate))
}

// TestPQCVectors parses the OpenSSL 3.5 vectors: the seed-only PKCS#8 key,
// the SPKI, a CSR and a self-signed certificate per parameter set, checking
// that they belong together and verify. The PKCS#8 form that carries both
// the seed and the expanded key is rejected by the standard library.
func TestPQCVectors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		size int
		want x509.SignatureAlgorithm
	}{
		{44, x509.MLDSA44},
		{65, x509.MLDSA65},
		{87, x509.MLDSA87},
	} {
		t.Run(tc.want.String(), func(t *testing.T) {
			t.Parallel()
			signer, err := certutil.ParsePrivateKeyPEM(pqcVector(t, tc.size, "key"))
			require.NoError(t, err)
			priv, ok := signer.(*mldsa.PrivateKey)
			require.True(t, ok, "%T", signer)

			generic, err := cryptoprov.ParsePrivateKeyPEM(pqcVector(t, tc.size, "key"))
			require.NoError(t, err)
			assert.True(t, priv.Equal(generic))

			ki, err := certutil.NewKeyInfo(priv)
			require.NoError(t, err)
			assert.Equal(t, certutil.KeyTypeMLDSA, ki.Type)
			assert.Equal(t, tc.size, ki.KeySize)
			assert.True(t, ki.IsPrivate)
			assert.Equal(t, crypto.Hash(0), ki.Hash)

			pubDER, err := certutil.GetKeyDERFromPEM(pqcVector(t, tc.size, "pub"), nil)
			require.NoError(t, err)
			pub, err := x509.ParsePKIXPublicKey(pubDER)
			require.NoError(t, err)
			assert.True(t, priv.PublicKey().Equal(pub))

			pem, err := certutil.EncodePublicKeyToPEM(pub)
			require.NoError(t, err)
			assert.Equal(t, string(pqcVector(t, tc.size, "pub")), string(pem), "SPKI round trip")

			csrDER, err := certutil.GetKeyDERFromPEM(pqcVector(t, tc.size, "csr"), nil)
			require.NoError(t, err)
			csr, err := x509.ParseCertificateRequest(csrDER)
			require.NoError(t, err)
			require.NoError(t, csr.CheckSignature())
			assert.Equal(t, tc.want, csr.SignatureAlgorithm)
			assert.True(t, priv.PublicKey().Equal(csr.PublicKey))
			assert.Equal(t, []string{"mldsa" + strconv.Itoa(tc.size) + ".example.com"}, csr.DNSNames)

			crt, err := certutil.ParseFromPEM(pqcVector(t, tc.size, "crt"))
			require.NoError(t, err)
			require.NoError(t, crt.CheckSignatureFrom(crt))
			assert.Equal(t, tc.want, crt.SignatureAlgorithm)
			assert.True(t, priv.PublicKey().Equal(crt.PublicKey))
			assert.True(t, crt.IsCA)

			// the key signs what OpenSSL's key signs
			sig, err := priv.Sign(rand.Reader, crt.RawTBSCertificate, nil)
			require.NoError(t, err)
			require.NoError(t, mldsa.Verify(crt.PublicKey.(*mldsa.PublicKey), crt.RawTBSCertificate, sig, nil))

			// re-encoding the seed-only key is byte for byte the OpenSSL file
			encoded, err := certutil.EncodePrivateKeyToPEM(priv)
			require.NoError(t, err)
			assert.Equal(t, string(pqcVector(t, tc.size, "key")), string(encoded))
		})
	}

	both, err := os.ReadFile(filepath.Join(pqcTestdata, "mldsa65-seed-and-expanded.key"))
	require.NoError(t, err)
	_, err = certutil.ParsePrivateKeyPEM(both)
	require.EqualError(t, err, "unable to parse private key")
	_, err = cryptoprov.ParsePrivateKeyPEM(both)
	require.ErrorContains(t, err, "failed to parse key: ")
	require.ErrorContains(t, err, "seed-only")
}

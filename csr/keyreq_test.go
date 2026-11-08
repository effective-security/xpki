package csr_test

import (
	"crypto"
	"crypto/mldsa"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/cryptoprov/inmemcrypto"
	"github.com/effective-security/xpki/csr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestKeyRequest(t *testing.T) {
	defprov := inmemcrypto.NewProvider()
	tt := []struct {
		algo   string
		size   int
		expalg x509.SignatureAlgorithm
		experr string
	}{
		{"rsa", 512, x509.SHA256WithRSA, "validate RSA key: RSA key is too weak: 512"},
		{"RSA", 1024, x509.SHA256WithRSA, "validate RSA key: RSA key is too weak: 1024"},
		{"RSA", 2048, x509.SHA256WithRSA, ""},
		{"RSA", 3072, x509.SHA256WithRSA, ""},
		{"rsa", 4096, x509.SHA512WithRSA, ""},
		{"rsa", 8192, x509.SHA512WithRSA, "validate RSA key: RSA key size too large: 8192"},
		{"rsa", 168192, x509.SHA512WithRSA, "validate RSA key: RSA key size too large: 168192"},
		{"ecdsa", 521, x509.ECDSAWithSHA512, ""},
		{"ECDSA", 384, x509.ECDSAWithSHA384, ""},
		{"ECDSA", 256, x509.ECDSAWithSHA256, ""},
		{"ECDSA", 128, x509.ECDSAWithSHA256, "validate ECDSA key: invalid curve size: 128"},
		{"ML-DSA", 44, x509.MLDSA44, ""},
		{"ml-dsa", 65, x509.MLDSA65, ""},
		{"MLDSA", 65, x509.MLDSA65, ""},
		{"ML-DSA", 87, x509.MLDSA87, ""},
		{"ML-DSA", 2048, x509.UnknownSignatureAlgorithm, "validate ML-DSA key: invalid ML-DSA parameter set (expected 44, 65 or 87): 2048"},
		{"ML-DSA", 0, x509.UnknownSignatureAlgorithm, "validate ML-DSA key: invalid ML-DSA parameter set (expected 44, 65 or 87): 0"},
		{"DILITHIUM", 65, x509.UnknownSignatureAlgorithm, "invalid algorithm: DILITHIUM"},
		{"DSA", 256, x509.UnknownSignatureAlgorithm, "invalid algorithm: DSA"},
	}

	for _, tc := range tt {
		label := fmt.Sprintf("%s_%d", tc.algo, tc.size)
		t.Run(label, func(t *testing.T) {
			assert.Equal(t, tc.expalg, csr.SigAlgo(tc.algo, tc.size))

			kr := csr.NewKeyRequest(defprov, label, tc.algo, tc.size, csr.SigningKey)
			priv, err := kr.Generate()
			if tc.experr != "" {
				require.Error(t, err)
				assert.Equal(t, tc.experr, err.Error())
			} else {
				require.NoError(t, err)
				signer := priv.(crypto.Signer)
				assert.Equal(t, tc.expalg, csr.DefaultSigAlgo(signer))
				assert.Equal(t, csr.IsPostQuantumAlgo(tc.algo), certutil.IsPostQuantumKey(signer))
			}
		})
	}
}

// TestKeyRequestMLDSAPurpose checks that an encryption purpose is rejected
// for ML-DSA, a signature scheme, while the signing and undefined purposes
// generate a key.
func TestKeyRequestMLDSAPurpose(t *testing.T) {
	t.Parallel()
	defprov := inmemcrypto.NewProvider()
	_, err := csr.NewKeyRequest(defprov, "pq", csr.AlgoMLDSA, csr.MLDSA44, csr.EncryptionKey).Generate()
	require.EqualError(t, err, "validate ML-DSA key: unsupported key purpose: 2, ML-DSA keys are signing keys")
	for _, purpose := range []csr.KeyPurpose{csr.Undefined, csr.SigningKey} {
		priv, err := csr.NewKeyRequest(defprov, "pq", csr.AlgoMLDSA, csr.MLDSA44, purpose).Generate()
		require.NoError(t, err, "purpose %d", purpose)
		assert.True(t, certutil.IsPostQuantumKey(priv))
	}
}

func TestPostQuantumDetection(t *testing.T) {
	t.Parallel()
	for _, algo := range []string{csr.AlgoMLDSA, "ml-dsa", "MLDSA", "mldsa", " ML-DSA "} {
		assert.True(t, csr.IsPostQuantumAlgo(algo), algo)
	}
	for _, algo := range []string{csr.AlgoRSA, csr.AlgoECDSA, "rsa", "ED25519", "DILITHIUM", "ML-KEM", ""} {
		assert.False(t, csr.IsPostQuantumAlgo(algo), algo)
	}
}

// TestKeyRequestMLDSAFromYAML decodes an ML-DSA key request as a CSR
// profile carries it and generates the key through GenerateKeyAndRequest.
func TestKeyRequestMLDSAFromYAML(t *testing.T) {
	t.Parallel()
	prov := csr.NewProvider(inmemcrypto.NewProvider())
	req := &csr.CertificateRequest{}
	require.NoError(t, yaml.Unmarshal([]byte("common_name: pq.example.com\nkey:\n  algo: ml-dsa\n  size: 44\n"), req))
	require.Equal(t, 44, req.KeyRequest.Size())
	assert.Equal(t, x509.MLDSA44, req.KeyRequest.SigAlgo())

	csrPEM, priv, keyID, err := prov.GenerateKeyAndRequest(req)
	require.NoError(t, err)
	assert.NotEmpty(t, keyID)
	parsed, err := csr.ParsePEM(csrPEM)
	require.NoError(t, err)
	assert.Equal(t, x509.MLDSA, parsed.PublicKeyAlgorithm)
	assert.True(t, parsed.PublicKey.(*mldsa.PublicKey).Equal(priv.(crypto.Signer).Public()))
	assert.Equal(t, x509.MLDSA44, parseCSR(t, csrPEM).SignatureAlgorithm)
}

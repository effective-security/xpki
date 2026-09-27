package csr_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"io"
	"math/big"
	"testing"

	"github.com/effective-security/xpki/csr"
	"github.com/stretchr/testify/assert"
)

// stubSigner is a crypto.Signer that only reports a public key.
type stubSigner struct {
	pub crypto.PublicKey
}

func (s stubSigner) Public() crypto.PublicKey { return s.pub }
func (s stubSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

// algoSigner is a stubSigner that advertises its signature algorithm, as a
// KMS signer does.
type algoSigner struct {
	stubSigner
	algo x509.SignatureAlgorithm
}

func (s algoSigner) SignatureAlgorithm() x509.SignatureAlgorithm { return s.algo }

// rsaPublic returns an RSA public key of bits without generating a key.
func rsaPublic(bits int) *rsa.PublicKey {
	return &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), uint(bits-1)), E: 65537}
}

// TestSigAlgo checks the default hash by key size: 3072-bit RSA uses
// SHA-256 (XPKI-114).
func TestSigAlgo(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		algo string
		size int
		want x509.SignatureAlgorithm
	}{
		{"RSA", 1024, x509.SHA256WithRSA},
		{"rsa", 2048, x509.SHA256WithRSA},
		{"RSA", 3072, x509.SHA256WithRSA},
		{"RSA", 4095, x509.SHA256WithRSA},
		{"RSA", 4096, x509.SHA512WithRSA},
		{"RSA", 8192, x509.SHA512WithRSA},
		{"ECDSA", csr.CurveP256, x509.ECDSAWithSHA256},
		{"ecdsa", csr.CurveP384, x509.ECDSAWithSHA384},
		{"ECDSA", csr.CurveP521, x509.ECDSAWithSHA512},
		{"ECDSA", 224, x509.ECDSAWithSHA256},
		{"Ed25519", 0, x509.UnknownSignatureAlgorithm},
	} {
		assert.Equal(t, tc.want, csr.SigAlgo(tc.algo, tc.size), "%s %d", tc.algo, tc.size)
	}
}

// TestDefaultSigAlgo checks the choice by key type and size, and that a
// SignatureAlgorithmer's algorithm wins (XPKI-114).
func TestDefaultSigAlgo(t *testing.T) {
	t.Parallel()
	p256 := &ecdsa.PublicKey{Curve: elliptic.P256()}
	for _, tc := range []struct {
		name string
		key  crypto.Signer
		want x509.SignatureAlgorithm
	}{
		{"rsa1024", stubSigner{rsaPublic(1024)}, x509.SHA256WithRSA},
		{"rsa2048", stubSigner{rsaPublic(2048)}, x509.SHA256WithRSA},
		{"rsa3072", stubSigner{rsaPublic(3072)}, x509.SHA256WithRSA},
		{"rsa4096", stubSigner{rsaPublic(4096)}, x509.SHA512WithRSA},
		{"p256", stubSigner{p256}, x509.ECDSAWithSHA256},
		{"p384", stubSigner{&ecdsa.PublicKey{Curve: elliptic.P384()}}, x509.ECDSAWithSHA384},
		{"p521", stubSigner{&ecdsa.PublicKey{Curve: elliptic.P521()}}, x509.ECDSAWithSHA512},
		{"p224", stubSigner{&ecdsa.PublicKey{Curve: elliptic.P224()}}, x509.ECDSAWithSHA256},
		{"unknown", stubSigner{"not a key"}, x509.UnknownSignatureAlgorithm},
		{"advertised pss", algoSigner{stubSigner{rsaPublic(3072)}, x509.SHA256WithRSAPSS}, x509.SHA256WithRSAPSS},
		{"advertised 4096 sha256", algoSigner{stubSigner{rsaPublic(4096)}, x509.SHA256WithRSA}, x509.SHA256WithRSA},
		{"advertised unknown falls back", algoSigner{stubSigner{rsaPublic(4096)}, x509.UnknownSignatureAlgorithm}, x509.SHA512WithRSA},
		{"advertised ecdsa", algoSigner{stubSigner{p256}, x509.ECDSAWithSHA384}, x509.ECDSAWithSHA384},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, csr.DefaultSigAlgo(tc.key))
		})
	}

	// SigAlgo and DefaultSigAlgo agree for every generated key size
	for _, bits := range []int{2048, 3072, 4096} {
		assert.Equal(t, csr.SigAlgo("RSA", bits), csr.DefaultSigAlgo(stubSigner{rsaPublic(bits)}), "RSA %d", bits)
	}
}

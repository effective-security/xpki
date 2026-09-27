package gcpkmscrypto_test

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/effective-security/xpki/cryptoprov/gcpkmscrypto"
	"github.com/effective-security/xpki/csr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A KMS signer advertises the X.509 algorithm of its key (XPKI-114).
var _ csr.SignatureAlgorithmer = (*gcpkmscrypto.Signer)(nil)

// TestSignerSignatureAlgorithm tables the KMS to X.509 algorithm mapping
// (XPKI-114).
func TestSignerSignatureAlgorithm(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
		want      x509.SignatureAlgorithm
	}{
		{kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256, x509.SHA256WithRSA},
		{kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256, x509.SHA256WithRSA},
		{kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256, x509.SHA256WithRSA},
		{kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512, x509.SHA512WithRSA},
		{kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256, x509.SHA256WithRSAPSS},
		{kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256, x509.SHA256WithRSAPSS},
		{kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256, x509.SHA256WithRSAPSS},
		{kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512, x509.SHA512WithRSAPSS},
		{kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, x509.ECDSAWithSHA256},
		{kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384, x509.ECDSAWithSHA384},
		{kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256, x509.UnknownSignatureAlgorithm},
		{kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_2048, x509.UnknownSignatureAlgorithm},
		{kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256, x509.UnknownSignatureAlgorithm},
		{kmspb.CryptoKeyVersion_CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED, x509.UnknownSignatureAlgorithm},
	} {
		signer := gcpkmscrypto.NewSigner(signKeyID, "label", nil, tc.algorithm, nil).(*gcpkmscrypto.Signer)
		assert.Equal(t, tc.want, signer.SignatureAlgorithm(), tc.algorithm.String())
		if tc.want != x509.UnknownSignatureAlgorithm {
			assert.Equal(t, tc.want, csr.DefaultSigAlgo(signer), tc.algorithm.String())
		}
	}
}

// TestCSRWithKMSKey signs CSRs through csr.Provider with KMS keys of every
// RSA and ECDSA algorithm on the fake KMS: the CSR carries the algorithm
// KMS accepts and verifies. Before XPKI-114 a 3072-bit key was signed with
// SHA-384, which no 3072-bit KMS algorithm accepts, and a 4096-bit SHA-256
// key with SHA-512.
func TestCSRWithKMSKey(t *testing.T) {
	t.Parallel()

	s := newFakeKMSServer()
	provider := grpcProvider(t, s)
	csrProv := csr.NewProvider(provider)

	// a generated 3072-bit key, as CreateRequestAndExportKey does
	req := csrProv.NewSigningCertificateRequest("gen-3072", "RSA", 3072, "example.com", nil, []string{"example.com", "10.0.0.1"})
	csrPEM, _, keyID, pub, err := csrProv.CreateRequestAndExportKey(req)
	require.NoError(t, err)
	assert.NotEmpty(t, keyID)
	parsed := parseCSR(t, csrPEM)
	assert.Equal(t, x509.SHA256WithRSA, parsed.SignatureAlgorithm)
	assert.Equal(t, pub, parsed.PublicKey)
	assert.Equal(t, []string{"example.com"}, parsed.DNSNames)
	assert.Equal(t, x509.SHA256WithRSA, req.KeyRequest.SigAlgo())

	for _, tc := range []struct {
		name      string
		algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
		want      x509.SignatureAlgorithm
	}{
		{"pkcs1-2048", kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256, x509.SHA256WithRSA},
		{"pkcs1-3072", kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256, x509.SHA256WithRSA},
		{"pkcs1-4096-sha256", kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256, x509.SHA256WithRSA},
		{"pkcs1-4096-sha512", kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512, x509.SHA512WithRSA},
		{"pss-3072", kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256, x509.SHA256WithRSAPSS},
		{"pss-4096-sha512", kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512, x509.SHA512WithRSAPSS},
		{"p256", kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, x509.ECDSAWithSHA256},
		{"p384", kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384, x509.ECDSAWithSHA384},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s.AddKey(t, "csr-"+tc.name, tc.algorithm, tc.name)
			pk, err := provider.GetKey("csr-" + tc.name)
			require.NoError(t, err)
			signer := pk.(crypto.Signer)
			assert.Equal(t, tc.want, csr.DefaultSigAlgo(signer))

			signs := s.CallCount("AsymmetricSign")
			csrPEM, err := csrProv.SignRequest(pk, &csr.CertificateRequest{
				CommonName: tc.name + ".example.com",
				SAN:        []string{tc.name + ".example.com", "ops@example.com"},
			})
			require.NoError(t, err)
			assert.Equal(t, signs+1, s.CallCount("AsymmetricSign"))
			parsed := parseCSR(t, csrPEM)
			assert.Equal(t, tc.want, parsed.SignatureAlgorithm)
			assert.Equal(t, signer.Public(), parsed.PublicKey)
			assert.Equal(t, []string{tc.name + ".example.com"}, parsed.DNSNames)
		})
	}
}

// parseCSR decodes a PEM CSR and checks its signature.
func parseCSR(t *testing.T, csrPEM []byte) *x509.CertificateRequest {
	t.Helper()
	block, _ := pem.Decode(csrPEM)
	require.NotNil(t, block)
	parsed, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	require.NoError(t, parsed.CheckSignature())
	return parsed
}

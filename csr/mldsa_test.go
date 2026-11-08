package csr_test

import (
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/cryptoprov/inmemcrypto"
	"github.com/effective-security/xpki/csr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMLDSAKeyAndRequest is the PQ1 end-to-end check: for every parameter
// set an in-memory ML-DSA key is generated, a CSR is created and parsed
// with its signature verified, the exported PKCS#8 key loads back and
// matches the CSR, and the key signs a certificate x509 verifies.
func TestMLDSAKeyAndRequest(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		size int
		want x509.SignatureAlgorithm
	}{
		{csr.MLDSA44, x509.MLDSA44},
		{csr.MLDSA65, x509.MLDSA65},
		{csr.MLDSA87, x509.MLDSA87},
	} {
		t.Run(tc.want.String(), func(t *testing.T) {
			t.Parallel()
			prov := csr.NewProvider(inmemcrypto.NewProvider())
			req := prov.NewSigningCertificateRequest("pq", csr.AlgoMLDSA, tc.size, "pq.example.com",
				[]csr.X509Name{{Organization: "xpki"}}, []string{"pq.example.com", "10.0.0.1"})
			assert.Equal(t, tc.want, req.KeyRequest.SigAlgo())

			csrPEM, keyPEM, keyID, pub, err := prov.CreateRequestAndExportKey(req)
			require.NoError(t, err)
			assert.NotEmpty(t, keyID)
			mlPub, ok := pub.(*mldsa.PublicKey)
			require.True(t, ok, "%T", pub)
			assert.True(t, certutil.IsPostQuantumKey(pub))

			// csr.Parse verifies the CSR signature and builds a template
			parsed, err := csr.ParsePEM(csrPEM)
			require.NoError(t, err)
			assert.Equal(t, x509.MLDSA, parsed.PublicKeyAlgorithm)
			assert.True(t, mlPub.Equal(parsed.PublicKey))
			assert.Equal(t, []string{"pq.example.com"}, parsed.DNSNames)
			assert.Equal(t, "pq.example.com", parsed.Subject.CommonName)
			request := parseCSR(t, csrPEM)
			assert.Equal(t, tc.want, request.SignatureAlgorithm)

			block, _ := pem.Decode(keyPEM)
			require.NotNil(t, block)
			assert.Equal(t, "PRIVATE KEY", block.Type)
			loaded, err := cryptoprov.ParsePrivateKeyPEM(keyPEM)
			require.NoError(t, err)
			priv, ok := loaded.(*mldsa.PrivateKey)
			require.True(t, ok, "%T", loaded)
			assert.True(t, mlPub.Equal(priv.Public()))
			assert.Equal(t, tc.want, csr.DefaultSigAlgo(priv))

			// the loaded key signs a certificate for the CSR key that verifies
			template := &x509.Certificate{
				SerialNumber:          big1(),
				Subject:               pkix.Name{CommonName: "pq root"},
				NotBefore:             time.Now().Add(-time.Minute),
				NotAfter:              time.Now().Add(time.Hour),
				IsCA:                  true,
				BasicConstraintsValid: true,
				KeyUsage:              x509.KeyUsageCertSign,
			}
			der, err := x509.CreateCertificate(rand.Reader, template, template, parsed.PublicKey, priv)
			require.NoError(t, err)
			crt, err := x509.ParseCertificate(der)
			require.NoError(t, err)
			assert.Equal(t, tc.want, crt.SignatureAlgorithm)
			require.NoError(t, crt.CheckSignatureFrom(crt))
			assert.True(t, certutil.IsPostQuantumCertificate(crt))

			// the provider signer rejects hash-then-sign callers
			signer, err := prov.NewKeyRequest("again", csr.AlgoMLDSA, tc.size, csr.SigningKey).Generate()
			require.NoError(t, err)
			_, err = signer.(crypto.Signer).Sign(rand.Reader, make([]byte, 32), crypto.SHA256)
			require.EqualError(t, err, "ML-DSA signs a message, not a digest: unsupported signer options SHA-256")
		})
	}
}

// TestSignRequestMLDSAParsedKey signs a CSR with a plain *mldsa.PrivateKey,
// the key type ParsePrivateKeyPEM returns for a PKCS#8 file.
func TestSignRequestMLDSAParsedKey(t *testing.T) {
	t.Parallel()
	priv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	prov := csr.NewProvider(inmemcrypto.NewProvider())
	csrPEM, err := prov.SignRequest(priv, &csr.CertificateRequest{
		CommonName: "pq.example.com",
		SAN:        []string{"pq.example.com"},
	})
	require.NoError(t, err)
	parsed, err := csr.ParsePEM(csrPEM)
	require.NoError(t, err)
	assert.Equal(t, x509.MLDSA, parsed.PublicKeyAlgorithm)
	assert.True(t, priv.PublicKey().Equal(parsed.PublicKey))
	assert.Equal(t, x509.MLDSA65, parseCSR(t, csrPEM).SignatureAlgorithm)
}

// parseCSR decodes a PEM CSR with crypto/x509 and checks its signature.
func parseCSR(t *testing.T, csrPEM []byte) *x509.CertificateRequest {
	t.Helper()
	block, _ := pem.Decode(csrPEM)
	require.NotNil(t, block)
	request, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	require.NoError(t, request.CheckSignature())
	return request
}

func big1() *big.Int {
	return big.NewInt(1)
}

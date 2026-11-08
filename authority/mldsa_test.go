package authority_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"

	"github.com/effective-security/xpki/authority"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/cryptoprov/inmemcrypto"
	"github.com/effective-security/xpki/csr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

const (
	pqRootCN   = "[TEST] PQ Root CA"
	pqServerCN = "pq.example.com"
)

// newRootWithKey creates a self-signed root through NewRoot with a key of
// algo and size in the in-memory provider, and returns the root PEM and a
// signer loaded from the exported key.
func newRootWithKey(t *testing.T, algo string, size int) (certPEM []byte, signer crypto.Signer) {
	t.Helper()
	prov := inmemcrypto.NewProvider()
	req := csr.CertificateRequest{
		CommonName: pqRootCN,
		KeyRequest: csr.NewKeyRequest(prov, "root-"+algo, algo, size, csr.SigningKey),
	}
	certPEM, csrPEM, keyPEM, err := authority.NewRoot("ROOT", rootCfg, prov, &req)
	require.NoError(t, err)
	assert.NotEmpty(t, csrPEM)

	providers, err := cryptoprov.New(prov, nil)
	require.NoError(t, err)
	signer, err = providers.NewSignerFromPEM(keyPEM)
	require.NoError(t, err)
	return certPEM, signer
}

// serverProfiles returns a server profile without a key policy and two
// with allowed_key_algorithms (decision D7).
func serverProfiles(t *testing.T) map[string]*authority.CertProfile {
	t.Helper()
	profiles := map[string]*authority.CertProfile{
		"server": {
			Usage:  []string{"digital signature", "server auth"},
			Expiry: csr.OneYear,
		},
		"pq-only": {
			Usage:                []string{"digital signature", "server auth"},
			Expiry:               csr.OneYear,
			AllowedKeyAlgorithms: []string{"ML-DSA"},
		},
		"classical-only": {
			Usage:                []string{"digital signature", "server auth"},
			Expiry:               csr.OneYear,
			AllowedKeyAlgorithms: []string{"rsa", "ecdsa", "ed25519"},
		},
	}
	for name, p := range profiles {
		require.NoError(t, p.Validate(), name)
	}
	return profiles
}

// csrFor signs a CSR for pqServerCN with key through csr.Provider.
func csrFor(t *testing.T, key crypto.Signer) string {
	t.Helper()
	csrPEM, err := csr.NewProvider(inmemcrypto.NewProvider()).SignRequest(key, &csr.CertificateRequest{
		CommonName: pqServerCN,
		SAN:        []string{pqServerCN},
	})
	require.NoError(t, err)
	return string(csrPEM)
}

func verifyChain(t *testing.T, leaf, root *x509.Certificate) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(root)
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		DNSName:   pqServerCN,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	require.NoError(t, err)
}

// TestMLDSAIssuer is the PQ2 acceptance test: an ML-DSA root (every
// parameter set) issues an ML-DSA leaf and an ECDSA leaf that x509
// verifies, proofs round-trip, and the key algorithm policy accepts and
// rejects CSRs as configured.
func TestMLDSAIssuer(t *testing.T) {
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
			rootPEM, signer := newRootWithKey(t, csr.AlgoMLDSA, tc.size)
			root, err := certutil.ParseFromPEM(rootPEM)
			require.NoError(t, err)
			assert.Equal(t, tc.want, root.SignatureAlgorithm)
			assert.True(t, root.IsCA)
			assert.True(t, certutil.IsPostQuantumCertificate(root))
			_, isMLDSA := signer.(*mldsa.PrivateKey)
			require.True(t, isMLDSA, "%T", signer)

			issuer, err := authority.CreateIssuer(&authority.IssuerConfig{
				Label:    "pq",
				Profiles: serverProfiles(t),
			}, rootPEM, nil, nil, signer)
			require.NoError(t, err)

			pqKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
			require.NoError(t, err)
			ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			pqCSR, ecCSR := csrFor(t, pqKey), csrFor(t, ecKey)

			pqLeaf, _, err := issuer.Sign(csr.SignRequest{Request: pqCSR, Profile: "server"})
			require.NoError(t, err)
			assert.Equal(t, tc.want, pqLeaf.SignatureAlgorithm)
			assert.Equal(t, x509.MLDSA, pqLeaf.PublicKeyAlgorithm)
			assert.True(t, pqKey.PublicKey().Equal(pqLeaf.PublicKey))
			verifyChain(t, pqLeaf, root)

			ecLeaf, _, err := issuer.Sign(csr.SignRequest{Request: ecCSR, Profile: "server"})
			require.NoError(t, err)
			assert.Equal(t, tc.want, ecLeaf.SignatureAlgorithm)
			assert.Equal(t, x509.ECDSA, ecLeaf.PublicKeyAlgorithm)
			verifyChain(t, ecLeaf, root)
			assert.True(t, certutil.IsPostQuantumCertificate(ecLeaf), "signed by an ML-DSA key")

			// decision D7: the profile key policy
			_, _, err = issuer.Sign(csr.SignRequest{Request: pqCSR, Profile: "pq-only"})
			require.NoError(t, err)
			_, _, err = issuer.Sign(csr.SignRequest{Request: ecCSR, Profile: "pq-only"})
			require.EqualError(t, err, "public key algorithm ECDSA is not allowed by profile pq-only")
			_, _, err = issuer.Sign(csr.SignRequest{Request: ecCSR, Profile: "classical-only"})
			require.NoError(t, err)
			_, _, err = issuer.Sign(csr.SignRequest{Request: pqCSR, Profile: "classical-only"})
			require.EqualError(t, err, "public key algorithm ML-DSA is not allowed by profile classical-only")

			// proofs sign the message with the ML-DSA key
			data := []byte("proof payload")
			proof, err := issuer.SignProof(data)
			require.NoError(t, err)
			require.NoError(t, issuer.VerifyProof(data, proof))
			require.ErrorContains(t, issuer.VerifyProof([]byte("tampered"), proof), "invalid ML-DSA signature")
			require.ErrorContains(t, issuer.VerifyProof(data, proof[:len(proof)-8]+"AAAAAAAA"), "invalid ML-DSA signature")
			require.ErrorContains(t, issuer.VerifyProof(data, "%%%"), "unable to verify proof")

			// a CRL signed by the ML-DSA issuer verifies too
			crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
				Number:     big.NewInt(1),
				ThisUpdate: pqLeaf.NotBefore,
				NextUpdate: pqLeaf.NotAfter,
			}, root, signer)
			require.NoError(t, err)
			crl, err := x509.ParseRevocationList(crlDER)
			require.NoError(t, err)
			require.NoError(t, crl.CheckSignatureFrom(root))
			assert.Equal(t, tc.want, crl.SignatureAlgorithm)
		})
	}
}

// TestClassicalIssuerSignsMLDSALeaf checks the other direction: an ECDSA
// issuer certifies an ML-DSA public key.
func TestClassicalIssuerSignsMLDSALeaf(t *testing.T) {
	t.Parallel()
	rootPEM, signer := newRootWithKey(t, csr.AlgoECDSA, csr.CurveP256)
	root, err := certutil.ParseFromPEM(rootPEM)
	require.NoError(t, err)
	issuer, err := authority.CreateIssuer(&authority.IssuerConfig{
		Label:    "ec",
		Profiles: serverProfiles(t),
	}, rootPEM, nil, nil, signer)
	require.NoError(t, err)

	pqKey, err := mldsa.GenerateKey(mldsa.MLDSA87())
	require.NoError(t, err)
	leaf, leafPEM, err := issuer.Sign(csr.SignRequest{Request: csrFor(t, pqKey), Profile: "server"})
	require.NoError(t, err)
	assert.Equal(t, x509.ECDSAWithSHA256, leaf.SignatureAlgorithm)
	assert.Equal(t, x509.MLDSA, leaf.PublicKeyAlgorithm)
	assert.True(t, certutil.IsPostQuantumCertificate(leaf), "ML-DSA public key")
	assert.False(t, certutil.IsPostQuantumCertificate(root))
	verifyChain(t, leaf, root)

	block, _ := pem.Decode(leafPEM)
	require.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE", block.Type)

	// the leaf key signs a CSR x509 accepts, and the classical policy rejects it
	_, _, err = issuer.Sign(csr.SignRequest{Request: csrFor(t, pqKey), Profile: "classical-only"})
	require.EqualError(t, err, "public key algorithm ML-DSA is not allowed by profile classical-only")
}

// TestMLDSAIssuerOCSP covers decision D5: an ML-DSA issuer that advertises
// OCSP needs a delegated classical responder, an issuer without an OCSP URL
// is accepted but cannot sign a response with its key, and the delegated
// responder signs responses that parse against the ML-DSA CA.
func TestMLDSAIssuerOCSP(t *testing.T) {
	t.Parallel()
	rootPEM, signer := newRootWithKey(t, csr.AlgoMLDSA, csr.MLDSA65)
	root, err := certutil.ParseFromPEM(rootPEM)
	require.NoError(t, err)
	ocspProfile := &authority.CertProfile{
		Usage:       []string{"digital signature", "ocsp signing"},
		Expiry:      csr.OneYear,
		OCSPNoCheck: true,
	}
	require.NoError(t, ocspProfile.Validate())

	_, err = authority.CreateIssuer(&authority.IssuerConfig{
		Label: "pq",
		AIA: &authority.AIAConfig{
			OcspURL: "http://localhost/ocsp",
		},
	}, rootPEM, nil, nil, signer)
	require.EqualError(t, err, `issuer "pq": an ML-DSA key cannot sign OCSP responses; set aia.delegated_ocsp_profile for a classical responder key or remove aia.ocsp_url`)

	// no OCSP URL: accepted, but the CA key never signs a response
	crlOnly, err := authority.CreateIssuer(&authority.IssuerConfig{
		Label: "pq",
		AIA: &authority.AIAConfig{
			CrlURL: "http://localhost/crl",
		},
	}, rootPEM, nil, nil, signer)
	require.NoError(t, err)
	_, err = crlOnly.SignOCSP(&authority.OCSPSignRequest{
		SerialNumber: big.NewInt(7),
		Status:       authority.OCSPStatusGood,
	})
	require.EqualError(t, err, "OCSP responses cannot be signed with an ML-DSA key: configure aia.delegated_ocsp_profile")

	delegating, err := authority.CreateIssuer(&authority.IssuerConfig{
		Label: "pq",
		AIA: &authority.AIAConfig{
			OcspURL:              "http://localhost/ocsp",
			DelegatedOCSPProfile: "ocsp",
		},
		Profiles: map[string]*authority.CertProfile{
			"ocsp": ocspProfile,
		},
	}, rootPEM, nil, nil, signer)
	require.NoError(t, err)

	responder, err := delegating.CreateDelegatedOCSPSigner()
	require.NoError(t, err)
	assert.Equal(t, x509.MLDSA65, responder.Cert.SignatureAlgorithm, "issued by the ML-DSA CA")
	assert.Equal(t, x509.ECDSA, responder.Cert.PublicKeyAlgorithm, "classical responder key")
	assert.False(t, certutil.IsPostQuantumKey(responder.Signer))
	require.NoError(t, responder.Cert.CheckSignatureFrom(root))

	der, err := delegating.SignOCSP(&authority.OCSPSignRequest{
		SerialNumber: big.NewInt(7),
		Status:       authority.OCSPStatusGood,
	})
	require.NoError(t, err)
	response, err := ocsp.ParseResponse(der, root)
	require.NoError(t, err)
	require.NotNil(t, response.Certificate)
	assert.True(t, responder.Cert.Equal(response.Certificate))
	assert.Equal(t, big.NewInt(7), response.SerialNumber)
	assert.Equal(t, ocsp.Good, response.Status)
}

// TestCertProfileAllowedKeyAlgorithms covers the names Validate accepts.
func TestCertProfileAllowedKeyAlgorithms(t *testing.T) {
	t.Parallel()
	for _, names := range [][]string{
		nil,
		{"rsa"},
		{"RSA", "ECDSA", "Ed25519", "ML-DSA"},
		{"mldsa"},
		{" ml-dsa "},
	} {
		p := &authority.CertProfile{
			Usage:                []string{"digital signature"},
			Expiry:               csr.OneYear,
			AllowedKeyAlgorithms: names,
		}
		require.NoError(t, p.Validate(), "%v", names)
	}
	for _, name := range []string{"dsa", "ml-kem", "dilithium", ""} {
		p := &authority.CertProfile{
			Usage:                []string{"digital signature"},
			Expiry:               csr.OneYear,
			AllowedKeyAlgorithms: []string{"rsa", name},
		}
		require.EqualError(t, p.Validate(), "unknown key algorithm: "+name)
	}
}

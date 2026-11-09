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
	"time"

	"github.com/effective-security/xpki/authority"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/cryptoprov/inmemcrypto"
	"github.com/effective-security/xpki/csr"
	"github.com/effective-security/xpki/oid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
	"gopkg.in/yaml.v3"
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

// ocspResponderProfile returns a valid delegated_ocsp_profile.
func ocspResponderProfile(t *testing.T) *authority.CertProfile {
	t.Helper()
	profile := &authority.CertProfile{
		Usage:       []string{"digital signature", "ocsp signing"},
		Expiry:      csr.OneYear,
		OCSPNoCheck: true,
	}
	require.NoError(t, profile.Validate())
	return profile
}

// TestMLDSAIssuerOCSP covers OCSP on an ML-DSA issuer: the CA key signs
// directly, and a delegated responder has a classical key by default or an
// ML-DSA key when configured.
func TestMLDSAIssuerOCSP(t *testing.T) {
	t.Parallel()
	rootPEM, signer := newRootWithKey(t, csr.AlgoMLDSA, csr.MLDSA65)
	root, err := certutil.ParseFromPEM(rootPEM)
	require.NoError(t, err)
	request := &authority.OCSPSignRequest{
		SerialNumber: big.NewInt(7),
		Status:       authority.OCSPStatusRevoked,
		Reason:       ocsp.Superseded,
		RevokedAt:    time.Now().Add(-time.Hour).Truncate(time.Second),
	}

	t.Run("direct", func(t *testing.T) {
		t.Parallel()
		direct, err := authority.CreateIssuer(&authority.IssuerConfig{
			Label: "pq",
			AIA: &authority.AIAConfig{
				OcspURL: "http://localhost/ocsp",
			},
		}, rootPEM, nil, nil, signer)
		require.NoError(t, err)

		responder, err := direct.CreateDelegatedOCSPSigner()
		require.NoError(t, err)
		assert.True(t, certutil.IsPostQuantumKey(responder.Signer), "the CA key")

		der, err := direct.SignOCSP(request)
		require.NoError(t, err)
		response, err := certutil.ParseOCSPResponse(der, root)
		require.NoError(t, err)
		assert.Equal(t, x509.MLDSA65, response.SignatureAlgorithm)
		assert.Nil(t, response.Certificate, "the issuer verifies a direct response")
		assert.Equal(t, big.NewInt(7), response.SerialNumber)
		assert.Equal(t, ocsp.Revoked, response.Status)
		assert.Equal(t, ocsp.Superseded, response.RevocationReason)
		assert.True(t, request.RevokedAt.Equal(response.RevokedAt))

		// golang.org/x/crypto/ocsp cannot verify it (D5)
		_, err = ocsp.ParseResponse(der, root)
		require.ErrorContains(t, err, "bad OCSP signature")
	})

	t.Run("classical responder by default", func(t *testing.T) {
		t.Parallel()
		delegating, err := authority.CreateIssuer(&authority.IssuerConfig{
			Label: "pq",
			AIA: &authority.AIAConfig{
				OcspURL:              "http://localhost/ocsp",
				DelegatedOCSPProfile: "ocsp",
			},
			Profiles: map[string]*authority.CertProfile{
				"ocsp": ocspResponderProfile(t),
			},
		}, rootPEM, nil, nil, signer)
		require.NoError(t, err)

		responder, err := delegating.CreateDelegatedOCSPSigner()
		require.NoError(t, err)
		assert.Equal(t, x509.MLDSA65, responder.Cert.SignatureAlgorithm, "issued by the ML-DSA CA")
		assert.Equal(t, x509.ECDSA, responder.Cert.PublicKeyAlgorithm, "classical responder key")
		assert.False(t, certutil.IsPostQuantumKey(responder.Signer))
		require.NoError(t, responder.Cert.CheckSignatureFrom(root))

		der, err := delegating.SignOCSP(request)
		require.NoError(t, err)
		// x/crypto reads it: the response signature is classical, and Go 1.27
		// verifies the ML-DSA signature on the responder certificate
		response, err := ocsp.ParseResponse(der, root)
		require.NoError(t, err)
		require.NotNil(t, response.Certificate)
		assert.True(t, responder.Cert.Equal(response.Certificate))
		assert.Equal(t, big.NewInt(7), response.SerialNumber)
		assert.Equal(t, ocsp.Revoked, response.Status)
		_, err = certutil.ParseOCSPResponse(der, root)
		require.NoError(t, err)
	})

	for _, tc := range []struct {
		name string
		size int
		algo x509.SignatureAlgorithm
	}{
		{"ML-DSA-44", csr.MLDSA44, x509.MLDSA44},
		{"ML-DSA-65", csr.MLDSA65, x509.MLDSA65},
		{"ML-DSA-87", csr.MLDSA87, x509.MLDSA87},
	} {
		t.Run("ML-DSA responder "+tc.name, func(t *testing.T) {
			t.Parallel()
			delegating, err := authority.CreateIssuer(&authority.IssuerConfig{
				Label: "pq",
				AIA: &authority.AIAConfig{
					OcspURL:              "http://localhost/ocsp",
					DelegatedOCSPProfile: "ocsp",
					DelegatedOCSPKeyAlgo: "ml-dsa",
					DelegatedOCSPKeySize: tc.size,
				},
				Profiles: map[string]*authority.CertProfile{
					"ocsp": ocspResponderProfile(t),
				},
			}, rootPEM, nil, nil, signer)
			require.NoError(t, err)

			responder, err := delegating.CreateDelegatedOCSPSigner()
			require.NoError(t, err)
			assert.Equal(t, x509.MLDSA, responder.Cert.PublicKeyAlgorithm)
			assert.True(t, certutil.IsPostQuantumKey(responder.Signer))

			der, err := delegating.SignOCSP(request)
			require.NoError(t, err)
			response, err := certutil.ParseOCSPResponse(der, root)
			require.NoError(t, err)
			assert.Equal(t, tc.algo, response.SignatureAlgorithm)
			require.NotNil(t, response.Certificate)
			assert.True(t, responder.Cert.Equal(response.Certificate))
			assert.Equal(t, ocsp.Revoked, response.Status)
			assert.False(t, response.NextUpdate.After(responder.Cert.NotAfter))
		})
	}
}

// TestClassicalIssuerMLDSAResponder certifies an ML-DSA delegated responder
// with a classical CA key.
func TestClassicalIssuerMLDSAResponder(t *testing.T) {
	t.Parallel()
	rootPEM, signer := newRootWithKey(t, csr.AlgoECDSA, csr.CurveP256)
	root, err := certutil.ParseFromPEM(rootPEM)
	require.NoError(t, err)
	issuer, err := authority.CreateIssuer(&authority.IssuerConfig{
		Label: "ec",
		AIA: &authority.AIAConfig{
			OcspURL:              "http://localhost/ocsp",
			DelegatedOCSPProfile: "ocsp",
			DelegatedOCSPKeyAlgo: csr.AlgoMLDSA,
			DelegatedOCSPKeySize: csr.MLDSA65,
		},
		Profiles: map[string]*authority.CertProfile{
			"ocsp": ocspResponderProfile(t),
		},
	}, rootPEM, nil, nil, signer)
	require.NoError(t, err)

	der, err := issuer.SignOCSP(&authority.OCSPSignRequest{
		SerialNumber: big.NewInt(9),
		Status:       authority.OCSPStatusGood,
	})
	require.NoError(t, err)
	response, err := certutil.ParseOCSPResponse(der, root)
	require.NoError(t, err)
	assert.Equal(t, x509.MLDSA65, response.SignatureAlgorithm)
	require.NotNil(t, response.Certificate)
	assert.Equal(t, x509.ECDSAWithSHA256, response.Certificate.SignatureAlgorithm)
	assert.Equal(t, ocsp.Good, response.Status)
}

// TestDelegatedOCSPKeyConfig covers the responder key settings CreateIssuer
// rejects, and an accepted RSA key.
func TestDelegatedOCSPKeyConfig(t *testing.T) {
	t.Parallel()
	rootPEM, signer := newRootWithKey(t, csr.AlgoECDSA, csr.CurveP256)
	ecdsaOnly := ocspResponderProfile(t)
	ecdsaOnly.AllowedKeyAlgorithms = []string{"ecdsa"}
	pqOnly := ocspResponderProfile(t)
	pqOnly.AllowedKeyAlgorithms = []string{"ml-dsa"}

	profiles := map[string]*authority.CertProfile{
		"ocsp":        ocspResponderProfile(t),
		"ecdsa-only":  ecdsaOnly,
		"ml-dsa-only": pqOnly,
	}
	for _, tc := range []struct {
		name    string
		aia     authority.AIAConfig
		keyAlgo x509.PublicKeyAlgorithm
		err     string
	}{
		{
			name: "RSA",
			aia: authority.AIAConfig{
				DelegatedOCSPProfile: "ocsp",
				DelegatedOCSPKeyAlgo: "RSA",
				DelegatedOCSPKeySize: 2048,
			},
			keyAlgo: x509.RSA,
		},
		{
			name: "ECDSA P-384",
			aia: authority.AIAConfig{
				DelegatedOCSPProfile: "ocsp",
				DelegatedOCSPKeyAlgo: "ecdsa",
				DelegatedOCSPKeySize: 384,
			},
			keyAlgo: x509.ECDSA,
		},
		{
			name: "ML-DSA for a profile that lists it",
			aia: authority.AIAConfig{
				DelegatedOCSPProfile: "ml-dsa-only",
				DelegatedOCSPKeyAlgo: "mldsa",
				DelegatedOCSPKeySize: 44,
			},
			keyAlgo: x509.MLDSA,
		},
		{
			name: "unknown algorithm",
			aia: authority.AIAConfig{
				DelegatedOCSPProfile: "ocsp",
				DelegatedOCSPKeyAlgo: "DSA",
				DelegatedOCSPKeySize: 2048,
			},
			err: `issuer "ec": delegated_ocsp_key_algo: invalid algorithm: DSA`,
		},
		{
			name: "algorithm without a size",
			aia: authority.AIAConfig{
				DelegatedOCSPProfile: "ocsp",
				DelegatedOCSPKeyAlgo: "ecdsa",
			},
			err: `issuer "ec": delegated_ocsp_key_algo: validate ECDSA key: invalid curve size: 0`,
		},
		{
			name: "weak RSA",
			aia: authority.AIAConfig{
				DelegatedOCSPProfile: "ocsp",
				DelegatedOCSPKeyAlgo: "rsa",
				DelegatedOCSPKeySize: 1024,
			},
			err: `issuer "ec": delegated_ocsp_key_algo: validate RSA key: RSA key is too weak: 1024`,
		},
		{
			name: "not a parameter set",
			aia: authority.AIAConfig{
				DelegatedOCSPProfile: "ocsp",
				DelegatedOCSPKeyAlgo: "ml-dsa",
				DelegatedOCSPKeySize: 66,
			},
			err: `issuer "ec": delegated_ocsp_key_algo: validate ML-DSA key: invalid ML-DSA parameter set (expected 44, 65 or 87): 66`,
		},
		{
			name: "size without an algorithm",
			aia: authority.AIAConfig{
				DelegatedOCSPProfile: "ocsp",
				DelegatedOCSPKeySize: 256,
			},
			err: `issuer "ec": delegated_ocsp_key_size requires delegated_ocsp_key_algo`,
		},
		{
			name: "key without a delegated profile",
			aia: authority.AIAConfig{
				DelegatedOCSPKeyAlgo: "ecdsa",
				DelegatedOCSPKeySize: 256,
			},
			err: `issuer "ec": delegated_ocsp_key_algo requires delegated_ocsp_profile`,
		},
		{
			name: "profile does not allow the configured key",
			aia: authority.AIAConfig{
				DelegatedOCSPProfile: "ecdsa-only",
				DelegatedOCSPKeyAlgo: "ml-dsa",
				DelegatedOCSPKeySize: 65,
			},
			err: `issuer "ec": delegated_ocsp_profile "ecdsa-only" does not allow the responder key algorithm ml-dsa`,
		},
		{
			name: "profile does not allow the default key",
			aia: authority.AIAConfig{
				DelegatedOCSPProfile: "ml-dsa-only",
			},
			err: `issuer "ec": delegated_ocsp_profile "ml-dsa-only" does not allow the responder key algorithm ECDSA`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			aia := tc.aia
			issuer, err := authority.CreateIssuer(&authority.IssuerConfig{
				Label:    "ec",
				AIA:      &aia,
				Profiles: profiles,
			}, rootPEM, nil, nil, signer)
			if tc.err != "" {
				require.EqualError(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			responder, err := issuer.CreateDelegatedOCSPSigner()
			require.NoError(t, err)
			assert.Equal(t, tc.keyAlgo, responder.Cert.PublicKeyAlgorithm)
		})
	}

	// the keys load from a configuration file and survive a copy
	var aia authority.AIAConfig
	require.NoError(t, yaml.Unmarshal([]byte("delegated_ocsp_profile: ocsp\ndelegated_ocsp_key_algo: ML-DSA\ndelegated_ocsp_key_size: 65\n"), &aia))
	algo, size := aia.Copy().DelegatedOCSPKey()
	assert.Equal(t, csr.AlgoMLDSA, algo)
	assert.Equal(t, csr.MLDSA65, size)
	var none *authority.AIAConfig
	algo, size = none.DelegatedOCSPKey()
	assert.Equal(t, csr.AlgoECDSA, algo)
	assert.Equal(t, csr.CurveP256, size)
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

// Key usage extension values, DER BIT STRINGs in the format of
// csr.X509Extension.
const (
	kuExtDigitalSignature = "hex:03020780"
	kuExtKeyEncipherment  = "hex:03020520"
	// a SEQUENCE where the BIT STRING belongs
	kuExtMalformed = "hex:3000"
	// a valid BIT STRING followed by a byte
	kuExtTrailing = "hex:0302078000"
	// not hexadecimal
	kuExtNotDecodable = "hex:zz"
)

// keyUsageExtension returns a raw key usage extension with a value above.
func keyUsageExtension(value string) csr.X509Extension {
	return csr.X509Extension{
		ID:    csr.OID(oid.ExtensionKeyUsage),
		Value: value,
	}
}

// TestMLDSAKeyUsage covers RFC 9881 section 5: a request for an ML-DSA
// certificate with a usage for encryption or key agreement is rejected,
// whichever way the usage reaches the certificate, and only for ML-DSA.
func TestMLDSAKeyUsage(t *testing.T) {
	t.Parallel()
	rootPEM, signer := newRootWithKey(t, csr.AlgoECDSA, csr.CurveP256)
	pqKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pqCSR := csrFor(t, pqKey)
	ecCSR := csrFor(t, ecKey)

	const (
		allowedKU = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment |
			x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		forbiddenMessage = "key usage not allowed for an ML-DSA key: "
	)

	for _, tc := range []struct {
		name       string
		usage      []string
		profileExt []csr.X509Extension
		requestExt []csr.X509Extension
		wantKU     x509.KeyUsage
		// err is the error after "profile <name>: "
		err string
		// the profile and request are still good for a classical key
		classicalKU x509.KeyUsage
	}{
		{
			name:   "allowed usages",
			usage:  []string{"digital signature", "content commitment", "cert sign", "crl sign", "server auth"},
			wantKU: allowedKU,
		},
		{
			name:   "no key usage",
			usage:  []string{"server auth"},
			wantKU: 0,
		},
		{
			name:        "key encipherment",
			usage:       []string{"digital signature", "key encipherment", "server auth"},
			err:         forbiddenMessage + "key encipherment",
			classicalKU: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		},
		{
			name:        "data encipherment",
			usage:       []string{"digital signature", "data encipherment"},
			err:         forbiddenMessage + "data encipherment",
			classicalKU: x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
		},
		{
			name:        "key agreement",
			usage:       []string{"digital signature", "key agreement"},
			err:         forbiddenMessage + "key agreement",
			classicalKU: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		},
		{
			name:        "encipher only",
			usage:       []string{"key agreement", "encipher only"},
			err:         forbiddenMessage + "key agreement, encipher only",
			classicalKU: x509.KeyUsageKeyAgreement | x509.KeyUsageEncipherOnly,
		},
		{
			name:        "decipher only",
			usage:       []string{"key agreement", "decipher only"},
			err:         forbiddenMessage + "key agreement, decipher only",
			classicalKU: x509.KeyUsageKeyAgreement | x509.KeyUsageDecipherOnly,
		},
		{
			name:       "raw profile extension",
			usage:      []string{"digital signature"},
			profileExt: []csr.X509Extension{keyUsageExtension(kuExtKeyEncipherment)},
			err:        forbiddenMessage + "key encipherment",
		},
		{
			name:       "raw request extension",
			usage:      []string{"digital signature"},
			requestExt: []csr.X509Extension{keyUsageExtension(kuExtKeyEncipherment)},
			err:        forbiddenMessage + "key encipherment",
		},
		{
			name:       "raw extension replaces the usages",
			usage:      []string{"key encipherment", "server auth"},
			profileExt: []csr.X509Extension{keyUsageExtension(kuExtDigitalSignature)},
			wantKU:     x509.KeyUsageDigitalSignature,
		},
		{
			name:       "malformed raw extension",
			usage:      []string{"digital signature"},
			profileExt: []csr.X509Extension{keyUsageExtension(kuExtMalformed)},
			err:        "invalid key usage extension",
		},
		{
			name:       "trailing data in the raw extension",
			usage:      []string{"digital signature"},
			profileExt: []csr.X509Extension{keyUsageExtension(kuExtTrailing)},
			err:        "invalid key usage extension: trailing data",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			profile := &authority.CertProfile{
				Usage:      tc.usage,
				Expiry:     csr.OneYear,
				Extensions: tc.profileExt,
			}
			require.NoError(t, profile.Validate())
			issuer, err := authority.CreateIssuer(&authority.IssuerConfig{
				Label:    "ec",
				Profiles: map[string]*authority.CertProfile{tc.name: profile},
			}, rootPEM, nil, nil, signer)
			require.NoError(t, err)

			leaf, _, err := issuer.Sign(csr.SignRequest{
				Request:    pqCSR,
				Profile:    tc.name,
				Extensions: tc.requestExt,
			})
			if tc.err != "" {
				require.ErrorContains(t, err, "profile "+tc.name+": "+tc.err)
				assert.Nil(t, leaf)
			} else {
				require.NoError(t, err)
				assert.Equal(t, x509.MLDSA, leaf.PublicKeyAlgorithm)
				assert.Equal(t, tc.wantKU, leaf.KeyUsage)
			}

			if tc.classicalKU != 0 {
				ecLeaf, _, err := issuer.Sign(csr.SignRequest{
					Request: ecCSR,
					Profile: tc.name,
				})
				require.NoError(t, err)
				assert.Equal(t, tc.classicalKU, ecLeaf.KeyUsage)
			}
		})
	}

	t.Run("root", func(t *testing.T) {
		t.Parallel()
		const profileName = "BAD-ROOT"
		prov := inmemcrypto.NewProvider()
		req := csr.CertificateRequest{
			CommonName: pqRootCN,
			KeyRequest: csr.NewKeyRequest(prov, "root", csr.AlgoMLDSA, csr.MLDSA65, csr.SigningKey),
		}
		cfg := &authority.Config{
			Profiles: map[string]*authority.CertProfile{
				profileName: {
					Usage:  []string{"cert sign", "crl sign", "key encipherment"},
					Expiry: csr.OneYear,
					CAConstraint: authority.CAConstraint{
						IsCA:       true,
						MaxPathLen: -1,
					},
				},
			},
		}
		_, _, _, err := authority.NewRoot(profileName, cfg, prov, &req)
		require.EqualError(t, err, "sign request: profile BAD-ROOT: "+forbiddenMessage+"key encipherment")
	})

	t.Run("delegated responder", func(t *testing.T) {
		t.Parallel()
		withUsage := ocspResponderProfile(t)
		withUsage.Usage = append(withUsage.Usage, "key encipherment")
		withExtension := ocspResponderProfile(t)
		withExtension.Extensions = []csr.X509Extension{keyUsageExtension(kuExtKeyEncipherment)}
		malformed := ocspResponderProfile(t)
		malformed.Extensions = []csr.X509Extension{keyUsageExtension(kuExtMalformed)}
		notDecodable := ocspResponderProfile(t)
		notDecodable.Extensions = []csr.X509Extension{keyUsageExtension(kuExtNotDecodable)}
		profiles := map[string]*authority.CertProfile{
			"with-usage":     withUsage,
			"with-extension": withExtension,
			"malformed":      malformed,
			"not-decodable":  notDecodable,
		}
		for name, wantErr := range map[string]string{
			"with-usage":     `issuer "ec": delegated_ocsp_profile "with-usage": ` + forbiddenMessage + "key encipherment",
			"with-extension": `issuer "ec": delegated_ocsp_profile "with-extension": ` + forbiddenMessage + "key encipherment",
			"malformed":      `issuer "ec": delegated_ocsp_profile "malformed": invalid key usage extension`,
			"not-decodable":  `issuer "ec": delegated_ocsp_profile "not-decodable": failed to decode extension`,
		} {
			_, err := authority.CreateIssuer(&authority.IssuerConfig{
				Label: "ec",
				AIA: &authority.AIAConfig{
					DelegatedOCSPProfile: name,
					DelegatedOCSPKeyAlgo: csr.AlgoMLDSA,
					DelegatedOCSPKeySize: csr.MLDSA65,
				},
				Profiles: profiles,
			}, rootPEM, nil, nil, signer)
			require.ErrorContains(t, err, wantErr)
		}

		// the same profile issues a responder with the default classical key
		issuer, err := authority.CreateIssuer(&authority.IssuerConfig{
			Label: "ec",
			AIA: &authority.AIAConfig{
				DelegatedOCSPProfile: "with-usage",
			},
			Profiles: profiles,
		}, rootPEM, nil, nil, signer)
		require.NoError(t, err)
		responder, err := issuer.CreateDelegatedOCSPSigner()
		require.NoError(t, err)
		assert.Equal(t, x509.ECDSA, responder.Cert.PublicKeyAlgorithm)
		assert.Equal(t, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, responder.Cert.KeyUsage)

		// the check runs again on a profile replaced after CreateIssuer
		pqIssuer, err := authority.CreateIssuer(&authority.IssuerConfig{
			Label: "ec",
			AIA: &authority.AIAConfig{
				DelegatedOCSPProfile: "ocsp",
				DelegatedOCSPKeyAlgo: csr.AlgoMLDSA,
				DelegatedOCSPKeySize: csr.MLDSA65,
			},
			Profiles: map[string]*authority.CertProfile{
				"ocsp": ocspResponderProfile(t),
			},
		}, rootPEM, nil, nil, signer)
		require.NoError(t, err)
		pqIssuer.AddProfile("ocsp", withUsage)
		_, err = pqIssuer.CreateDelegatedOCSPSigner()
		require.ErrorContains(t, err, forbiddenMessage+"key encipherment")
	})
}

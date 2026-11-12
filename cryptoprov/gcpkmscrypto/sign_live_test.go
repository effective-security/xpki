package gcpkmscrypto_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/effective-security/xpki/v2/certutil"
	"github.com/effective-security/xpki/v2/cryptoprov"
	"github.com/effective-security/xpki/v2/cryptoprov/gcpkmscrypto"
	"github.com/effective-security/xpki/v2/csr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLiveKMSSign confirms the classical key operations against the real
// service: for every RSA size and ECDSA curve GenerateKey creates, it
// creates an HSM key, signs a digest and verifies it locally, loads the key
// by its version, by its bare id and through its pkcs11: URI, describes it
// with its public key, signs a CSR and a certificate with the algorithm the
// key version accepts, finds it in a listing, and schedules it for
// destruction, after which it is no longer enabled. It creates billable HSM
// keys in the key ring of XPKI_LIVE_GCP_KMS_KEYRING; a 4096-bit RSA key can
// take a while to generate. It is opt-in and does not follow
// XPKI_INTEGRATION.
func TestLiveKMSSign(t *testing.T) {
	keyring := os.Getenv(liveKMSKeyringEnv)
	if keyring == "" {
		t.Skipf("%s is not set: no real Cloud KMS to run against", liveKMSKeyringEnv)
	}
	loaded, err := gcpkmscrypto.KmsLoader(&mockTokenCfg{
		manufacturer: gcpkmscrypto.ProviderName,
		model:        "KMS",
		atts:         "Keyring=" + keyring,
	})
	require.NoError(t, err)
	provider := loaded.(*gcpkmscrypto.Provider)
	t.Cleanup(func() {
		assert.NoError(t, provider.Close())
	})
	liveSignFlow(t, provider)
}

// TestLiveKMSSignOnFake runs the flow of TestLiveKMSSign on the in-process
// KMS, so that the live test is known to be right before it creates
// billable keys.
func TestLiveKMSSignOnFake(t *testing.T) {
	t.Parallel()
	liveSignFlow(t, grpcProvider(t, newFakeKMSServer()))
}

// liveSignFlow is the body of TestLiveKMSSign.
func liveSignFlow(t *testing.T, provider *gcpkmscrypto.Provider) {
	providers, err := cryptoprov.New(provider, nil)
	require.NoError(t, err)

	suffix := strings.ToLower(certutil.RandomString(8))
	for _, tc := range []struct {
		name    string
		keyType string
		size    int
		// hash is the digest of the KMS algorithm GenerateKey picks, and
		// other a hash the key version does not accept
		hash  crypto.Hash
		other crypto.Hash
		algo  x509.SignatureAlgorithm
	}{
		{
			name:    "rsa-2048",
			keyType: certutil.KeyTypeRSA,
			size:    2048,
			hash:    crypto.SHA256,
			other:   crypto.SHA512,
			algo:    x509.SHA256WithRSA,
		},
		{
			name:    "rsa-3072",
			keyType: certutil.KeyTypeRSA,
			size:    3072,
			hash:    crypto.SHA256,
			other:   crypto.SHA384,
			algo:    x509.SHA256WithRSA,
		},
		{
			name:    "rsa-4096",
			keyType: certutil.KeyTypeRSA,
			size:    4096,
			hash:    crypto.SHA512,
			other:   crypto.SHA256,
			algo:    x509.SHA512WithRSA,
		},
		{
			name:    "ec-p256",
			keyType: certutil.KeyTypeECDSA,
			size:    256,
			hash:    crypto.SHA256,
			other:   crypto.SHA384,
			algo:    x509.ECDSAWithSHA256,
		},
		{
			name:    "ec-p384",
			keyType: certutil.KeyTypeECDSA,
			size:    384,
			hash:    crypto.SHA384,
			other:   crypto.SHA256,
			algo:    x509.ECDSAWithSHA384,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			label := "xpki-live-sign-" + suffix + "-" + tc.name
			priv, err := provider.GenerateKey(t.Context(), &cryptoprov.GenerateKeyRequest{
				Label: label,
				Type:  tc.keyType,
				Size:  tc.size,
				Tags:  map[string]string{"live": suffix},
			})
			require.NoError(t, err)
			keyID, gotLabel, err := provider.IdentifyKey(t.Context(), priv)
			require.NoError(t, err)
			assert.Equal(t, label, gotLabel)
			bareID, version, _ := strings.Cut(keyID, "/cryptoKeyVersions/")
			assert.Equal(t, "1", version)
			destroyed := false
			t.Cleanup(func() {
				if destroyed {
					return
				}
				// the context of the test is done by now
				assert.NoError(t, provider.DestroyKey(context.Background(), keyID),
					"key %s is left in the key ring", keyID)
			})

			signer := priv.(crypto.Signer)
			pub := signer.Public()
			digest := sum(tc.hash, "signed by a real KMS")
			verify := func(signer crypto.Signer) {
				t.Helper()
				sig, err := signer.Sign(rand.Reader, digest, tc.hash)
				require.NoError(t, err)
				switch key := pub.(type) {
				case *rsa.PublicKey:
					assert.Equal(t, tc.size, key.N.BitLen())
					require.NoError(t, rsa.VerifyPKCS1v15(key, tc.hash, digest, sig))
				case *ecdsa.PublicKey:
					assert.Equal(t, tc.size, key.Curve.Params().BitSize)
					require.True(t, ecdsa.VerifyASN1(key, digest, sig))
				default:
					require.Failf(t, "unexpected public key", "%T", pub)
				}
			}
			verify(signer)

			// a hash the key version does not accept fails before any RPC
			_, err = signer.Sign(rand.Reader, sum(tc.other, "digest"), tc.other)
			require.Error(t, err)

			// the key loads by its version, by its bare id and by its URI
			for _, id := range []string{keyID, bareID} {
				again, err := provider.GetKey(t.Context(), id)
				require.NoError(t, err, id)
				againSigner := again.(crypto.Signer)
				assert.True(t, equalPublic(pub, againSigner.Public()), id)
				verify(againSigner)
			}
			uri, _, err := provider.ExportKey(t.Context(), keyID)
			require.NoError(t, err)
			_, fromURI, err := providers.LoadPrivateKey(t.Context(), []byte(uri))
			require.NoError(t, err)
			assert.True(t, equalPublic(pub, fromURI.(crypto.Signer).Public()))

			info, err := provider.KeyInfo(t.Context(), keyID, cryptoprov.KeyFieldsAll|cryptoprov.KeyFieldPublicKey)
			require.NoError(t, err)
			assert.Equal(t, keyID, info.ID)
			assert.Equal(t, label, info.Label)
			assert.Equal(t, tc.keyType, info.Type)
			assert.Equal(t, tc.size, info.Size)
			assert.Equal(t, cryptoprov.KeyUsageSign, info.Usage)
			assert.Equal(t, cryptoprov.KeyStateEnabled, info.State)
			assert.Equal(t, "1", info.CurrentVersionID)
			assert.Equal(t, suffix, info.Tags["live"])
			assert.Equal(t, "HSM", info.Meta["protection"])
			block, _ := pem.Decode([]byte(info.PublicKey))
			require.NotNil(t, block, info.PublicKey)
			described, err := x509.ParsePKIXPublicKey(block.Bytes)
			require.NoError(t, err)
			assert.True(t, equalPublic(pub, described))

			// a CSR and a certificate, with the algorithm of the key version
			algo := csr.DefaultSigAlgo(signer)
			assert.Equal(t, tc.algo, algo)
			subject := pkix.Name{CommonName: "xpki live KMS test"}
			csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
				Subject:            subject,
				SignatureAlgorithm: algo,
			}, signer)
			require.NoError(t, err)
			parsedCSR, err := x509.ParseCertificateRequest(csrDER)
			require.NoError(t, err)
			require.NoError(t, parsedCSR.CheckSignature())
			template := &x509.Certificate{
				SerialNumber:          big.NewInt(1),
				Subject:               subject,
				NotBefore:             time.Now().Add(-time.Minute),
				NotAfter:              time.Now().Add(time.Hour),
				IsCA:                  true,
				BasicConstraintsValid: true,
				SignatureAlgorithm:    algo,
			}
			certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, signer)
			require.NoError(t, err)
			cert, err := x509.ParseCertificate(certDER)
			require.NoError(t, err)
			require.NoError(t, cert.CheckSignatureFrom(cert))

			// the listing finds it by label, type, usage and state
			filter := cryptoprov.KeyFilter{
				Label:  label,
				Types:  []string{tc.keyType},
				Usage:  cryptoprov.KeyUsageSign,
				States: []cryptoprov.KeyState{cryptoprov.KeyStateEnabled},
			}
			keys := listAll(t, provider, &cryptoprov.ListKeysRequest{
				Filter: filter,
				Fields: cryptoprov.KeyFieldMetadata,
			})
			require.Len(t, keys, 1)
			assert.Equal(t, bareID, keys[0].ID)
			assert.Equal(t, tc.size, keys[0].Size)
			assert.Equal(t, "1", keys[0].CurrentVersionID)

			// destruction is scheduled: the key is no longer enabled and
			// has no version to sign with
			require.NoError(t, provider.DestroyKey(t.Context(), keyID))
			destroyed = true
			info, err = provider.KeyInfo(t.Context(), keyID, cryptoprov.KeyFieldState)
			require.NoError(t, err)
			assert.Equal(t, cryptoprov.KeyStatePendingDeletion, info.State)
			assert.Empty(t, listAll(t, provider, &cryptoprov.ListKeysRequest{Filter: filter}))
			_, err = provider.GetKey(t.Context(), bareID)
			require.ErrorContains(t, err, "has no enabled version")
		})
	}
}

// equalPublic reports whether a and b are the same public key.
func equalPublic(a, b crypto.PublicKey) bool {
	eq, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && eq.Equal(b)
}

// sum returns the hash digest of msg.
func sum(hash crypto.Hash, msg string) []byte {
	h := hash.New()
	_, _ = h.Write([]byte(msg))
	return h.Sum(nil)
}

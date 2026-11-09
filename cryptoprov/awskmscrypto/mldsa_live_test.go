package awskmscrypto_test

import (
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/cryptoprov/awskmscrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// liveKMSRegionEnv names the region of the real AWS KMS that
// TestLiveKMSMLDSA runs against, with the credentials of the SDK default chain.
// The test is opt-in and does not follow XPKI_INTEGRATION: it creates billable
// keys and schedules them for deletion.
const liveKMSRegionEnv = "XPKI_LIVE_AWS_KMS_REGION"

// TestLiveKMSMLDSA confirms the ML-DSA request shapes against the real
// service: for every parameter set it creates a key, signs a message, a μ and
// a message with a context through EXTERNAL_MU, verifies each signature
// locally, reads the key back, and signs a CSR and a certificate.
func TestLiveKMSMLDSA(t *testing.T) {
	region := os.Getenv(liveKMSRegionEnv)
	if region == "" {
		t.Skipf("%s is not set: no real AWS KMS to run against", liveKMSRegionEnv)
	}
	provider, err := awskmscrypto.KmsLoader(&mockTokenCfg{
		manufacturer: awskmscrypto.ProviderName,
		model:        "KMS",
		atts:         "Region=" + region,
	})
	require.NoError(t, err)
	manager := provider.(cryptoprov.KeyManager)

	for _, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		t.Run(params.String(), func(t *testing.T) {
			label := "xpki-live-" + strings.ToLower(params.String()) + "-" + certutil.RandomString(8)
			priv, err := provider.GenerateMLDSAKey(label, params)
			require.NoError(t, err)
			keyID, gotLabel, err := provider.IdentifyKey(priv)
			require.NoError(t, err)
			assert.Equal(t, label, gotLabel)
			t.Cleanup(func() {
				assert.NoError(t, manager.DestroyKeyPairOnSlot(manager.CurrentSlotID(), keyID),
					"key %s is left in the account", keyID)
			})

			signer := priv.(crypto.Signer)
			pub, ok := signer.Public().(*mldsa.PublicKey)
			require.True(t, ok, "%T", signer.Public())
			assert.Equal(t, params, pub.Parameters())
			verifyLiveMLDSASigner(t, signer, pub)

			loaded, err := provider.GetKey(keyID)
			require.NoError(t, err)
			loadedSigner := loaded.(crypto.Signer)
			assert.True(t, pub.Equal(loadedSigner.Public()))
			sig, err := loadedSigner.Sign(rand.Reader, []byte(label), nil)
			require.NoError(t, err)
			require.NoError(t, mldsa.Verify(pub, []byte(label), sig, nil))

			info, err := manager.KeyInfo(manager.CurrentSlotID(), keyID, true)
			require.NoError(t, err)
			assert.Equal(t, certutil.KeyTypeMLDSA, info.Type)
			assert.Equal(t, params.String(), info.Meta[cryptoprov.MetaParameterSet])
			assert.Contains(t, info.PublicKey, "PUBLIC KEY")
		})
	}
}

// verifyLiveMLDSASigner signs a message, a μ and a message with a context, and
// a CSR and a certificate, and verifies each locally.
func verifyLiveMLDSASigner(t *testing.T, signer crypto.Signer, pub *mldsa.PublicKey) {
	t.Helper()
	message := []byte("signed by a real KMS")

	sig, err := signer.Sign(rand.Reader, message, nil)
	require.NoError(t, err)
	require.NoError(t, mldsa.Verify(pub, message, sig, nil))

	mu, err := cryptoprov.MLDSAMu(pub, "", message)
	require.NoError(t, err)
	sig, err = signer.Sign(rand.Reader, mu, crypto.MLDSAMu)
	require.NoError(t, err)
	require.NoError(t, mldsa.Verify(pub, message, sig, nil))

	opts := &mldsa.Options{Context: "xpki"}
	sig, err = signer.Sign(rand.Reader, message, opts)
	require.NoError(t, err)
	require.NoError(t, mldsa.Verify(pub, message, sig, opts))

	subject := pkix.Name{CommonName: "xpki live KMS test"}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: subject}, signer)
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
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, signer)
	require.NoError(t, err)
	crt, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	require.NoError(t, crt.CheckSignatureFrom(crt))
}

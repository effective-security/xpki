package testca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/effective-security/xpki/certutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaults(t *testing.T) {
	assert.NotPanics(t, func() {
		root := NewEntity(
			Authority,
			NotBefore(time.Now()),
			NotAfter(time.Now().Add(100*time.Hour)),
			ExtKeyUsage(x509.ExtKeyUsageOCSPSigning),
		)

		err := root.Certificate.CheckSignatureFrom(root.Certificate)
		require.NoError(t, err)
	})
}

func TestIntermediate(t *testing.T) {
	assert.NotPanics(t, func() {
		NewEntity(
			CrlDpURL("http://localhost/crl"),
			DNSName("localhost"),
		).Issue()
	})
}

func TestSubject(t *testing.T) {
	assert.NotPanics(t, func() {
		var (
			expected = "foobar"
			root     = NewEntity(Subject(pkix.Name{CommonName: expected}))
			actual   = root.Certificate.Subject.CommonName
		)

		assert.Equal(t, expected, actual, "bad subject")
	})
}

func TestNextSerialNumber(t *testing.T) {
	assert.NotPanics(t, func() {
		var (
			expected = int64(123)
			ca       = NewEntity(NextSerialNumber(expected)).Issue()
			actual   = ca.Certificate.SerialNumber.Int64()
		)
		assert.Equal(t, expected, actual, "bad SN")
	})
}

func TestPrivateKey(t *testing.T) {
	assert.NotPanics(t, func() {
		var (
			expected, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			ca          = NewEntity(PrivateKey(expected))
			actual      = ca.PrivateKey.(*ecdsa.PrivateKey)
		)

		assert.Equal(t, expected.D.String(), actual.D.String(), "bad D")
		assert.Equal(t, expected.X.String(), actual.X.String(), "bad X")
		assert.Equal(t, expected.Y.String(), actual.Y.String(), "bad Y")
	})
}

func TestIssuer(t *testing.T) {
	assert.NotPanics(t, func() {
		var (
			root  = NewEntity(Authority)
			inter = NewEntity(Issuer(root))

			expected = root.Certificate.RawSubject
			actual   = inter.Certificate.RawIssuer
		)

		require.Equal(t, expected, actual, "bad issuer. expected %q, got %q", string(expected), string(actual))

		err := inter.Certificate.CheckSignatureFrom(root.Certificate)
		require.NoError(t, err)
	})
}

func TestIsCA(t *testing.T) {
	var (
		normal = NewEntity()
		ca     = NewEntity(Authority)
	)

	assert.True(t, ca.Certificate.IsCA, "expected CA cert to be CA")
	assert.False(t, normal.Certificate.IsCA, "expected normal cert not to be CA")
}

func TestChain(t *testing.T) {
	var (
		ca    = NewEntity(Authority)
		inter = ca.Issue(Authority)
		leaf  = inter.Issue()
	)

	ch := leaf.Chain()
	require.Equal(t, 3, len(ch))
	assert.True(t, ch[0].Equal(leaf.Certificate))
	assert.True(t, ch[1].Equal(inter.Certificate))
	assert.True(t, ch[2].Equal(ca.Certificate))

	kc := leaf.KeyAndCertChain()
	assert.Equal(t, leaf.Certificate.Raw, kc.Certificate.Raw)
	assert.Equal(t, ca.Certificate.Raw, kc.Root.Raw)
	assert.Equal(t, 1, len(kc.Chain))
	assert.Equal(t, inter.Certificate.Raw, kc.Chain[0].Raw)
}

func TestMakeTSA(t *testing.T) {
	oids := []asn1.ObjectIdentifier{oidExtKeyUsageTimeStamping}
	eku, err := asn1.Marshal(oids)
	require.NoError(t, err)

	var (
		ca = NewEntity(
			Authority,
			Subject(pkix.Name{
				CommonName: "[TEST] Timestamp Root CA",
			}),
			KeyUsage(x509.KeyUsageCertSign|x509.KeyUsageCRLSign|x509.KeyUsageDigitalSignature),
		)
		inter1 = ca.Issue(
			Authority,
			Subject(pkix.Name{
				CommonName: "[TEST] Timestamp Issuing CA Level 1",
			}),
			KeyUsage(x509.KeyUsageCertSign|x509.KeyUsageCRLSign|x509.KeyUsageDigitalSignature),
		)
		inter2 = inter1.Issue(
			Authority,
			Subject(pkix.Name{
				CommonName: "[TEST] Timestamp Issuing CA Level 2",
			}),
			KeyUsage(x509.KeyUsageCertSign|x509.KeyUsageCRLSign|x509.KeyUsageDigitalSignature),
		)
		leaf = inter2.Issue(
			Subject(pkix.Name{
				CommonName: "[TEST] TSA",
			}),
			KeyUsage(x509.KeyUsageDigitalSignature),
			Extensions([]pkix.Extension{
				{
					Id:       oidExtKeyUsage,
					Critical: true,
					Value:    eku,
				},
			}),
		)
	)
	ch := leaf.Chain()
	require.Equal(t, 4, len(ch))

	assert.True(t, ch[0].Equal(leaf.Certificate))
	assert.True(t, ch[1].Equal(inter2.Certificate))
	assert.True(t, ch[2].Equal(inter1.Certificate))
	assert.True(t, ch[3].Equal(ca.Certificate))

	kc := leaf.KeyAndCertChain()
	assert.Equal(t, leaf.Certificate.Raw, kc.Certificate.Raw)
	assert.Equal(t, ca.Certificate.Raw, kc.Root.Raw)
	assert.Equal(t, 2, len(kc.Chain))
	assert.Equal(t, inter2.Certificate.Raw, kc.Chain[0].Raw)
	assert.Equal(t, inter1.Certificate.Raw, kc.Chain[1].Raw)
}

func TestChainPool(t *testing.T) {
	var (
		ca    = NewEntity(Authority)
		inter = ca.Issue(Authority)
		leaf  = inter.Issue()
	)

	_, err := leaf.Certificate.Verify(x509.VerifyOptions{
		Roots:         ca.ChainPool(),
		Intermediates: leaf.ChainPool(),
	})
	require.NoError(t, err)
}

func TestPFX(t *testing.T) {
	assert.NotPanics(t, func() {
		NewEntity().PFX("asdf")
	})
}

func Test_MakeValidCertsChainTSA(t *testing.T) {
	// RSA
	key, crt, chain, end := MakeValidCertsChainTSA(t, 24, false)
	assert.NotNil(t, key)
	assert.NotNil(t, crt)
	assert.NotNil(t, chain)
	assert.NotNil(t, end)

	// EC
	key, crt, chain, end = MakeValidCertsChainTSA(t, 24, true)
	assert.NotNil(t, key)
	assert.NotNil(t, crt)
	assert.NotNil(t, chain)
	assert.NotNil(t, end)
}

func Test_MakeInvalidCertsChainTSA(t *testing.T) {
	key, crt, chain, end := MakeInvalidCertsChainTSA(t, 24)
	assert.NotNil(t, key)
	assert.NotNil(t, crt)
	assert.NotNil(t, chain)
	assert.NotNil(t, end)
}

func TestAIA(t *testing.T) {
	i := NewEntity(IssuingCertificateURL("a", "b"), OCSPServer("c", "d"))

	assert.Equal(t, []string{"a", "b"}, i.Certificate.IssuingCertificateURL, "bad IssuingCertificateURL: ", i.Certificate.IssuingCertificateURL)
	assert.Equal(t, []string{"c", "d"}, i.Certificate.OCSPServer, "bad OCSPServer: ", i.Certificate.OCSPServer)
}

func TestSetSAN(t *testing.T) {
	template := new(x509.Certificate)
	assert.NotPanics(t, func() {
		SetSAN(template, []string{
			"localhost",
			"127.0.0.1",
			"denis@effective-security.pt",
			"https://effective-security.pt",
		})
	})
}

func TestSaveCertAndKey(t *testing.T) {
	ca1 := NewEntity(
		Authority,
		Subject(pkix.Name{
			CommonName: "[TEST] Root CA One",
		}),
		KeyUsage(x509.KeyUsageCertSign|x509.KeyUsageCRLSign|x509.KeyUsageDigitalSignature),
	)
	inter1 := ca1.Issue(
		Authority,
		Subject(pkix.Name{
			CommonName: "[TEST] Issuing CA One Level 1",
		}),
		KeyUsage(x509.KeyUsageCertSign|x509.KeyUsageCRLSign|x509.KeyUsageDigitalSignature),
	)
	srv := inter1.Issue(
		Subject(pkix.Name{
			CommonName: "localhost",
		}),
		ExtKeyUsage(x509.ExtKeyUsageServerAuth),
		DNSName("localhost", "127.0.0.1"),
	)

	tmpDir := filepath.Join(os.TempDir(), "testca")
	os.MkdirAll(tmpDir, os.ModePerm)
	defer os.RemoveAll(tmpDir)

	serverCertFile := filepath.Join(tmpDir, "test-server.pem")
	serverKeyFile := filepath.Join(tmpDir, "test-server-key.pem")

	err := srv.SaveCertAndKey(serverCertFile, serverKeyFile, true)
	require.NoError(t, err)

	chain, err := certutil.LoadChainFromPEM(serverCertFile)
	require.NoError(t, err)
	assert.Len(t, chain, 2)
}

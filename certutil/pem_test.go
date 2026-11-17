package certutil_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/effective-security/xpki/v2/certutil"
	"github.com/effective-security/xpki/v2/cryptoprov"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_EncodeToPEMString(t *testing.T) {
	orig := strings.TrimSpace(selfSignedCert)
	crt, err := certutil.ParseFromPEM([]byte(orig))
	require.NoError(t, err)
	pem, err := certutil.EncodeToPEMString(true, crt)
	require.NoError(t, err)
	assert.Equal(t, orig, pem)

	crt1, err := certutil.ParseFromPEM([]byte(issuer1))
	require.NoError(t, err)
	crt2, err := certutil.ParseFromPEM([]byte(issuer2))
	require.NoError(t, err)

	pem, err = certutil.EncodeToPEMString(true, crt1, crt2)
	require.NoError(t, err)
	assert.Equal(t, strings.TrimSpace(issuers), pem)
}

func Test_ParseChainFromPEM(t *testing.T) {
	list, err := certutil.ParseChainFromPEM([]byte(issuers))
	require.NoError(t, err)
	assert.Equal(t, 2, len(list))
}

func Test_LoadFromPEM(t *testing.T) {
	crt, err := certutil.LoadFromPEM("testdata/selfsigned.pem")
	require.NoError(t, err)

	n := certutil.NameToString(&crt.Subject)
	assert.Equal(t, "C=US, ST=CA, L=San Francisco, O=CloudFlare LLC, OU=Security, CN=testssl.lol", n)
}

func Test_LoadChainFromPEM(t *testing.T) {
	chain, err := certutil.LoadChainFromPEM("testdata/ca-bundle.pem")
	require.NoError(t, err)
	assert.True(t, len(chain) > 100)
}

func TestLoadPEMFiles(t *testing.T) {
	b, err := certutil.LoadPEMFiles("testdata/ca-bundle.pem", "testdata/int-bundle.pem")
	require.NoError(t, err)

	_, err = certutil.ParseChainFromPEM(b)
	require.NoError(t, err)

	_, err = certutil.CreatePoolFromPEM(b)
	require.NoError(t, err)
}

func TestJoinPEM(t *testing.T) {
	assert.Equal(t, []byte("1\n2"), certutil.JoinPEM([]byte("\n   1  \n\n\n"), []byte("\t  \n   2  \n\n\t \n   ")))
	assert.Equal(t, []byte("1"), certutil.JoinPEM([]byte("\n   1  \n\n\n"), nil))
	assert.Equal(t, []byte("2"), certutil.JoinPEM(nil, []byte("\t  \n   2  \n\n\t \n   ")))
}

func Test_ParseRSAPublicKeyFromPEM(t *testing.T) {
	_, err := certutil.ParseRSAPublicKeyFromPEM(nil)
	require.Error(t, err)
	assert.Equal(t, `key must be PEM encoded`, err.Error())

	pvk := `-----BEGIN RSA PRIVATE KEY-----
MIIJJwIBAAKCAgEAoEfI9ReDrM2DM3t/VNUgjcZyYeK0glOQZc8PzvHd1OMQrHPD
yvLjh4Hj8aONoaGUSj1WaBrbczoZL2KDHiVuVVHU/CvEKa5srQcAAsyyBMtx38m+

4VG8OYT9yabo70LhrTtT8saGR5LDG3kWVxF7/Mwt7ucwj9+8UFAyRgRLJVUaJk9N
MUM7MmYW+uByV82+ogEcDMUl8jTActqcwZ6zxCYCs+6TTdqxW259ozLksRiNdvsy
uo2YIfCNG9Tloo9mNMjmhNl2Z8VsshqFqoHEk0N9CTMgjPkazaeE2UkcJQ==
-----END RSA PRIVATE KEY-----
`

	_, err = certutil.ParseRSAPublicKeyFromPEM([]byte(pvk))
	require.Error(t, err)
	assert.Equal(t, `unable to parse RSA Public Key`, err.Error())
}

func Test_EncodePublicKeyToPEM(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	p, err := certutil.EncodePublicKeyToPEM(key.Public())
	require.NoError(t, err)

	_, err = certutil.ParseRSAPublicKeyFromPEM(p)
	require.NoError(t, err)
}

func Test_EncodePrivateKeyToPEM_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	p, err := certutil.EncodePrivateKeyToPEM(key)
	require.NoError(t, err)

	_, err = cryptoprov.ParsePrivateKeyPEM(p)
	require.NoError(t, err)
}

// Test_EncodePrivateKeyToPEM_MLDSA round-trips every parameter set through
// the PKCS#8 seed form with both PEM parsers of the module.
func Test_EncodePrivateKeyToPEM_MLDSA(t *testing.T) {
	t.Parallel()
	for _, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		key, err := mldsa.GenerateKey(params)
		require.NoError(t, err)

		p, err := certutil.EncodePrivateKeyToPEM(key)
		require.NoError(t, err)
		block, rest := pem.Decode(p)
		require.NotNil(t, block)
		assert.Empty(t, rest)
		assert.Equal(t, "PRIVATE KEY", block.Type)
		assert.Len(t, block.Bytes, 54, "seed form")

		parsed, err := certutil.ParsePrivateKeyPEM(p)
		require.NoError(t, err)
		assert.True(t, key.Equal(parsed))
		generic, err := cryptoprov.ParsePrivateKeyPEM(p)
		require.NoError(t, err)
		assert.True(t, key.Equal(generic))
	}
}

func Test_EncodePrivateKeyToPEM_EC(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	p, err := certutil.EncodePrivateKeyToPEM(key)
	require.NoError(t, err)

	_, err = cryptoprov.ParsePrivateKeyPEM(p)
	require.NoError(t, err)
}

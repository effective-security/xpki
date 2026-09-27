package testca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

type equalKey interface {
	Equal(crypto.PrivateKey) bool
}

func testKeys(t *testing.T) map[string]crypto.PrivateKey {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return map[string]crypto.PrivateKey{
		"rsa":     rsaKey,
		"ecdsa":   ecKey,
		"ed25519": edKey,
	}
}

// TestToPKCS8 checks that ToPKCS8 yields an unencrypted PKCS#8 PEM block
// that the standard library parses back to an equal key, with no OpenSSL
// involved (XPKI-063).
func TestToPKCS8(t *testing.T) {
	for name, key := range testKeys(t) {
		t.Run(name, func(t *testing.T) {
			pemBytes := ToPKCS8(key)
			block, rest := pem.Decode(pemBytes)
			require.NotNil(t, block)
			assert.Empty(t, rest)
			assert.Equal(t, "PRIVATE KEY", block.Type)
			assert.Empty(t, block.Headers)

			parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			require.NoError(t, err)
			assert.True(t, key.(equalKey).Equal(parsed), "parsed key differs")
			assert.IsType(t, key, parsed)
		})
	}
}

// TestToPFX checks that ToPFX produces a PKCS#12 packet that decodes with
// the given password to the same certificate and an equal key, with any
// password (XPKI-063: the OpenSSL-based version accepted alphanumeric
// passwords only).
func TestToPFX(t *testing.T) {
	passwords := map[string]string{
		"alphanumeric": "asdf1234",
		"symbols":      `p@ss word!"#$%&'()*+,-./:;<=>?[\]^_{|}~`,
		"unicode":      "pässwörd-日本語",
		"empty":        "",
	}
	for keyName, key := range testKeys(t) {
		if keyName == "ed25519" {
			// NewEntity signs with RSA or ECDSA keys; PKCS#12 packets
			// are generated for those.
			continue
		}
		for pwName, password := range passwords {
			t.Run(keyName+"/"+pwName, func(t *testing.T) {
				ent := NewEntity(PrivateKey(key.(crypto.Signer)))
				data := ToPFX(ent.Certificate, ent.PrivateKey, password)
				require.NotEmpty(t, data)

				parsedKey, parsedCert, err := pkcs12.Decode(data, password)
				require.NoError(t, err)
				assert.Equal(t, ent.Certificate.Raw, parsedCert.Raw)
				assert.True(t, key.(equalKey).Equal(parsedKey), "decoded key differs")

				_, _, err = pkcs12.Decode(data, password+"x")
				require.Error(t, err)
			})
		}
	}
}

func TestToPFX_Unsupported(t *testing.T) {
	ent := NewEntity()
	assert.Panics(t, func() {
		ToPFX(ent.Certificate, "not a key", "pw")
	})
	assert.Panics(t, func() {
		ToPFX(nil, ent.PrivateKey, "pw")
	})
}

func TestKeyExport_UnknownType(t *testing.T) {
	for name, key := range map[string]any{
		"string":  "not a key",
		"nil":     nil,
		"ed25519": testKeys(t)["ed25519"],
	} {
		t.Run(name, func(t *testing.T) {
			assert.Panics(t, func() { ToDER(key) })
			assert.Panics(t, func() { PrivKeyToPEM(key) })
		})
	}
	assert.Panics(t, func() { ToPKCS8("not a key") })
	assert.Panics(t, func() { ToPKCS8(nil) })
	assert.Panics(t, func() { ToPKCS8(&rsa.PrivateKey{}) }, "an invalid key must not be encoded")
}

func TestToDERAndPrivKeyToPEM(t *testing.T) {
	keys := testKeys(t)

	rsaKey := keys["rsa"].(*rsa.PrivateKey)
	parsedRSA, err := x509.ParsePKCS1PrivateKey(ToDER(rsaKey))
	require.NoError(t, err)
	assert.True(t, rsaKey.Equal(parsedRSA))
	block, _ := pem.Decode(PrivKeyToPEM(rsaKey))
	require.NotNil(t, block)
	assert.Equal(t, "RSA PRIVATE KEY", block.Type)
	assert.Equal(t, ToDER(rsaKey), block.Bytes)

	ecKey := keys["ecdsa"].(*ecdsa.PrivateKey)
	parsedEC, err := x509.ParseECPrivateKey(ToDER(ecKey))
	require.NoError(t, err)
	assert.True(t, ecKey.Equal(parsedEC))
	block, _ = pem.Decode(PrivKeyToPEM(ecKey))
	require.NotNil(t, block)
	assert.Equal(t, "EC PRIVATE KEY", block.Type)
	assert.Equal(t, ToDER(ecKey), block.Bytes)
}

// TestToPFX_NonBMPPassword documents the PKCS#12 password limit: the
// password is a BMPString (UCS-2), so a character outside the Basic
// Multilingual Plane cannot be encoded and ToPFX panics (XPKI-063).
func TestToPFX_NonBMPPassword(t *testing.T) {
	ent := NewEntity()
	assert.NotPanics(t, func() { ToPFX(ent.Certificate, ent.PrivateKey, "pässwörd-€-日本") })
	assert.Panics(t, func() { ToPFX(ent.Certificate, ent.PrivateKey, "pass\U0001F600word") })
}

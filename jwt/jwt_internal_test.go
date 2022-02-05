package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/cryptoprov/inmemcrypto"
	"github.com/golang-jwt/jwt"
	gojwt "github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCurrentKeyLastWithoutID(t *testing.T) {
	p, err := New(&Config{
		Issuer: "issuer.com",
		Keys: []*Key{
			{ID: "1", Seed: "seed1"},
			{ID: "2", Seed: "seed2"},
		},
	}, nil)
	require.NoError(t, err)
	id, _ := p.(*provider).currentKey()
	assert.Equal(t, "2", id)
}

func TestClaims(t *testing.T) {
	c := Claims{
		"jti": "123",
	}
	c2 := Claims{
		"jti": "2",
	}
	c3 := jwt.MapClaims{
		"c3": 333,
	}
	c4 := map[string]interface{}{
		"c4": "444",
	}
	err := c.Add(c2)
	require.NoError(t, err)
	assert.Equal(t, "2", c["jti"])

	err = c.Add(c3)
	require.NoError(t, err)
	assert.Equal(t, 333, c["c3"])

	err = c.Add(c4)
	require.NoError(t, err)
	assert.Equal(t, "444", c["c4"])

	std := jwt.StandardClaims{
		IssuedAt: time.Now().Unix(),
	}
	err = c.Add(std)
	require.NoError(t, err)
	assert.Len(t, c, 4)

	err = c.Add(3)
	assert.EqualError(t, err, "unsupported claims interface")
	assert.NoError(t, c.Valid())

	var std2 jwt.StandardClaims
	err = c.To(&std2)
	require.NoError(t, err)
	assert.NoError(t, std2.Valid())

	std2.NotBefore = time.Now().Add(time.Hour).Unix()
	std2.ExpiresAt = time.Now().Add(-time.Hour).Unix()
	assert.EqualError(t, std2.Valid(), "token is not valid yet")
}

func TestSigningMethodES256(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	s, err := gojwt.SigningMethodES256.Sign("test", ecKey)
	require.NoError(t, err)

	err = gojwt.SigningMethodES256.Verify("test", s, &ecKey.PublicKey)
	require.NoError(t, err)

	pemKey, err := certutil.EncodePrivateKeyToPEM(ecKey)
	require.NoError(t, err)

	crypto, err := cryptoprov.New(inmemcrypto.NewProvider(), nil)
	require.NoError(t, err)

	signer, err := crypto.NewSignerFromPEM(pemKey)
	require.NoError(t, err)

	signature, err := sign("test", signer)
	require.NoError(t, err)

	err = gojwt.SigningMethodES256.Verify("test", signature, &ecKey.PublicKey)
	require.NoError(t, err)
}

func TestSigningMethodRS256(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	s, err := gojwt.SigningMethodRS256.Sign("test", key)
	require.NoError(t, err)

	err = gojwt.SigningMethodRS256.Verify("test", s, &key.PublicKey)
	require.NoError(t, err)

	pemKey, err := certutil.EncodePrivateKeyToPEM(key)
	require.NoError(t, err)

	crypto, err := cryptoprov.New(inmemcrypto.NewProvider(), nil)
	require.NoError(t, err)

	signer, err := crypto.NewSignerFromPEM(pemKey)
	require.NoError(t, err)

	signature, err := sign("test", signer)
	require.NoError(t, err)

	err = gojwt.SigningMethodRS256.Verify("test", signature, &key.PublicKey)
	require.NoError(t, err)
}

func TestSigningMethodHS256(t *testing.T) {
	key := certutil.Random(32)
	s, err := gojwt.SigningMethodHS256.Sign("test", key)
	require.NoError(t, err)

	err = gojwt.SigningMethodHS256.Verify("test", s, key)
	require.NoError(t, err)

	signer, err := newSymmetricSigner("HS256", key)
	require.NoError(t, err)

	signature, err := sign("test", signer)
	require.NoError(t, err)

	err = gojwt.SigningMethodHS256.Verify("test", signature, key)
	require.NoError(t, err)
}

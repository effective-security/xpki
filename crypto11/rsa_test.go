package crypto11

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var rsaSizes = []int{1024, 2048, 4096}

func TestNativeRSA(t *testing.T) {
	var err error
	var key *rsa.PrivateKey
	for _, nbits := range rsaSizes {
		key, err = rsa.GenerateKey(rand.Reader, nbits)
		require.NoError(t, err)

		err = key.Validate()
		require.NoError(t, err)

		testRsaSigning(t, key, nbits)
		testRsaEncryption(t, key, nbits)
	}
}

func TestHardRSA(t *testing.T) {
	var err error
	var priv *PKCS11PrivateKeyRSA
	var key2, key3 crypto.PrivateKey
	var id, label string

	for _, nbits := range rsaSizes {
		priv, err = p11lib.GenerateRSAKeyPair(nbits, Signing)
		require.NoError(t, err)
		require.NotNil(t, priv)

		err = priv.Validate()
		require.NoError(t, err)

		testRsaSigning(t, priv, nbits)
		// Get a fresh handle to  the key
		id, label, err = p11lib.Identify(&priv.key.PKCS11Object)
		require.NoError(t, err)

		key2, err = p11lib.FindKeyPair(id, "")
		require.NoError(t, err)

		testRsaSigning(t, key2.(*PKCS11PrivateKeyRSA), nbits)
		key3, err = p11lib.FindKeyPair("", label)

		require.NoError(t, err)
		testRsaSigning(t, key3.(crypto.Signer), nbits)
	}

	for _, nbits := range rsaSizes {
		priv, err = p11lib.GenerateRSAKeyPair(nbits, Encryption)
		require.NoError(t, err)
		require.NotNil(t, priv)

		err = priv.Validate()
		require.NoError(t, err)

		testRsaEncryption(t, priv, nbits)
		// Get a fresh handle to  the key
		id, _, err = p11lib.Identify(&priv.key.PKCS11Object)
		require.NoError(t, err)

		key2, err = p11lib.FindKeyPair(id, "")
		require.NoError(t, err)
		require.NotNil(t, key2)
	}
}

func testRsaSigning(t *testing.T, key crypto.Signer, nbits int) {
	testRsaSigningPKCS1v15(t, key, crypto.SHA1)
	testRsaSigningPKCS1v15(t, key, crypto.SHA224)
	testRsaSigningPKCS1v15(t, key, crypto.SHA256)
	testRsaSigningPKCS1v15(t, key, crypto.SHA384)
	testRsaSigningPKCS1v15(t, key, crypto.SHA512)
	testRsaSigningPSS(t, key, crypto.SHA1)
	testRsaSigningPSS(t, key, crypto.SHA256)
	testRsaSigningPSS(t, key, crypto.SHA384)
	if nbits > 1024 { // key too small for SHA512 with sLen=hLen
		testRsaSigningPSS(t, key, crypto.SHA512)
	}
}

func testRsaSigningPKCS1v15(t *testing.T, key crypto.Signer, hashFunction crypto.Hash) {
	var err error
	var sig []byte

	plaintext := []byte("sign me with PKCS#1 v1.5")
	h := hashFunction.New()
	h.Write(plaintext)
	plaintextHash := h.Sum([]byte{})
	sig, err = key.Sign(rand.Reader, plaintextHash, hashFunction)
	require.NoError(t, err)

	rsaPubkey := key.Public().(*rsa.PublicKey)
	err = rsa.VerifyPKCS1v15(rsaPubkey, hashFunction, plaintextHash, sig)
	require.NoError(t, err)
}

// testRsaSigningPSS signs with every supported salt-length option and
// verifies each signature with crypto/rsa using the same option.
func testRsaSigningPSS(t *testing.T, key crypto.Signer, hashFunction crypto.Hash) {
	plaintext := []byte("sign me with PSS")
	h := hashFunction.New()
	h.Write(plaintext)
	plaintextHash := h.Sum([]byte{})
	rsaPubkey := key.Public().(*rsa.PublicKey)

	saltLengths := []int{
		rsa.PSSSaltLengthEqualsHash,
		rsa.PSSSaltLengthAuto,
		8,
	}
	for _, saltLength := range saltLengths {
		pssOptions := &rsa.PSSOptions{SaltLength: saltLength, Hash: hashFunction}
		sig, err := key.Sign(rand.Reader, plaintextHash, pssOptions)
		require.NoError(t, err, "PSS sign: hash=%v salt=%d", hashFunction, saltLength)

		err = rsa.VerifyPSS(rsaPubkey, hashFunction, plaintextHash, sig, pssOptions)
		require.NoError(t, err, "PSS verify: hash=%v salt=%d", hashFunction, saltLength)
	}
}

func TestHardRSA_UnsupportedOptions(t *testing.T) {
	priv, err := p11lib.GenerateRSAKeyPair(2048, Signing)
	require.NoError(t, err)

	digest := make([]byte, crypto.MD5.Size())

	t.Run("pkcs1v15 unsupported hash", func(t *testing.T) {
		_, err := priv.Sign(rand.Reader, digest, crypto.MD5)
		require.Error(t, err)
		assert.True(t, errors.Is(err, errUnsupportedRSAOptions), "got %v", err)
		assert.EqualError(t, err, "unsupported PKCS#1 v1.5 hash: MD5: crypto11/rsa: unsupported RSA option value")
	})

	t.Run("pss unsupported hash", func(t *testing.T) {
		_, err := priv.Sign(rand.Reader, digest, &rsa.PSSOptions{Hash: crypto.MD5, SaltLength: rsa.PSSSaltLengthAuto})
		require.Error(t, err)
		assert.True(t, errors.Is(err, errUnsupportedRSAOptions), "got %v", err)
	})

	t.Run("pss negative salt", func(t *testing.T) {
		_, err := priv.Sign(rand.Reader, digest, &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: -3})
		require.Error(t, err)
		assert.True(t, errors.Is(err, errUnsupportedRSAOptions), "got %v", err)
	})

	t.Run("decrypt unsupported options", func(t *testing.T) {
		_, err := priv.Decrypt(rand.Reader, digest, crypto.SHA256)
		require.Error(t, err)
		assert.True(t, errors.Is(err, errUnsupportedRSAOptions), "got %v", err)
	})

	t.Run("decrypt session key len", func(t *testing.T) {
		_, err := priv.Decrypt(rand.Reader, digest, &rsa.PKCS1v15DecryptOptions{SessionKeyLen: 16})
		require.Error(t, err)
		assert.True(t, errors.Is(err, errUnsupportedRSAOptions), "got %v", err)
	})
}

// TODO: larger HASH, with label
func testRsaEncryption(t *testing.T, key crypto.Decrypter, nbits int) { // nolint: unparam
	testRsaEncryptionOAEP(t, key, crypto.SHA1, []byte{})
	testRsaEncryptionPKCS1v15(t, key)
	// testRsaEncryptionOAEP(t, key, crypto.SHA224, []byte{})
	// if nbits > 1024 { // key too small for SHA256
	// 	// testRsaEncryptionOAEP(t, key, crypto.SHA256, []byte{})
	// }
	//testRsaEncryptionOAEP(t, key, crypto.SHA384, []byte{})
	// if nbits > 1024 { // key too small for SHA512
	// 	// testRsaEncryptionOAEP(t, key, crypto.SHA512, []byte{})
	// }

	//
	// With label
	//

	// if nbits == 1024 {
	// 	// testRsaEncryptionOAEP(t, key, crypto.SHA1, []byte{1, 2, 3, 4})
	// }
	//testRsaEncryptionOAEP(t, key, crypto.SHA224, []byte{5, 6, 7, 8})
	// testRsaEncryptionOAEP(t, key, crypto.SHA256, []byte{9})
	// testRsaEncryptionOAEP(t, key, crypto.SHA384, []byte{10, 11, 12, 13, 14, 15})
	// if nbits > 1024 {
	// 	// testRsaEncryptionOAEP(t, key, crypto.SHA512, []byte{16, 17, 18})
	// }
}

// testRsaEncryptionPKCS1v15 checks that nil options and an explicit
// *rsa.PKCS1v15DecryptOptions both perform PKCS#1 v1.5 decryption.
func testRsaEncryptionPKCS1v15(t *testing.T, key crypto.Decrypter) {
	plaintext := []byte("encrypt me with PKCS#1 v1.5")
	rsaPubkey := key.Public().(*rsa.PublicKey)
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPubkey, plaintext)
	require.NoError(t, err, "PKCS1v15 Encrypt")

	decrypted, err := key.Decrypt(rand.Reader, ciphertext, nil)
	require.NoError(t, err, "PKCS1v15 Decrypt with nil options")
	assert.Equal(t, plaintext, decrypted)

	decrypted, err = key.Decrypt(rand.Reader, ciphertext, &rsa.PKCS1v15DecryptOptions{})
	require.NoError(t, err, "PKCS1v15 Decrypt with options")
	assert.Equal(t, plaintext, decrypted)
}

func testRsaEncryptionOAEP(t *testing.T, key crypto.Decrypter, hashFunction crypto.Hash, label []byte) {
	var err error
	var ciphertext, decrypted []byte

	plaintext := []byte("encrypt me with new hotness")
	h := hashFunction.New()
	rsaPubkey := key.Public().(*rsa.PublicKey)
	ciphertext, err = rsa.EncryptOAEP(h, rand.Reader, rsaPubkey, plaintext, label)
	require.NoError(t, err, "OAEP Encrypt")

	options := &rsa.OAEPOptions{Hash: hashFunction, Label: label}
	decrypted, err = key.Decrypt(rand.Reader, ciphertext, options)
	require.NoError(t, err, "OAEP Decrypt")

	assert.Equal(t, 0, bytes.Compare(plaintext, decrypted), "OAEP Decrypt: wrong answer")
}

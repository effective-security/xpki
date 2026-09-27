package dataprotection

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSymmetricConstants checks the documented blob parameters against the
// AEAD the provider uses (XPKI-083).
func TestSymmetricConstants(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, 32))
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)

	assert.Equal(t, gcm.NonceSize(), SymmetricNonceSize)
	assert.Equal(t, gcm.Overhead(), SymmetricTagSize)
	assert.Equal(t, SymmetricNonceSize+SymmetricTagSize, SymmetricOverhead)
	assert.Equal(t, 32, SymmetricMinSecretSize, "AES-256 key size")
	assert.Equal(t, uint64(1)<<32, SymmetricMaxMessagesPerKey, "NIST SP 800-38D §8.3 random IV limit")

	secret := make([]byte, SymmetricMinSecretSize)
	_, err = rand.Read(secret)
	require.NoError(t, err)
	p, err := NewSymmetric(secret)
	require.NoError(t, err)
	sp, ok := p.(*symProvider)
	require.True(t, ok)
	assert.Equal(t, SymmetricNonceSize, sp.nonceSize)
	assert.Equal(t, SymmetricTagSize, sp.gcm.Overhead())
}

// TestSymmetricBlobLayout checks that a blob is nonce || ciphertext || tag,
// exactly SymmetricOverhead bytes longer than the plaintext, and that every
// Protect call draws a distinct nonce.
func TestSymmetricBlobLayout(t *testing.T) {
	secret := make([]byte, SymmetricMinSecretSize)
	_, err := rand.Read(secret)
	require.NoError(t, err)
	p, err := NewSymmetric(secret)
	require.NoError(t, err)
	ctx := context.Background()

	for _, size := range []int{0, 1, 15, 16, 17, 1024} {
		plaintext := make([]byte, size)
		_, err := rand.Read(plaintext)
		require.NoError(t, err)

		protected, err := p.Protect(ctx, plaintext)
		require.NoError(t, err)
		assert.Len(t, protected, size+SymmetricOverhead, "size %d", size)

		unprotected, err := p.Unprotect(ctx, protected)
		require.NoError(t, err)
		// an empty plaintext comes back as an empty (possibly nil) slice
		assert.True(t, bytes.Equal(plaintext, unprotected), "size %d", size)
	}

	// a blob of exactly the overhead is an empty plaintext, one byte less
	// can not carry a tag
	empty, err := p.Protect(ctx, nil)
	require.NoError(t, err)
	require.Len(t, empty, SymmetricOverhead)
	_, err = p.Unprotect(ctx, empty[:SymmetricOverhead-1])
	assert.EqualError(t, err, "failed to unprotect: cipher: message authentication failed")

	nonces := map[string]bool{}
	for range 256 {
		protected, err := p.Protect(ctx, []byte("x"))
		require.NoError(t, err)
		nonce := string(protected[:SymmetricNonceSize])
		assert.False(t, nonces[nonce], "nonce reused")
		nonces[nonce] = true
	}
}

// TestSymmetricSameSecretSameKey checks that providers created from the
// same secret interoperate and that another secret does not, which is the
// contract the rotation guidance relies on.
func TestSymmetricSameSecretSameKey(t *testing.T) {
	secret := make([]byte, SymmetricMinSecretSize)
	_, err := rand.Read(secret)
	require.NoError(t, err)
	p1, err := NewSymmetric(secret)
	require.NoError(t, err)
	p2, err := NewSymmetric(secret)
	require.NoError(t, err)

	ctx := context.Background()
	protected, err := p1.Protect(ctx, []byte("rotate me"))
	require.NoError(t, err)
	got, err := p2.Unprotect(ctx, protected)
	require.NoError(t, err)
	assert.Equal(t, "rotate me", string(got))

	other := make([]byte, SymmetricMinSecretSize)
	_, err = rand.Read(other)
	require.NoError(t, err)
	p3, err := NewSymmetric(other)
	require.NoError(t, err)
	_, err = p3.Unprotect(ctx, protected)
	assert.EqualError(t, err, "failed to unprotect: cipher: message authentication failed")
}

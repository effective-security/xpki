package dataprotection

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"github.com/cockroachdb/errors"
	"golang.org/x/crypto/hkdf"
)

// Parameters of the provider returned by NewSymmetric. They document the
// blob layout and the usage limits; see the package documentation
// (XPKI-083).
const (
	// SymmetricNonceSize is the size in bytes of the random nonce that
	// starts every protected blob (the standard 96-bit GCM nonce).
	SymmetricNonceSize = 12
	// SymmetricTagSize is the size in bytes of the GCM authentication tag
	// that ends every protected blob.
	SymmetricTagSize = 16
	// SymmetricOverhead is the number of bytes a protected blob is longer
	// than its plaintext.
	SymmetricOverhead = SymmetricNonceSize + SymmetricTagSize
	// SymmetricMinSecretSize is the recommended minimum size in bytes of the
	// secret given to NewSymmetric: 256 bits of key material from
	// crypto/rand, matching the AES-256 key HKDF derives from it. It is a
	// recommendation, not enforced: NewSymmetric accepts any secret so that
	// existing callers keep working.
	SymmetricMinSecretSize = 32
	// SymmetricMaxMessagesPerKey is the maximum number of Protect calls
	// under one secret: with 96-bit random nonces, NIST SP 800-38D §8.3
	// limits the invocations of the authenticated encryption function to
	// 2^32 per key, so that the probability of a nonce collision stays
	// below 2^-32.
	SymmetricMaxMessagesPerKey uint64 = 1 << 32
)

type symProvider struct {
	gcm       cipher.AEAD
	nonceSize int
}

// NewSymmetric returns a Provider based on AES-256-GCM with a key derived
// from secret by HKDF-SHA256 (no salt, no info).
//
// secret must be high-entropy key material, at least SymmetricMinSecretSize
// bytes from crypto/rand or the output of a memory-hard password KDF; HKDF
// does not harden a passphrase. The same secret always derives the same key,
// so blobs protected under it are readable by every provider created from
// it. The size of secret is not checked. See the package documentation for
// the per-secret usage limits and rotation guidance.
func NewSymmetric(secret []byte) (Provider, error) {
	// Underlying hash function for HMAC.
	hash := sha256.New

	hkdf := hkdf.New(hash, secret, nil, nil)

	// AES-256
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, errors.WithStack(err)
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &symProvider{gcm: gcm, nonceSize: gcm.NonceSize()}, nil
}

// Protect returns the protected blob
//
//	nonce (SymmetricNonceSize) || AES-256-GCM ciphertext || tag (SymmetricTagSize)
//
// with a fresh random nonce, so the blob is SymmetricOverhead bytes longer
// than data. No associated data is bound. The caller must not exceed
// SymmetricMaxMessagesPerKey calls under one secret; data must be shorter
// than 2^36 - 32 bytes (the AES-GCM limit crypto/cipher enforces).
func (p symProvider) Protect(_ context.Context, data []byte) ([]byte, error) {
	nonce := make([]byte, p.nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.WithStack(err)
	}
	ciphertext := p.gcm.Seal(nil, nonce, data, nil)

	protected := make([]byte, len(nonce)+len(ciphertext))
	copy(protected, nonce)
	copy(protected[p.nonceSize:], ciphertext)

	return protected, nil
}

// Unprotect returns the data of a blob made by Protect. A blob shorter than
// the nonce is rejected; a blob protected under another secret, or modified
// in any byte, fails with "failed to unprotect: cipher: message
// authentication failed". The blob does not identify its secret: the caller
// must know which secret protected it (see the package documentation on
// rotation).
func (p symProvider) Unprotect(_ context.Context, protected []byte) ([]byte, error) {
	if len(protected) < p.nonceSize {
		return nil, errors.Errorf("invalid data: less than nonce size")
	}
	plaintext, err := p.gcm.Open(nil, protected[:p.nonceSize], protected[p.nonceSize:], nil)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to unprotect")
	}

	return plaintext, nil
}

// IsReady returns true when provider has encryption keys
func (p symProvider) IsReady() bool {
	return true
}

// PublicKey is returned for asymmetric signer
func (p symProvider) PublicKey() crypto.PublicKey {
	return nil
}

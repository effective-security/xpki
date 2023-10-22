package dataprotection

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"github.com/pkg/errors"
	"golang.org/x/crypto/hkdf"
)

type symProvider struct {
	gcm       cipher.AEAD
	nonceSize int
}

// NewSymmetric returns `Provider` based on AES256-GCM encryption
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

// Protect returns protected blob
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

// Unprotect returns unprotected data
func (p symProvider) Unprotect(_ context.Context, protected []byte) ([]byte, error) {
	if len(protected) < p.nonceSize {
		return nil, errors.Errorf("invalid data")
	}
	plaintext, err := p.gcm.Open(nil, protected[:p.nonceSize], protected[p.nonceSize:], nil)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to upprotect")
	}

	return plaintext, nil
}

// IsReady returns true when provider has encryption keys
func (p symProvider) IsReady() bool {
	return true
}

// PublicKey is returned for assymetric signer
func (p symProvider) PublicKey() crypto.PublicKey {
	return nil
}

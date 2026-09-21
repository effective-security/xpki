package inmemcrypto_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"
	"testing"

	"github.com/effective-security/xpki/cryptoprov/inmemcrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	keyWriters    = 4
	keyReaders    = 4
	keysPerWriter = 4
	rsaKeyBits    = 2048
	signPurpose   = 1
	missingKeyID  = "missing-key"
)

func TestConcurrentKeyOperations(t *testing.T) {
	p := inmemcrypto.NewProvider()
	existingEC, err := p.GenerateECDSAKey("existing-ec", elliptic.P256())
	require.NoError(t, err)
	existingRSA, err := p.GenerateRSAKey("existing-rsa", rsaKeyBits, signPurpose)
	require.NoError(t, err)

	type generatedKey struct {
		key   crypto.PrivateKey
		label string
		err   error
	}
	generated := make([]generatedKey, keyWriters*keysPerWriter)
	start := make(chan struct{})
	stop := make(chan struct{})
	var ready, writers, readers sync.WaitGroup
	ready.Add(keyWriters + keyReaders)
	writers.Add(keyWriters)
	readers.Add(keyReaders)
	for range keyReaders {
		go func() {
			defer readers.Done()
			ready.Done()
			<-start
			for {
				checkStoredKey(t, p, existingEC, "existing-ec")
				checkStoredKey(t, p, existingRSA, "existing-rsa")
				key, err := p.GetKey(missingKeyID)
				assert.EqualError(t, err, "key not found: missing-key: key not found: missing-key")
				assert.True(t, key == nil, "missing key must return nil")
				uri, keyBytes, err := p.ExportKey(missingKeyID)
				assert.EqualError(t, err, "unable to get key: missing-key: key not found: missing-key")
				assert.Empty(t, uri)
				assert.True(t, keyBytes == nil, "missing key must not export bytes")
				select {
				case <-stop:
					return
				default:
				}
			}
		}()
	}
	for worker := range keyWriters {
		go func() {
			defer writers.Done()
			ready.Done()
			<-start
			for i := range keysPerWriter {
				result := &generated[worker*keysPerWriter+i]
				result.label = fmt.Sprintf("worker-%d-key-%d", worker, i)
				if worker == 0 {
					result.key, result.err = p.GenerateRSAKey(result.label, rsaKeyBits, signPurpose)
				} else {
					result.key, result.err = p.GenerateECDSAKey(result.label, elliptic.P256())
				}
				if assert.NoError(t, result.err) {
					checkStoredKey(t, p, result.key, result.label)
				}
			}
		}()
	}
	ready.Wait()
	close(start)
	writers.Wait()
	close(stop)
	readers.Wait()

	ids := make(map[string]struct{}, len(generated))
	for _, result := range generated {
		require.NoError(t, result.err)
		exported := checkStoredKey(t, p, result.key, result.label)
		require.NotNil(t, exported)
		id, _, err := p.IdentifyKey(result.key)
		require.NoError(t, err)
		assert.NotContains(t, ids, id, "generated key ID must be unique")
		ids[id] = struct{}{}
		signer, ok := result.key.(crypto.Signer)
		require.True(t, ok)
		publicKey := signer.Public()
		checkSignature(t, signer, publicKey)
		checkSignature(t, exported, publicKey)
	}
}

// All assertions are nonfatal because readers call this helper in goroutines.
// Private key bytes are never included in failure messages.
func checkStoredKey(t *testing.T, p *inmemcrypto.Provider, key crypto.PrivateKey, label string) crypto.Signer {
	t.Helper()
	id, actualLabel, err := p.IdentifyKey(key)
	if !assert.NoError(t, err) {
		return nil
	}
	assert.NotEmpty(t, id)
	assert.Equal(t, label, actualLabel)
	stored, err := p.GetKey(id)
	if !assert.NoError(t, err) {
		return nil
	}
	assert.True(t, key == stored, "lookup must return the registered signer")
	uri, keyBytes, err := p.ExportKey(id)
	if !assert.NoError(t, err) {
		return nil
	}
	assert.Empty(t, uri)
	block, rest := pem.Decode(keyBytes)
	if !assert.True(t, block != nil, "export must contain a PEM block") {
		return nil
	}
	assert.True(t, len(rest) == 0, "export must contain exactly one PEM block")
	assert.Empty(t, block.Headers)
	signer, ok := key.(crypto.Signer)
	if !assert.True(t, ok, "generated key must support signing") {
		return nil
	}
	var exported crypto.Signer
	switch publicKey := signer.Public().(type) {
	case *ecdsa.PublicKey:
		assert.Equal(t, "EC PRIVATE KEY", block.Type)
		parsed, err := x509.ParseECPrivateKey(block.Bytes)
		if !assert.NoError(t, err) {
			return nil
		}
		assert.True(t, publicKey.Equal(parsed.Public()), "exported EC key must match the signer")
		exported = parsed
	case *rsa.PublicKey:
		assert.Equal(t, "RSA PRIVATE KEY", block.Type)
		parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if !assert.NoError(t, err) {
			return nil
		}
		assert.True(t, publicKey.Equal(parsed.Public()), "exported RSA key must match the signer")
		exported = parsed
	default:
		t.Errorf("unexpected public key type %T", publicKey)
		return nil
	}
	// Caller-owned PEM buffers must not affect another lookup or export.
	keyBytes[0] ^= 1
	return exported
}

func checkSignature(t *testing.T, signer crypto.Signer, publicKey crypto.PublicKey) {
	t.Helper()
	digest := sha256.Sum256([]byte("inmemcrypto concurrent key operations"))
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	switch publicKey := publicKey.(type) {
	case *ecdsa.PublicKey:
		assert.True(t, ecdsa.VerifyASN1(publicKey, digest[:], signature))
	case *rsa.PublicKey:
		require.NoError(t, rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature))
	default:
		t.Fatalf("unexpected public key type %T", publicKey)
	}
}

func BenchmarkGetKey(b *testing.B) {
	p := inmemcrypto.NewProvider()
	key, err := p.GenerateECDSAKey("benchmark", elliptic.P256())
	require.NoError(b, err)
	id, _, err := p.IdentifyKey(key)
	require.NoError(b, err)
	b.Run("hit", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			stored, err := p.GetKey(id)
			if err != nil || stored != key {
				b.Fatal("lookup did not return the registered signer")
			}
		}
	})
	b.Run("miss", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			stored, err := p.GetKey(missingKeyID)
			if err == nil || stored != nil {
				b.Fatal("missing-key lookup must return an error and no key")
			}
		}
	})
}

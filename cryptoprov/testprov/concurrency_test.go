package testprov_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"

	"github.com/effective-security/xpki/cryptoprov/testprov"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	keyWriters    = 4
	keyReaders    = 4
	keysPerWriter = 4
	rsaKeyBits    = 2048
	missingKeyID  = "missing-key"
	keyURIFormat  = "pkcs11:manufacturer=testprov;model=inmem;serial=20764350726;token=%s;id=%s;type=private"
)

func TestConcurrentKeyOperations(t *testing.T) {
	p, err := testprov.Init()
	require.NoError(t, err)
	existing, err := p.GenerateECDSAKey("existing", elliptic.P256())
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
				checkStoredKey(t, p, existing, "existing")
				key, err := p.GetKey(missingKeyID)
				assert.EqualError(t, err, "GetKey(missing-key): key not found: missing-key")
				assert.True(t, key == nil, "missing key must return nil")
				uri, keyBytes, err := p.ExportKey(missingKeyID)
				assert.EqualError(t, err, "keyID=missing-key: key not found: missing-key")
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
					result.key, result.err = p.GenerateRSAKey(result.label, rsaKeyBits, 2)
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
		checkStoredKey(t, p, result.key, result.label)
		id, _, err := p.IdentifyKey(result.key)
		require.NoError(t, err)
		assert.NotContains(t, ids, id, "generated key ID must be unique")
		ids[id] = struct{}{}
		checkKeyOperations(t, result.key)
	}
	checkKeyOperations(t, existing)
}

// All assertions in this helper are nonfatal because readers call it in goroutines.
func checkStoredKey(t *testing.T, p *testprov.Provider, key crypto.PrivateKey, label string) {
	t.Helper()
	id, actualLabel, err := p.IdentifyKey(key)
	if !assert.NoError(t, err) {
		return
	}
	assert.NotEmpty(t, id)
	assert.Equal(t, label, actualLabel)
	stored, err := p.GetKey(id)
	if !assert.NoError(t, err) {
		return
	}
	assert.True(t, key == stored, "lookup must return the registered signer")
	uri, keyBytes, err := p.ExportKey(id)
	if assert.NoError(t, err) {
		assert.Equal(t, fmt.Sprintf(keyURIFormat, label, id), uri)
		assert.True(t, keyBytes == nil, "private key bytes must not be exported")
	}
}

func checkKeyOperations(t *testing.T, key crypto.PrivateKey) {
	t.Helper()
	signer, ok := key.(crypto.Signer)
	require.True(t, ok)
	message := []byte("testprov concurrent key operations")
	digest := sha256.Sum256(message)
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	switch publicKey := signer.Public().(type) {
	case *ecdsa.PublicKey:
		assert.True(t, ecdsa.VerifyASN1(publicKey, digest[:], signature))
	case *rsa.PublicKey:
		err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature)
		require.NoError(t, err)
		ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, message, nil)
		require.NoError(t, err)
		decrypter, ok := key.(crypto.Decrypter)
		require.True(t, ok)
		plaintext, err := decrypter.Decrypt(rand.Reader, ciphertext, &rsa.OAEPOptions{
			Hash: crypto.SHA256,
		})
		require.NoError(t, err)
		assert.Equal(t, message, plaintext)
	default:
		t.Fatalf("unexpected public key type %T", publicKey)
	}
}

func BenchmarkGetKey(b *testing.B) {
	p, err := testprov.Init()
	require.NoError(b, err)
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

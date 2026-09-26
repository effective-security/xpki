package gcpkmscrypto_test

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/cryptoprov/gcpkmscrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	lifecycleSigners = 4
	lifecycleClosers = 3
	// closeBlockedFor is how long Close must stay blocked while signs run.
	closeBlockedFor = 50 * time.Millisecond
)

// TestCloseWaitsForInflightSign overlaps blocked signing RPCs with
// concurrent Close calls, then uses the provider after Close (XPKI-018).
func TestCloseWaitsForInflightSign(t *testing.T) {
	var inflight, closedDuringSign atomic.Int32
	started := make(chan struct{}, lifecycleSigners)
	release := make(chan struct{})
	closeErr := errors.New("close failed")
	client := &fakeKMS{
		asymmetricSign: func(req *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
			inflight.Add(1)
			defer inflight.Add(-1)
			started <- struct{}{}
			<-release
			return signResponse(req, []byte("signature")), nil
		},
		close: func() error {
			if inflight.Load() != 0 {
				closedDuringSign.Add(1)
			}
			return closeErr
		},
	}
	provider := newProvider(t, client)
	signer := gcpkmscrypto.NewSigner("key", "label", nil, provider)
	digest := sha256.Sum256([]byte("to be signed"))

	var signs sync.WaitGroup
	signErrs := make([]error, lifecycleSigners)
	for i := range lifecycleSigners {
		signs.Go(func() {
			_, signErrs[i] = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		})
	}
	for range lifecycleSigners {
		<-started
	}

	var closers sync.WaitGroup
	closeErrs := make([]error, lifecycleClosers)
	closed := make(chan struct{})
	for i := range lifecycleClosers {
		closers.Go(func() {
			closeErrs[i] = provider.Close()
		})
	}
	go func() {
		closers.Wait()
		close(closed)
	}()

	select {
	case <-closed:
		t.Fatal("Close returned while signing RPCs were in flight")
	case <-time.After(closeBlockedFor):
	}

	close(release)
	signs.Wait()
	<-closed

	for i, err := range signErrs {
		assert.NoError(t, err, "sign %d", i)
	}
	assert.Zero(t, closedDuringSign.Load(), "client closed while a sign was in flight")

	// exactly one Close closes the client and reports its error
	var failed int
	for _, err := range closeErrs {
		if err != nil {
			failed++
			assert.ErrorIs(t, err, closeErr)
			assert.Equal(t, "unable to close KMS client: close failed", err.Error())
		}
	}
	assert.Equal(t, 1, failed)
	assert.NoError(t, provider.Close())
	assert.NotNil(t, provider.KmsClient, "Close must not clear the client")

	callsBefore := len(client.Calls())
	for name, op := range map[string]func() error{
		"Sign": func() error {
			_, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
			return err
		},
		"GetKey": func() error {
			_, err := provider.GetKey("key")
			return err
		},
		"KeyInfo": func() error {
			_, err := provider.KeyInfo(0, "key", true)
			return err
		},
		"EnumKeys": func() error {
			_, err := provider.EnumKeys(0, "")
			return err
		},
		"DestroyKeyPairOnSlot": func() error {
			return provider.DestroyKeyPairOnSlot(0, "key")
		},
		"GenerateRSAKey": func() error {
			_, err := provider.GenerateRSAKey("label", 2048, 1)
			return err
		},
		"GenerateECDSAKey": func() error {
			_, err := provider.GenerateECDSAKey("label", elliptic.P256())
			return err
		},
	} {
		err := op()
		require.Error(t, err, name)
		assert.ErrorIs(t, err, gcpkmscrypto.ErrClosed, name)
	}
	assert.Len(t, client.Calls(), callsBefore, "no RPC after Close")
}

// TestCloseIdle closes a provider with no calls in flight, twice.
func TestCloseIdle(t *testing.T) {
	client := &fakeKMS{}
	provider := coverageProvider(t, client)
	require.NoError(t, provider.Close())
	require.NoError(t, provider.Close())
	assert.Equal(t, []string{"Close"}, client.Calls())

	// operations that do not use the client still work
	uri, _, err := provider.ExportKey("key")
	require.NoError(t, err)
	assert.Contains(t, uri, "id=key")
}

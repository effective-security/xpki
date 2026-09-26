package gcpkmscrypto_test

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/cryptoprov/gcpkmscrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	genKey        = "gen"
	genKeyName    = coverageKeyring + "/cryptoKeys/" + genKey
	genVersion    = genKeyName + "/cryptoKeyVersions/1"
	genVersionID  = genKey + "/cryptoKeyVersions/1"
	genAttempts   = 5
	genInterval   = 250 * time.Millisecond
	cancelLatency = time.Second
)

var keyIDSuffix = regexp.MustCompile(`^(.*)-([a-z2-7]{8})$`)

// TestKeyLabelAndID checks the label and id rules: charset, length,
// suffix retention and randomness (XPKI-022).
func TestKeyLabelAndID(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("A", 80)
	for _, tc := range []struct {
		name  string
		in    string
		label string
		base  string
	}{
		{name: "plain", in: "plain", label: "plain", base: "plain"},
		{name: "star", in: "plain*", label: "plain", base: "plain"},
		{name: "upper and punctuation", in: "My Key.v1/Test:CA_2", label: "my-key-v1-test-ca_2", base: "my-key-v1-test-ca_2"},
		{name: "unicode", in: "ünïcode", label: "-n-code", base: "-n-code"},
		{name: "long", in: long + "*", label: strings.Repeat("a", 63), base: strings.Repeat("a", 54)},
		{name: "exactly fits", in: strings.Repeat("b", 54), label: strings.Repeat("b", 54), base: strings.Repeat("b", 54)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			label, id := gcpkmscrypto.KeyLabelAndID(tc.in)
			assert.Equal(t, tc.label, label)
			m := keyIDSuffix.FindStringSubmatch(id)
			require.NotNil(t, m, id)
			assert.Equal(t, tc.base, m[1])
			assert.LessOrEqual(t, len(id), 63)
			assert.LessOrEqual(t, len(label), 63)
			assert.Regexp(t, `^[a-z0-9_-]*$`, label)
			assert.Regexp(t, `^[a-z0-9_-]{1,63}$`, id)

			// the label repeats, the id does not
			label2, id2 := gcpkmscrypto.KeyLabelAndID(tc.in)
			assert.Equal(t, label, label2)
			assert.NotEqual(t, id, id2)
		})
	}

	t.Run("empty", func(t *testing.T) {
		label, id := gcpkmscrypto.KeyLabelAndID("")
		assert.Empty(t, label)
		assert.Regexp(t, `^[a-z2-7]{8}$`, id)
		label, id = gcpkmscrypto.KeyLabelAndID("*")
		assert.Empty(t, label)
		assert.Regexp(t, `^[a-z2-7]{8}$`, id)
	})
}

// TestGenerateRSAKeyPurpose checks that an encryption key is rejected
// before any RPC (XPKI-019) and that every other purpose is a signing key,
// as in the other providers (XPKI-118).
func TestGenerateRSAKeyPurpose(t *testing.T) {
	t.Parallel()

	client := &fakeKMS{}
	provider := newProvider(t, client)
	_, err := provider.GenerateRSAKey("enc", 2048, 2)
	require.EqualError(t, err, "unsupported key purpose: 2, only signing keys are supported")
	_, err = provider.GenerateRSAKey("enc", 1024, 1)
	require.EqualError(t, err, "unsupported key size: 1024")
	assert.Empty(t, client.Calls())

	for _, purpose := range []int{0, 1, 3} {
		_, err := provider.GenerateRSAKey("sign", 2048, purpose)
		require.ErrorIs(t, err, errUnexpectedCall, "purpose %d reaches CreateCryptoKey", purpose)
	}
	assert.Equal(t, 3, client.CallCount("CreateCryptoKey"))
}

// generatingKMS returns a fake client whose CreateCryptoKey answers with
// createErrs in turn before creating genKey, whose version 1 reports
// PENDING_GENERATION pending times before state.
func generatingKMS(pending int, state kmspb.CryptoKeyVersion_CryptoKeyVersionState, createErrs ...error) *fakeKMS {
	var mu sync.Mutex
	return &fakeKMS{
		createCryptoKey: func(req *kmspb.CreateCryptoKeyRequest) (*kmspb.CryptoKey, error) {
			mu.Lock()
			defer mu.Unlock()
			if len(createErrs) > 0 {
				err := createErrs[0]
				createErrs = createErrs[1:]
				return nil, err
			}
			return &kmspb.CryptoKey{
				Name:            genKeyName,
				Purpose:         req.GetCryptoKey().GetPurpose(),
				VersionTemplate: req.GetCryptoKey().GetVersionTemplate(),
				Labels:          req.GetCryptoKey().GetLabels(),
			}, nil
		},
		getCryptoKeyVersion: func(req *kmspb.GetCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
			mu.Lock()
			defer mu.Unlock()
			ver := enabledVersion(genKey, kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256)
			ver.Name = req.GetName()
			if pending > 0 {
				pending--
				ver.State = kmspb.CryptoKeyVersion_PENDING_GENERATION
			} else {
				ver.State = state
				if state == kmspb.CryptoKeyVersion_GENERATION_FAILED {
					ver.GenerationFailureReason = "hsm error"
				}
			}
			return ver, nil
		},
		getPublicKey: func(req *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
			return &kmspb.PublicKey{Name: req.GetName(), Pem: p256PublicPEM}, nil
		},
	}
}

// recordingSleep returns a wait that records the requested durations and
// returns at once.
func recordingSleep(mu *sync.Mutex, waits *[]time.Duration) func(context.Context, time.Duration) error {
	return func(_ context.Context, d time.Duration) error {
		mu.Lock()
		defer mu.Unlock()
		*waits = append(*waits, d)
		return nil
	}
}

// TestGenerateKeyIDExists checks that an existing key id is retried with a
// new id, and that other creation errors are not (XPKI-022).
func TestGenerateKeyIDExists(t *testing.T) {
	t.Parallel()

	exists := status.Error(codes.AlreadyExists, "exists")
	invalid := status.Error(codes.InvalidArgument, "invalid")

	t.Run("retried", func(t *testing.T) {
		t.Parallel()
		client := generatingKMS(0, kmspb.CryptoKeyVersion_ENABLED, exists, exists)
		var ids []string
		create := client.createCryptoKey
		client.createCryptoKey = func(req *kmspb.CreateCryptoKeyRequest) (*kmspb.CryptoKey, error) {
			ids = append(ids, req.GetCryptoKeyId())
			assert.Equal(t, "label", req.GetCryptoKey().GetLabels()["label"])
			return create(req)
		}
		pk, err := newProvider(t, client).GenerateECDSAKey("label", elliptic.P256())
		require.NoError(t, err)
		assert.Equal(t, genVersionID, pk.(*gcpkmscrypto.Signer).KeyID())
		require.Len(t, ids, 3)
		assert.Len(t, map[string]bool{ids[0]: true, ids[1]: true, ids[2]: true}, 3, "distinct ids: %v", ids)
		assert.Equal(t, []string{"CreateCryptoKey", "CreateCryptoKey", "CreateCryptoKey", "GetCryptoKeyVersion", "GetPublicKey"}, client.Calls())
	})

	t.Run("exhausted", func(t *testing.T) {
		t.Parallel()
		client := generatingKMS(0, kmspb.CryptoKeyVersion_ENABLED, exists, exists, exists)
		_, err := newProvider(t, client).GenerateECDSAKey("label", elliptic.P256())
		require.Error(t, err)
		assert.Equal(t, codes.AlreadyExists, status.Code(errors.UnwrapAll(err)))
		assert.True(t, strings.HasPrefix(err.Error(), "failed to create key label-"), err.Error())
		assert.Equal(t, 3, client.CallCount("CreateCryptoKey"))
		assert.Equal(t, 0, client.CallCount("GetCryptoKeyVersion"))
	})

	t.Run("other error", func(t *testing.T) {
		t.Parallel()
		client := generatingKMS(0, kmspb.CryptoKeyVersion_ENABLED, invalid)
		_, err := newProvider(t, client).GenerateECDSAKey("label", elliptic.P256())
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(errors.UnwrapAll(err)))
		assert.Equal(t, 1, client.CallCount("CreateCryptoKey"))
	})
}

// TestGenerateKeyWait checks the poll count, the waits between polls and
// the stop conditions of the wait for key generation (XPKI-024).
func TestGenerateKeyWait(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		pending int
		state   kmspb.CryptoKeyVersion_CryptoKeyVersionState
		polls   int
		waits   int
		public  int
		err     string
	}{
		{name: "ready at once", pending: 0, state: kmspb.CryptoKeyVersion_ENABLED, polls: 1, waits: 0, public: 1},
		{name: "ready after 3 polls", pending: 3, state: kmspb.CryptoKeyVersion_ENABLED, polls: 4, waits: 3, public: 1},
		{name: "ready on the last poll", pending: genAttempts - 1, state: kmspb.CryptoKeyVersion_ENABLED, polls: genAttempts, waits: genAttempts - 1, public: 1},
		{name: "exhausted", pending: genAttempts, state: kmspb.CryptoKeyVersion_ENABLED, polls: genAttempts, waits: genAttempts - 1, err: "key version " + genVersion + " is still PENDING_GENERATION after 5 polls"},
		{name: "generation failed", pending: 0, state: kmspb.CryptoKeyVersion_GENERATION_FAILED, polls: 1, waits: 0, err: "key version " + genVersionID + " is GENERATION_FAILED: hsm error"},
		{name: "disabled after pending", pending: 2, state: kmspb.CryptoKeyVersion_DISABLED, polls: 3, waits: 2, err: "key version " + genVersionID + " is DISABLED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var mu sync.Mutex
			var waits []time.Duration
			client := generatingKMS(tc.pending, tc.state)
			provider := newProvider(t, client)
			gcpkmscrypto.SetGenerationWait(provider, genInterval, genAttempts, recordingSleep(&mu, &waits))

			pk, err := provider.GenerateECDSAKey("label", elliptic.P256())
			if tc.err != "" {
				require.EqualError(t, err, tc.err)
				assert.Nil(t, pk)
			} else {
				require.NoError(t, err)
				assert.Equal(t, genVersionID, pk.(*gcpkmscrypto.Signer).KeyID())
			}
			assert.Equal(t, tc.polls, client.CallCount("GetCryptoKeyVersion"), "polls")
			assert.Equal(t, tc.public, client.CallCount("GetPublicKey"), "GetPublicKey calls")
			assert.Len(t, waits, tc.waits, "waits")
			for _, d := range waits {
				assert.Equal(t, genInterval, d)
			}
		})
	}

	t.Run("poll error", func(t *testing.T) {
		t.Parallel()
		failure := errors.New("KMS unavailable")
		client := generatingKMS(0, kmspb.CryptoKeyVersion_ENABLED)
		client.getCryptoKeyVersion = func(*kmspb.GetCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
			return nil, failure
		}
		provider := newProvider(t, client)
		var mu sync.Mutex
		var waits []time.Duration
		gcpkmscrypto.SetGenerationWait(provider, genInterval, genAttempts, recordingSleep(&mu, &waits))
		_, err := provider.GenerateECDSAKey("label", elliptic.P256())
		require.ErrorIs(t, err, failure)
		assert.Equal(t, "failed to get key version "+genVersion+": KMS unavailable", err.Error())
		assert.Equal(t, 1, client.CallCount("GetCryptoKeyVersion"))
		assert.Empty(t, waits)
	})
}

// pollingProvider returns a provider over a fake whose version never leaves
// PENDING_GENERATION, with the real wait and a long interval, and a channel
// that receives each poll.
func pollingProvider(t *testing.T) (*gcpkmscrypto.Provider, <-chan struct{}) {
	t.Helper()
	polled := make(chan struct{}, genAttempts)
	client := generatingKMS(genAttempts, kmspb.CryptoKeyVersion_ENABLED)
	poll := client.getCryptoKeyVersion
	client.getCryptoKeyVersion = func(req *kmspb.GetCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
		polled <- struct{}{}
		return poll(req)
	}
	provider := newProvider(t, client)
	gcpkmscrypto.SetGenerationWait(provider, time.Hour, genAttempts, nil)
	return provider, polled
}

// TestGenerateKeyWaitCancelled checks that Close and a cancelled context
// end the wait for key generation at once (XPKI-024).
func TestGenerateKeyWaitCancelled(t *testing.T) {
	t.Parallel()

	t.Run("close", func(t *testing.T) {
		t.Parallel()
		provider, polled := pollingProvider(t)
		done := make(chan error, 1)
		go func() {
			_, err := provider.GenerateECDSAKey("label", elliptic.P256())
			done <- err
		}()
		<-polled

		closeStart := time.Now()
		require.NoError(t, provider.Close())
		closeLatency := time.Since(closeStart)

		select {
		case err := <-done:
			require.ErrorIs(t, err, gcpkmscrypto.ErrClosed)
			assert.Equal(t, "key version "+genVersion+" is PENDING_GENERATION: gcpkms: provider is closed", err.Error())
		case <-time.After(cancelLatency):
			t.Fatal("key generation did not stop after Close")
		}
		assert.Less(t, closeLatency, cancelLatency, "Close waited for the poll interval")
		assert.Equal(t, 1, provider.KmsClient.(*fakeKMS).CallCount("GetCryptoKeyVersion"))
	})

	t.Run("context", func(t *testing.T) {
		t.Parallel()
		provider, polled := pollingProvider(t)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			_, err := gcpkmscrypto.GenKey(provider, ctx, "label", kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256)
			done <- err
		}()
		<-polled
		cancel()
		select {
		case err := <-done:
			require.ErrorIs(t, err, context.Canceled)
		case <-time.After(cancelLatency):
			t.Fatal("key generation did not stop after cancellation")
		}
		// the provider is not closed: it still serves requests
		assert.NoError(t, provider.Close())
	})
}

// TestGenerateKeyRequest checks the CreateCryptoKey request of each
// generator against the real SDK client.
func TestGenerateKeyRequest(t *testing.T) {
	t.Parallel()

	s := newFakeKMSServer()
	provider := grpcProvider(t, s)

	for _, tc := range []struct {
		name      string
		generate  func() (crypto.PrivateKey, error)
		algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
	}{
		{name: "rsa2048", generate: func() (crypto.PrivateKey, error) { return provider.GenerateRSAKey("RSA 2048", 2048, 1) }, algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256},
		{name: "rsa3072", generate: func() (crypto.PrivateKey, error) { return provider.GenerateRSAKey("RSA 3072", 3072, 1) }, algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256},
		{name: "rsa4096", generate: func() (crypto.PrivateKey, error) { return provider.GenerateRSAKey("RSA 4096", 4096, 1) }, algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512},
		{name: "p256", generate: func() (crypto.PrivateKey, error) { return provider.GenerateECDSAKey("EC P256*", elliptic.P256()) }, algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
		{name: "p384", generate: func() (crypto.PrivateKey, error) { return provider.GenerateECDSAKey("EC P384", elliptic.P384()) }, algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pk, err := tc.generate()
			require.NoError(t, err)
			signer := pk.(*gcpkmscrypto.Signer)
			assert.Equal(t, tc.algorithm, signer.Algorithm())
			ids := s.CreateIDs()
			id := ids[len(ids)-1]
			assert.Regexp(t, `^(rsa|ec)-(2048|3072|4096|p256|p384)-[a-z2-7]{8}$`, id)
			assert.Equal(t, id+"/cryptoKeyVersions/1", signer.KeyID())
			assert.Equal(t, strings.TrimSuffix(id[:len(id)-9], "-"), signer.Label())

			ki, err := provider.KeyInfo(0, signer.KeyID(), false)
			require.NoError(t, err)
			assert.Equal(t, "protection=HSM,label="+signer.Label(), ki.Label)
			assert.Equal(t, tc.algorithm.String(), ki.Meta["algo"])
			assert.Equal(t, "ASYMMETRIC_SIGN", ki.Meta["purpose"])
		})
	}
}

package gcpkmscrypto_test

import (
	"context"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/cryptoprov/gcpkmscrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/option"
)

// swapFactory replaces KmsClientFactory for the test.
func swapFactory(t *testing.T, factory func(string) (gcpkmscrypto.KmsClient, error)) {
	t.Helper()
	original := gcpkmscrypto.KmsClientFactory
	gcpkmscrypto.KmsClientFactory = factory
	t.Cleanup(func() { gcpkmscrypto.KmsClientFactory = original })
}

// TestInitEndpoint checks that Init hands the Endpoint attribute to the
// client factory and that a provider built through the SDK construction
// path reaches the server at that endpoint (XPKI-021).
func TestInitEndpoint(t *testing.T) {
	s := newFakeKMSServer()
	addr := startFakeKMS(t, s)
	s.AddKey(t, "ep", kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, "endpoint")

	var endpoints []string
	swapFactory(t, func(endpoint string) (gcpkmscrypto.KmsClient, error) {
		endpoints = append(endpoints, endpoint)
		return gcpkmscrypto.NewKmsClient(context.Background(), endpoint, localClientOptions()...)
	})

	for _, tc := range []struct {
		name     string
		atts     string
		endpoint string
	}{
		{name: "default", atts: "Keyring=" + testKeyring, endpoint: ""},
		{name: "custom", atts: "Endpoint=" + addr + ", Keyring=" + testKeyring, endpoint: addr},
		{name: "custom first", atts: "Keyring=" + testKeyring + ",Endpoint=" + addr, endpoint: addr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			endpoints = nil
			provider, err := gcpkmscrypto.Init(&mockTokenCfg{
				manufacturer: gcpkmscrypto.ProviderName,
				model:        "KMS",
				atts:         tc.atts,
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = provider.Close() })
			assert.Equal(t, []string{tc.endpoint}, endpoints)
			if tc.endpoint == "" {
				// the default endpoint is Google's; no RPC is made
				return
			}
			calls := s.CallCount("GetCryptoKey")
			ki, err := provider.KeyInfo(0, "ep", false)
			require.NoError(t, err)
			assert.Equal(t, "ep", ki.ID)
			assert.Equal(t, calls+1, s.CallCount("GetCryptoKey"))
		})
	}

	t.Run("factory failure", func(t *testing.T) {
		failure := errors.New("no credentials")
		swapFactory(t, func(string) (gcpkmscrypto.KmsClient, error) { return nil, failure })
		_, err := gcpkmscrypto.KmsLoader(&mockTokenCfg{atts: "Endpoint=" + addr + ",Keyring=" + testKeyring})
		require.ErrorIs(t, err, failure)
		assert.Equal(t, "failed to create KMS client: no credentials", err.Error())
	})

	// XPKI-120: without a keyring there is no provider and no client
	t.Run("missing keyring", func(t *testing.T) {
		endpoints = nil
		for _, atts := range []string{"", "Endpoint=" + addr, "keyring=" + testKeyring, "Keyring="} {
			_, err := gcpkmscrypto.Init(&mockTokenCfg{atts: atts})
			require.EqualError(t, err, "gcpkms: the Keyring attribute is required", atts)
		}
		assert.Empty(t, endpoints, "factory not called")
	})
}

// TestNewKmsClientEndpoint checks the SDK construction path itself: an
// endpoint is applied, and the default constructs without one.
func TestNewKmsClientEndpoint(t *testing.T) {
	t.Parallel()

	s := newFakeKMSServer()
	addr := startFakeKMS(t, s)
	s.AddKey(t, "first", kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, "first")

	client := grpcClient(t, addr)
	provider := gcpkmscrypto.NewTestProvider(testTokenCfg(testKeyring), client, testKeyring)
	keys, err := provider.EnumKeys(0, "")
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, "first", keys[0].ID)
	assert.Equal(t, 1, s.CallCount("ListCryptoKeys"))

	// the default endpoint: construction only, no RPC
	defaultClient, err := gcpkmscrypto.NewKmsClient(context.Background(), "", option.WithoutAuthentication())
	require.NoError(t, err)
	require.NoError(t, defaultClient.Close())
}

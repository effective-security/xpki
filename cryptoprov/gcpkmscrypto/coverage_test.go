package gcpkmscrypto_test

import (
	"context"
	"crypto/elliptic"
	"encoding/pem"
	"net"
	"strings"
	"testing"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/cryptoprov/gcpkmscrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const coverageKeyring = "projects/test/locations/global/keyRings/coverage"

// p256PublicPEM is a P-256 public key as GetPublicKey returns it.
const p256PublicPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpSwQTzpTI9LFgLtdHAMHl0oEIgwf
2i7YbXYfrucbC0xPekQgsxEJJqQJauSwOugli7FYYKxyapk3j6lGImVCbA==
-----END PUBLIC KEY-----
`

func coverageProvider(t *testing.T, client gcpkmscrypto.KmsClient) *gcpkmscrypto.Provider {
	t.Helper()
	swapFactory(t, func(string) (gcpkmscrypto.KmsClient, error) { return client, nil })
	provider, err := gcpkmscrypto.Init(&mockTokenCfg{
		manufacturer: gcpkmscrypto.ProviderName,
		model:        "KMS",
		atts:         "ignored, Keyring=" + coverageKeyring,
	})
	require.NoError(t, err)
	return provider
}

type listingKMSServer struct {
	kmspb.UnimplementedKeyManagementServiceServer
	requests chan *kmspb.ListCryptoKeysRequest
	fail     bool
}

func (s *listingKMSServer) ListCryptoKeys(_ context.Context, req *kmspb.ListCryptoKeysRequest) (*kmspb.ListCryptoKeysResponse, error) {
	s.requests <- req
	if s.fail {
		return nil, status.Error(codes.PermissionDenied, "denied")
	}
	key := &kmspb.CryptoKey{
		Name:       coverageKeyring + "/cryptoKeys/enabled",
		CreateTime: timestamppb.New(time.Unix(1000, 0)),
		Purpose:    kmspb.CryptoKey_ASYMMETRIC_SIGN,
		VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
			ProtectionLevel: kmspb.ProtectionLevel_HSM,
			Algorithm:       kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
		},
		Labels: map[string]string{"label": "test"},
		Primary: &kmspb.CryptoKeyVersion{
			Name:  coverageKeyring + "/cryptoKeys/enabled/cryptoKeyVersions/3",
			State: kmspb.CryptoKeyVersion_ENABLED,
		},
	}
	if req.PageToken == "second" {
		// no optional metadata: Primary, VersionTemplate, CreateTime (XPKI-023)
		bare := &kmspb.CryptoKey{
			Name:    coverageKeyring + "/cryptoKeys/no-primary",
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
		}
		return &kmspb.ListCryptoKeysResponse{CryptoKeys: []*kmspb.CryptoKey{bare}}, nil
	}
	disabled := &kmspb.CryptoKey{
		Name:    coverageKeyring + "/cryptoKeys/disabled",
		Primary: &kmspb.CryptoKeyVersion{State: kmspb.CryptoKeyVersion_DISABLED},
	}
	return &kmspb.ListCryptoKeysResponse{
		CryptoKeys:    []*kmspb.CryptoKey{key, disabled},
		NextPageToken: "second",
	}, nil
}

func TestEnumKeysPagination(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{
			false: "pages and disabled key",
			true:  "permission denied",
		}[fail], func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			service := &listingKMSServer{
				requests: make(chan *kmspb.ListCryptoKeysRequest, 4),
				fail:     fail,
			}
			server := grpc.NewServer()
			kmspb.RegisterKeyManagementServiceServer(server, service)
			go func() { _ = server.Serve(listener) }()
			t.Cleanup(server.Stop)
			client, err := kms.NewKeyManagementClient(context.Background(), option.WithEndpoint(listener.Addr().String()), option.WithoutAuthentication(), option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())))
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, client.Close()) })
			provider := coverageProvider(t, client)
			keys, err := provider.EnumKeys(0, "")
			if fail {
				require.Error(t, err)
				assert.Equal(t, codes.PermissionDenied, status.Code(errors.UnwrapAll(err)))
				assert.Nil(t, keys)
				return
			}
			require.NoError(t, err)
			require.Len(t, keys, 2)
			assert.Equal(t, "enabled", keys[0].ID)
			assert.Equal(t, "no-primary", keys[1].ID)
			assert.Equal(t, "ENABLED", keys[0].Meta["state"])
			assert.Equal(t, "3", keys[0].CurrentVersionID)
			assert.Equal(t, map[string]string{"purpose": "ASYMMETRIC_SIGN"}, keys[1].Meta)
			assert.Empty(t, keys[1].CurrentVersionID)
			assert.Nil(t, keys[1].CreationTime)
			assert.Empty(t, keys[1].Label)
			assert.Equal(t, "HSM", keys[0].Meta["protection"])
			assert.Equal(t, time.Unix(1000, 0).UTC(), *keys[0].CreationTime)
			first, second := <-service.requests, <-service.requests
			assert.Equal(t, coverageKeyring, first.Parent)
			assert.Empty(t, first.PageToken)
			assert.Equal(t, "second", second.PageToken)
		})
	}
}

// TestKMSFailurePropagation checks that every KMS error is returned wrapped
// from the operation that made the call.
func TestKMSFailurePropagation(t *testing.T) {
	t.Parallel()

	failure := errors.New("KMS unavailable")
	key := func(*kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error) {
		return &kmspb.CryptoKey{
			Name:            coverageKeyring + "/cryptoKeys/key",
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{},
		}, nil
	}
	version := func(*kmspb.GetCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
		return enabledVersion("key", kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256), nil
	}
	failVersion := func(*kmspb.GetCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) { return nil, failure }
	failPublic := func(*kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) { return nil, failure }
	malformedPublic := func(*kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
		return &kmspb.PublicKey{Pem: string(pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: []byte("invalid"),
		}))}, nil
	}
	created := func(*kmspb.CreateCryptoKeyRequest) (*kmspb.CryptoKey, error) {
		return &kmspb.CryptoKey{Name: coverageKeyring + "/cryptoKeys/key"}, nil
	}

	for _, tc := range []struct {
		name   string
		client *fakeKMS
		op     func(*gcpkmscrypto.Provider) error
	}{
		{
			name:   "create",
			client: &fakeKMS{createCryptoKey: func(*kmspb.CreateCryptoKeyRequest) (*kmspb.CryptoKey, error) { return nil, failure }},
			op:     func(p *gcpkmscrypto.Provider) error { _, err := p.GenerateRSAKey("test", 2048, 1); return err },
		},
		{
			name:   "generate version",
			client: &fakeKMS{createCryptoKey: created, getCryptoKeyVersion: failVersion},
			op: func(p *gcpkmscrypto.Provider) error {
				_, err := p.GenerateECDSAKey("test", elliptic.P256())
				return err
			},
		},
		{
			name:   "generate public",
			client: &fakeKMS{createCryptoKey: created, getCryptoKeyVersion: version, getPublicKey: failPublic},
			op: func(p *gcpkmscrypto.Provider) error {
				_, err := p.GenerateECDSAKey("test", elliptic.P256())
				return err
			},
		},
		{
			name:   "generate malformed",
			client: &fakeKMS{createCryptoKey: created, getCryptoKeyVersion: version, getPublicKey: malformedPublic},
			op: func(p *gcpkmscrypto.Provider) error {
				_, err := p.GenerateECDSAKey("test", elliptic.P256())
				return err
			},
		},
		{
			name:   "get",
			client: &fakeKMS{getCryptoKey: func(*kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error) { return nil, failure }},
			op:     func(p *gcpkmscrypto.Provider) error { _, err := p.GetKey("key/cryptoKeyVersions/1"); return err },
		},
		{
			name:   "get version",
			client: &fakeKMS{getCryptoKey: key, getCryptoKeyVersion: failVersion},
			op:     func(p *gcpkmscrypto.Provider) error { _, err := p.GetKey("key/cryptoKeyVersions/1"); return err },
		},
		{
			name:   "get public",
			client: &fakeKMS{getCryptoKey: key, getCryptoKeyVersion: version, getPublicKey: failPublic},
			op:     func(p *gcpkmscrypto.Provider) error { _, err := p.GetKey("key/cryptoKeyVersions/1"); return err },
		},
		{
			name:   "get malformed",
			client: &fakeKMS{getCryptoKey: key, getCryptoKeyVersion: version, getPublicKey: malformedPublic},
			op:     func(p *gcpkmscrypto.Provider) error { _, err := p.GetKey("key/cryptoKeyVersions/1"); return err },
		},
		{
			name:   "describe",
			client: &fakeKMS{getCryptoKey: func(*kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error) { return nil, failure }},
			op: func(p *gcpkmscrypto.Provider) error {
				_, err := p.KeyInfo(0, "key/cryptoKeyVersions/1", false)
				return err
			},
		},
		{
			name:   "describe version",
			client: &fakeKMS{getCryptoKey: key, getCryptoKeyVersion: failVersion},
			op: func(p *gcpkmscrypto.Provider) error {
				_, err := p.KeyInfo(0, "key/cryptoKeyVersions/1", false)
				return err
			},
		},
		{
			name:   "describe public",
			client: &fakeKMS{getCryptoKey: key, getCryptoKeyVersion: version, getPublicKey: failPublic},
			op: func(p *gcpkmscrypto.Provider) error {
				_, err := p.KeyInfo(0, "key/cryptoKeyVersions/1", true)
				return err
			},
		},
		{
			name: "destroy",
			client: &fakeKMS{destroyCryptoKeyVersion: func(*kmspb.DestroyCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
				return nil, failure
			}},
			op: func(p *gcpkmscrypto.Provider) error { return p.DestroyKeyPairOnSlot(0, "key/cryptoKeyVersions/1") },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.op(newProvider(t, tc.client))
			require.Error(t, err)
			if strings.Contains(tc.name, "malformed") {
				assert.Contains(t, err.Error(), "failed to parse public key")
			} else {
				assert.ErrorIs(t, err, failure)
			}
		})
	}

	t.Run("destroy success", func(t *testing.T) {
		t.Parallel()
		var destroyed string
		client := &fakeKMS{
			destroyCryptoKeyVersion: func(req *kmspb.DestroyCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
				destroyed = req.GetName()
				return &kmspb.CryptoKeyVersion{DestroyTime: timestamppb.Now()}, nil
			},
		}
		provider := newProvider(t, client)
		require.NoError(t, provider.DestroyKeyPairOnSlot(0, "key/cryptoKeyVersions/1"))
		assert.Equal(t, coverageKeyring+"/cryptoKeys/key/cryptoKeyVersions/1", destroyed)
		assert.Equal(t, []string{"DestroyCryptoKeyVersion"}, client.Calls())

		_, err := provider.GenerateRSAKey("test", 1024, 1)
		require.EqualError(t, err, "unsupported key size: 1024")
		_, err = provider.GenerateECDSAKey("test", elliptic.P521())
		require.EqualError(t, err, "unsupported curve")
		_, _, err = provider.IdentifyKey(struct{}{})
		require.EqualError(t, err, "not supported key")
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		t.Parallel()
		client := &fakeKMS{
			getCryptoKey: key,
			getCryptoKeyVersion: func(*kmspb.GetCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
				return enabledVersion("key", kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256), nil
			},
		}
		_, err := newProvider(t, client).GetKey("key/cryptoKeyVersions/1")
		require.EqualError(t, err, "unsupported key algorithm RSA_DECRYPT_OAEP_2048_SHA256: key/cryptoKeyVersions/1")
		assert.Equal(t, 0, client.CallCount("GetPublicKey"))
	})
}

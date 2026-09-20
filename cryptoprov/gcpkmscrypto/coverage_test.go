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
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const coverageKeyring = "projects/test/locations/global/keyRings/coverage"

func coverageProvider(t *testing.T, client gcpkmscrypto.KmsClient) *gcpkmscrypto.Provider {
	t.Helper()
	original := gcpkmscrypto.KmsClientFactory
	gcpkmscrypto.KmsClientFactory = func() (gcpkmscrypto.KmsClient, error) { return client, nil }
	t.Cleanup(func() { gcpkmscrypto.KmsClientFactory = original })
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
		Labels:  map[string]string{"label": "test"},
		Primary: &kmspb.CryptoKeyVersion{State: kmspb.CryptoKeyVersion_ENABLED},
	}
	if req.PageToken == "second" {
		key.Name = coverageKeyring + "/cryptoKeys/no-primary"
		key.Primary = nil
		return &kmspb.ListCryptoKeysResponse{CryptoKeys: []*kmspb.CryptoKey{key}}, nil
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
			assert.NotContains(t, keys[1].Meta, "state")
			assert.Equal(t, "HSM", keys[0].Meta["protection"])
			assert.Equal(t, time.Unix(1000, 0).UTC(), *keys[0].CreationTime)
			first, second := <-service.requests, <-service.requests
			assert.Equal(t, coverageKeyring, first.Parent)
			assert.Empty(t, first.PageToken)
			assert.Equal(t, "second", second.PageToken)
		})
	}
}

func TestKMSFailurePropagation(t *testing.T) {
	failure := errors.New("KMS unavailable")
	key := &kmspb.CryptoKey{
		Name:            coverageKeyring + "/cryptoKeys/key",
		VersionTemplate: &kmspb.CryptoKeyVersionTemplate{},
	}
	for _, operation := range []string{"create", "generate public", "generate malformed", "get", "get public", "get malformed", "describe", "describe public", "destroy"} {
		t.Run(operation, func(t *testing.T) {
			client := &mockedProvider{}
			client.Test(t)
			t.Cleanup(func() { client.AssertExpectations(t) })
			provider := coverageProvider(t, client)
			var err error
			switch operation {
			case "create":
				client.On("CreateCryptoKey", mock.Anything, mock.Anything, mock.Anything).Return((*kmspb.CryptoKey)(nil), failure).Once()
				_, err = provider.GenerateRSAKey("test", 2048, 2)
			case "generate public", "generate malformed":
				client.On("CreateCryptoKey", mock.Anything, mock.Anything, mock.Anything).Return(key, nil).Once()
				if operation == "generate public" {
					client.On("GetPublicKey", mock.Anything, mock.Anything, mock.Anything).Return((*kmspb.PublicKey)(nil), failure).Once()
				} else {
					client.On("GetPublicKey", mock.Anything, mock.Anything, mock.Anything).Return(&kmspb.PublicKey{Pem: "invalid"}, nil).Once()
				}
				_, err = provider.GenerateECDSAKey("test", elliptic.P256())
			case "get", "describe":
				client.On("GetCryptoKey", mock.Anything, mock.Anything, mock.Anything).Return((*kmspb.CryptoKey)(nil), failure).Once()
				if operation == "get" {
					_, err = provider.GetKey("key")
				} else {
					_, err = provider.KeyInfo(0, "key", false)
				}
			case "get public", "get malformed", "describe public":
				client.On("GetCryptoKey", mock.Anything, mock.Anything, mock.Anything).Return(key, nil).Once()
				if operation == "get malformed" {
					client.On("GetPublicKey", mock.Anything, mock.Anything, mock.Anything).Return(&kmspb.PublicKey{Pem: string(pem.EncodeToMemory(&pem.Block{
						Type:  "PUBLIC KEY",
						Bytes: []byte("invalid"),
					}))}, nil).Once()
				} else {
					client.On("GetPublicKey", mock.Anything, mock.Anything, mock.Anything).Return((*kmspb.PublicKey)(nil), failure).Once()
				}
				if operation == "describe public" {
					_, err = provider.KeyInfo(0, "key", true)
				} else {
					_, err = provider.GetKey("key")
				}
			case "destroy":
				client.On("DestroyCryptoKeyVersion", mock.Anything, mock.Anything, mock.Anything).Return((*kmspb.CryptoKeyVersion)(nil), failure).Once()
				err = provider.DestroyKeyPairOnSlot(0, "key")
			}
			require.Error(t, err)
			if strings.Contains(operation, "malformed") {
				assert.Contains(t, err.Error(), "failed to parse public key")
			} else {
				assert.ErrorIs(t, err, failure)
			}
		})
	}
	t.Run("destroy success", func(t *testing.T) {
		client := &mockedProvider{}
		provider := coverageProvider(t, client)
		client.On("DestroyCryptoKeyVersion", mock.Anything, mock.MatchedBy(func(req *kmspb.DestroyCryptoKeyVersionRequest) bool {
			return req.Name == coverageKeyring+"/cryptoKeys/key/cryptoKeyVersions/1"
		}), mock.Anything).Return(&kmspb.CryptoKeyVersion{DestroyTime: timestamppb.Now()}, nil).Once()
		require.NoError(t, provider.DestroyKeyPairOnSlot(0, "key"))
		client.AssertExpectations(t)
		_, err := provider.GenerateRSAKey("test", 1024, 1)
		require.EqualError(t, err, "unsupported key size: 1024")
		_, err = provider.GenerateECDSAKey("test", elliptic.P521())
		require.EqualError(t, err, "unsupported curve")
		_, _, err = provider.IdentifyKey(struct{}{})
		require.EqualError(t, err, "not supported key")
	})
	t.Run("factory failure", func(t *testing.T) {
		original := gcpkmscrypto.KmsClientFactory
		t.Cleanup(func() { gcpkmscrypto.KmsClientFactory = original })
		gcpkmscrypto.KmsClientFactory = func() (gcpkmscrypto.KmsClient, error) { return nil, failure }
		_, err := gcpkmscrypto.KmsLoader(&mockTokenCfg{})
		require.ErrorIs(t, err, failure)
	})
	label, id := gcpkmscrypto.KeyLabelAndID(strings.Repeat("A", 80) + "*")
	assert.Equal(t, strings.Repeat("a", 80), label)
	assert.Len(t, id, 63)
}

package gcpkmscrypto_test

import (
	"context"
	"sync"
	"testing"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/cryptoprov/gcpkmscrypto"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// fakeKMS is a KmsClient whose methods run the matching func field and
// record the call. A method without a func returns errUnexpectedCall, so a
// test sees any RPC it did not expect.
type fakeKMS struct {
	getCryptoKey            func(*kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error)
	getPublicKey            func(*kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error)
	destroyCryptoKeyVersion func(*kmspb.DestroyCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error)
	asymmetricSign          func(*kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error)
	createCryptoKey         func(*kmspb.CreateCryptoKeyRequest) (*kmspb.CryptoKey, error)
	close                   func() error

	mu    sync.Mutex
	calls []string
}

var errUnexpectedCall = errors.New("unexpected KMS call")

var _ gcpkmscrypto.KmsClient = (*fakeKMS)(nil)

func (f *fakeKMS) record(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
}

// Calls returns the names of the methods called so far.
func (f *fakeKMS) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// ListCryptoKeys returns nil: an iterator can not be built outside the kms
// package, so listing is tested against a local gRPC server
// (TestEnumKeysPagination).
func (f *fakeKMS) ListCryptoKeys(context.Context, *kmspb.ListCryptoKeysRequest, ...gax.CallOption) *kms.CryptoKeyIterator {
	f.record("ListCryptoKeys")
	return nil
}

func (f *fakeKMS) GetCryptoKey(_ context.Context, req *kmspb.GetCryptoKeyRequest, _ ...gax.CallOption) (*kmspb.CryptoKey, error) {
	f.record("GetCryptoKey")
	if f.getCryptoKey == nil {
		return nil, errors.WithStack(errUnexpectedCall)
	}
	return f.getCryptoKey(req)
}

func (f *fakeKMS) GetPublicKey(_ context.Context, req *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
	f.record("GetPublicKey")
	if f.getPublicKey == nil {
		return nil, errors.WithStack(errUnexpectedCall)
	}
	return f.getPublicKey(req)
}

func (f *fakeKMS) GetCryptoKeyVersion(context.Context, *kmspb.GetCryptoKeyVersionRequest, ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	f.record("GetCryptoKeyVersion")
	return nil, errors.WithStack(errUnexpectedCall)
}

func (f *fakeKMS) DestroyCryptoKeyVersion(_ context.Context, req *kmspb.DestroyCryptoKeyVersionRequest, _ ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	f.record("DestroyCryptoKeyVersion")
	if f.destroyCryptoKeyVersion == nil {
		return nil, errors.WithStack(errUnexpectedCall)
	}
	return f.destroyCryptoKeyVersion(req)
}

func (f *fakeKMS) AsymmetricSign(_ context.Context, req *kmspb.AsymmetricSignRequest, _ ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
	f.record("AsymmetricSign")
	if f.asymmetricSign == nil {
		return nil, errors.WithStack(errUnexpectedCall)
	}
	return f.asymmetricSign(req)
}

func (f *fakeKMS) CreateCryptoKey(_ context.Context, req *kmspb.CreateCryptoKeyRequest, _ ...gax.CallOption) (*kmspb.CryptoKey, error) {
	f.record("CreateCryptoKey")
	if f.createCryptoKey == nil {
		return nil, errors.WithStack(errUnexpectedCall)
	}
	return f.createCryptoKey(req)
}

func (f *fakeKMS) Close() error {
	f.record("Close")
	if f.close == nil {
		return nil
	}
	return f.close()
}

// signResponse returns a valid response for req with signature sig.
func signResponse(req *kmspb.AsymmetricSignRequest, sig []byte) *kmspb.AsymmetricSignResponse {
	return &kmspb.AsymmetricSignResponse{
		Name:                 req.Name,
		Signature:            sig,
		SignatureCrc32C:      wrapperspb.Int64(int64(gcpkmscrypto.Crc32c(sig))),
		VerifiedDigestCrc32C: true,
	}
}

// newProvider returns a provider for coverageKeyring that uses client.
func newProvider(t *testing.T, client gcpkmscrypto.KmsClient) *gcpkmscrypto.Provider {
	t.Helper()
	return gcpkmscrypto.NewTestProvider(client, coverageKeyring)
}

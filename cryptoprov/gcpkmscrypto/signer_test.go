package gcpkmscrypto_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/effective-security/xpki/cryptoprov/gcpkmscrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const signKeyVersion = coverageKeyring + "/cryptoKeys/key/cryptoKeyVersions/1"

// TestSignRejectsOptionsLocally checks that bad options or digests fail
// before any RPC (XPKI-025).
func TestSignRejectsOptionsLocally(t *testing.T) {
	t.Parallel()

	client := &fakeKMS{}
	signer := gcpkmscrypto.NewSigner("key", "label", nil, newProvider(t, client))
	var nilPSS *rsa.PSSOptions

	for _, tc := range []struct {
		name   string
		digest []byte
		opts   crypto.SignerOpts
		err    string
	}{
		{name: "nil", digest: make([]byte, 32), opts: nil, err: "signer options are required"},
		{name: "typed nil", digest: make([]byte, 32), opts: nilPSS, err: "signer options are required"},
		{name: "no hash", digest: make([]byte, 32), opts: crypto.Hash(0), err: "unsupported hash: unknown hash value 0"},
		{name: "SHA1", digest: make([]byte, 20), opts: crypto.SHA1, err: "unsupported hash: SHA-1"},
		{name: "SHA224", digest: make([]byte, 28), opts: crypto.SHA224, err: "unsupported hash: SHA-224"},
		{name: "SHA256 short", digest: make([]byte, 20), opts: crypto.SHA256, err: "digest length 20 does not match SHA-256 (32 bytes)"},
		{name: "SHA384 as SHA256", digest: make([]byte, 32), opts: crypto.SHA384, err: "digest length 32 does not match SHA-384 (48 bytes)"},
		{name: "SHA512 empty", digest: nil, opts: crypto.SHA512, err: "digest length 0 does not match SHA-512 (64 bytes)"},
		{name: "PSS SHA1", digest: make([]byte, 20), opts: &rsa.PSSOptions{Hash: crypto.SHA1}, err: "unsupported hash: SHA-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sig, err := signer.Sign(rand.Reader, tc.digest, tc.opts)
			require.EqualError(t, err, tc.err)
			assert.Nil(t, sig)
		})
	}
	assert.Empty(t, client.Calls(), "no RPC for locally rejected input")
}

func TestSignRequest(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		opts   crypto.SignerOpts
		hash   crypto.Hash
		digest func(*kmspb.Digest) []byte
	}{
		{name: "SHA256", opts: crypto.SHA256, hash: crypto.SHA256, digest: (*kmspb.Digest).GetSha256},
		{name: "SHA384", opts: crypto.SHA384, hash: crypto.SHA384, digest: (*kmspb.Digest).GetSha384},
		{name: "SHA512", opts: crypto.SHA512, hash: crypto.SHA512, digest: (*kmspb.Digest).GetSha512},
		{name: "PSS SHA256", opts: &rsa.PSSOptions{Hash: crypto.SHA256}, hash: crypto.SHA256, digest: (*kmspb.Digest).GetSha256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := tc.hash.New()
			h.Write([]byte("to be signed"))
			digest := h.Sum(nil)

			var got *kmspb.AsymmetricSignRequest
			client := &fakeKMS{
				asymmetricSign: func(req *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
					got = req
					return signResponse(req, []byte("signature")), nil
				},
			}
			signer := gcpkmscrypto.NewSigner("key", "label", nil, newProvider(t, client))
			sig, err := signer.Sign(rand.Reader, digest, tc.opts)
			require.NoError(t, err)
			assert.Equal(t, []byte("signature"), sig)

			require.NotNil(t, got)
			assert.Equal(t, signKeyVersion, got.Name)
			assert.Equal(t, digest, tc.digest(got.Digest))
			assert.Equal(t, int64(gcpkmscrypto.Crc32c(digest)), got.DigestCrc32C.GetValue())
		})
	}
}

// TestSignResponseIntegrity checks that a response is accepted only with a
// verified digest and a matching signature checksum (XPKI-023).
func TestSignResponseIntegrity(t *testing.T) {
	t.Parallel()

	digest := make([]byte, 32)
	for _, tc := range []struct {
		name string
		resp func(*kmspb.AsymmetricSignRequest) *kmspb.AsymmetricSignResponse
		err  string
	}{
		{
			name: "nil response",
			resp: func(*kmspb.AsymmetricSignRequest) *kmspb.AsymmetricSignResponse { return nil },
			err:  "unable to sign: empty response",
		},
		{
			name: "digest not verified",
			resp: func(req *kmspb.AsymmetricSignRequest) *kmspb.AsymmetricSignResponse {
				resp := signResponse(req, []byte("signature"))
				resp.VerifiedDigestCrc32C = false
				return resp
			},
			err: "request corrupted in-transit",
		},
		{
			name: "missing signature checksum",
			resp: func(req *kmspb.AsymmetricSignRequest) *kmspb.AsymmetricSignResponse {
				resp := signResponse(req, []byte("signature"))
				resp.SignatureCrc32C = nil
				return resp
			},
			err: "response has no signature checksum",
		},
		{
			name: "signature checksum mismatch",
			resp: func(req *kmspb.AsymmetricSignRequest) *kmspb.AsymmetricSignResponse {
				resp := signResponse(req, []byte("signature"))
				resp.SignatureCrc32C = wrapperspb.Int64(resp.SignatureCrc32C.Value + 1)
				return resp
			},
			err: "response corrupted in-transit",
		},
		{
			name: "signature changed",
			resp: func(req *kmspb.AsymmetricSignRequest) *kmspb.AsymmetricSignResponse {
				resp := signResponse(req, []byte("signature"))
				resp.Signature = []byte("tampered")
				return resp
			},
			err: "response corrupted in-transit",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client := &fakeKMS{
				asymmetricSign: func(req *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
					return tc.resp(req), nil
				},
			}
			signer := gcpkmscrypto.NewSigner("key", "label", nil, newProvider(t, client))
			sig, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
			require.Error(t, err)
			assert.True(t, strings.HasPrefix(err.Error(), tc.err), err.Error())
			assert.Nil(t, sig)
		})
	}
}

func TestSignNilProvider(t *testing.T) {
	t.Parallel()
	signer := gcpkmscrypto.NewSigner("key", "label", nil, nil)
	_, err := signer.Sign(rand.Reader, make([]byte, 32), crypto.SHA256)
	require.EqualError(t, err, "signer has no provider")
}

package gcpkmscrypto_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/effective-security/xpki/cryptoprov/gcpkmscrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	signKeyID      = "key/cryptoKeyVersions/1"
	signKeyVersion = coverageKeyring + "/cryptoKeys/" + signKeyID
)

// testSigner returns a signer for signKeyID with algorithm over client.
func testSigner(t *testing.T, client *fakeKMS, algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) crypto.Signer {
	t.Helper()
	return gcpkmscrypto.NewSigner(signKeyID, "label", nil, algorithm, newProvider(t, client))
}

// TestSignRejectsOptionsLocally checks that options that do not match the
// key algorithm, bad digests or an unsupported algorithm fail before any
// RPC (XPKI-019, XPKI-025).
func TestSignRejectsOptionsLocally(t *testing.T) {
	t.Parallel()

	client := &fakeKMS{}
	var nilPSS *rsa.PSSOptions
	pss := func(saltLength int) *rsa.PSSOptions {
		return &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: saltLength}
	}

	for _, tc := range []struct {
		name      string
		algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
		digest    []byte
		opts      crypto.SignerOpts
		err       string
	}{
		{name: "nil", algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, digest: make([]byte, 32), opts: nil, err: "signer options are required"},
		{name: "typed nil", algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, digest: make([]byte, 32), opts: nilPSS, err: "signer options are required"},
		{name: "no hash", algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, digest: make([]byte, 32), opts: crypto.Hash(0), err: "hash unknown hash value 0 does not match key algorithm EC_SIGN_P256_SHA256"},
		{name: "SHA1", algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, digest: make([]byte, 20), opts: crypto.SHA1, err: "hash SHA-1 does not match key algorithm EC_SIGN_P256_SHA256"},
		{name: "SHA384 on P256", algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, digest: make([]byte, 48), opts: crypto.SHA384, err: "hash SHA-384 does not match key algorithm EC_SIGN_P256_SHA256"},
		{name: "SHA256 on P384", algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384, digest: make([]byte, 32), opts: crypto.SHA256, err: "hash SHA-256 does not match key algorithm EC_SIGN_P384_SHA384"},
		{name: "SHA256 on RSA 4096 SHA512", algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512, digest: make([]byte, 32), opts: crypto.SHA256, err: "hash SHA-256 does not match key algorithm RSA_SIGN_PKCS1_4096_SHA512"},
		{name: "SHA384 on RSA 3072", algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256, digest: make([]byte, 48), opts: crypto.SHA384, err: "hash SHA-384 does not match key algorithm RSA_SIGN_PKCS1_3072_SHA256"},
		{name: "SHA256 short", algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, digest: make([]byte, 20), opts: crypto.SHA256, err: "digest length 20 does not match SHA-256 (32 bytes)"},
		{name: "SHA512 empty", algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512, digest: nil, opts: crypto.SHA512, err: "digest length 0 does not match SHA-512 (64 bytes)"},
		{name: "PSS on EC", algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, digest: make([]byte, 32), opts: pss(rsa.PSSSaltLengthEqualsHash), err: "key algorithm EC_SIGN_P256_SHA256 does not use PSS padding"},
		{name: "PSS on PKCS1", algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256, digest: make([]byte, 32), opts: pss(rsa.PSSSaltLengthEqualsHash), err: "key algorithm RSA_SIGN_PKCS1_2048_SHA256 does not use PSS padding"},
		{name: "PKCS1 on PSS", algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256, digest: make([]byte, 32), opts: crypto.SHA256, err: "key algorithm RSA_SIGN_PSS_2048_SHA256 requires *rsa.PSSOptions"},
		{name: "PSS salt 20", algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256, digest: make([]byte, 32), opts: pss(20), err: "PSS salt length 20 is not supported: KMS uses the digest length 32"},
		{name: "PSS salt auto", algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256, digest: make([]byte, 32), opts: pss(rsa.PSSSaltLengthAuto), err: "PSS salt length 0 is not supported: KMS uses the digest length 32"},
		{name: "PSS SHA1", algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256, digest: make([]byte, 20), opts: &rsa.PSSOptions{Hash: crypto.SHA1}, err: "hash SHA-1 does not match key algorithm RSA_SIGN_PSS_2048_SHA256"},
		{name: "unspecified algorithm", algorithm: kmspb.CryptoKeyVersion_CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED, digest: make([]byte, 32), opts: crypto.SHA256, err: "unsupported key algorithm: CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED"},
		{name: "raw PKCS1", algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_2048, digest: make([]byte, 32), opts: crypto.SHA256, err: "unsupported key algorithm: RSA_SIGN_RAW_PKCS1_2048"},
		{name: "Ed25519", algorithm: kmspb.CryptoKeyVersion_EC_SIGN_ED25519, digest: make([]byte, 32), opts: crypto.SHA256, err: "unsupported key algorithm: EC_SIGN_ED25519"},
		{name: "secp256k1", algorithm: kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256, digest: make([]byte, 32), opts: crypto.SHA256, err: "unsupported key algorithm: EC_SIGN_SECP256K1_SHA256"},
		{name: "decrypt key", algorithm: kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256, digest: make([]byte, 32), opts: crypto.SHA256, err: "unsupported key algorithm: RSA_DECRYPT_OAEP_2048_SHA256"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sig, err := testSigner(t, client, tc.algorithm).Sign(rand.Reader, tc.digest, tc.opts)
			require.EqualError(t, err, tc.err)
			assert.Nil(t, sig)
		})
	}

	t.Run("bare key ID", func(t *testing.T) {
		signer := gcpkmscrypto.NewSigner("key", "label", nil, kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, newProvider(t, client))
		_, err := signer.Sign(rand.Reader, make([]byte, 32), crypto.SHA256)
		require.EqualError(t, err, "signer key ID names no version: key")
	})
	assert.Empty(t, client.Calls(), "no RPC for locally rejected input")
}

func TestSignRequest(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
		opts      crypto.SignerOpts
		hash      crypto.Hash
		digest    func(*kmspb.Digest) []byte
	}{
		{name: "P256", algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, opts: crypto.SHA256, hash: crypto.SHA256, digest: (*kmspb.Digest).GetSha256},
		{name: "P384", algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384, opts: crypto.SHA384, hash: crypto.SHA384, digest: (*kmspb.Digest).GetSha384},
		{name: "PKCS1 2048", algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256, opts: crypto.SHA256, hash: crypto.SHA256, digest: (*kmspb.Digest).GetSha256},
		{name: "PKCS1 4096 SHA512", algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512, opts: crypto.SHA512, hash: crypto.SHA512, digest: (*kmspb.Digest).GetSha512},
		{name: "PSS salt equals hash", algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256, opts: &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: rsa.PSSSaltLengthEqualsHash}, hash: crypto.SHA256, digest: (*kmspb.Digest).GetSha256},
		{name: "PSS 4096 salt 32", algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256, opts: &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: 32}, hash: crypto.SHA256, digest: (*kmspb.Digest).GetSha256},
		{name: "PSS salt 64", algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512, opts: &rsa.PSSOptions{Hash: crypto.SHA512, SaltLength: 64}, hash: crypto.SHA512, digest: (*kmspb.Digest).GetSha512},
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
			sig, err := testSigner(t, client, tc.algorithm).Sign(rand.Reader, digest, tc.opts)
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
			sig, err := testSigner(t, client, kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256).Sign(rand.Reader, digest, crypto.SHA256)
			require.Error(t, err)
			assert.True(t, strings.HasPrefix(err.Error(), tc.err), err.Error())
			assert.Nil(t, sig)
		})
	}
}

func TestSignNilProvider(t *testing.T) {
	t.Parallel()
	signer := gcpkmscrypto.NewSigner(signKeyID, "label", nil, kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, nil)
	_, err := signer.Sign(rand.Reader, make([]byte, 32), crypto.SHA256)
	require.EqualError(t, err, "signer has no provider")
}

// publicPEM returns the PKIX PEM of pub, as KMS returns it.
func publicPEM(t *testing.T, pub crypto.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// TestSignVerifiesLocally signs with every supported algorithm through the
// real SDK client and verifies the signature with the key's public key
// (XPKI-019).
func TestSignVerifiesLocally(t *testing.T) {
	t.Parallel()

	s := newFakeKMSServer()
	provider := grpcProvider(t, s)

	for _, tc := range []struct {
		name      string
		algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
		hash      crypto.Hash
		pss       bool
		wrong     crypto.SignerOpts
	}{
		{name: "p256", algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, hash: crypto.SHA256, wrong: crypto.SHA384},
		{name: "p384", algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384, hash: crypto.SHA384, wrong: crypto.SHA256},
		{name: "pkcs1-2048", algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256, hash: crypto.SHA256, wrong: &rsa.PSSOptions{Hash: crypto.SHA256}},
		{name: "pkcs1-3072", algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256, hash: crypto.SHA256, wrong: crypto.SHA384},
		{name: "pkcs1-4096", algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512, hash: crypto.SHA512, wrong: crypto.SHA256},
		{name: "pss-2048", algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256, hash: crypto.SHA256, pss: true, wrong: crypto.SHA256},
		{name: "pss-4096", algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512, hash: crypto.SHA512, pss: true, wrong: &rsa.PSSOptions{Hash: crypto.SHA256}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s.AddKey(t, tc.name, tc.algorithm, tc.name)
			pk, err := provider.GetKey(tc.name)
			require.NoError(t, err)
			signer := pk.(crypto.Signer)
			assert.Equal(t, tc.algorithm, pk.(*gcpkmscrypto.Signer).Algorithm())

			h := tc.hash.New()
			h.Write([]byte("message for " + tc.name))
			digest := h.Sum(nil)
			var opts crypto.SignerOpts = tc.hash
			if tc.pss {
				opts = &rsa.PSSOptions{Hash: tc.hash, SaltLength: rsa.PSSSaltLengthEqualsHash}
			}
			sig, err := signer.Sign(rand.Reader, digest, opts)
			require.NoError(t, err)

			switch pub := signer.Public().(type) {
			case *ecdsa.PublicKey:
				assert.True(t, ecdsa.VerifyASN1(pub, digest, sig))
			case *rsa.PublicKey:
				if tc.pss {
					assert.NoError(t, rsa.VerifyPSS(pub, tc.hash, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}))
					assert.Error(t, rsa.VerifyPKCS1v15(pub, tc.hash, digest, sig))
				} else {
					assert.NoError(t, rsa.VerifyPKCS1v15(pub, tc.hash, digest, sig))
				}
			default:
				t.Fatalf("unexpected public key %T", pub)
			}

			// options that do not fit the algorithm fail without an RPC
			signs := s.CallCount("AsymmetricSign")
			wh := tc.wrong.HashFunc().New()
			wh.Write(digest)
			_, err = signer.Sign(rand.Reader, wh.Sum(nil), tc.wrong)
			require.Error(t, err)
			assert.Equal(t, signs, s.CallCount("AsymmetricSign"))
		})
	}
}

package awskmscrypto_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/cryptoprov/awskmscrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signerFor creates a signing key of spec in client and returns its signer.
func signerFor(t *testing.T, client *fakeKMS, spec types.KeySpec) (*awskmscrypto.Signer, string) {
	t.Helper()
	keyID := client.mustAddKey(t, "label", spec, types.KeyUsageTypeSignVerify)
	priv, err := newProvider(t, client).GetKey(keyID)
	require.NoError(t, err)
	signer, ok := priv.(*awskmscrypto.Signer)
	require.True(t, ok)
	return signer, keyID
}

// TestSignRejectsOptionsLocally checks that nil options, an unsupported
// hash, a digest of the wrong length, PSS options on an ECDSA key, an
// unsupported salt length and an algorithm the key does not support fail
// before any RPC (XPKI-025).
func TestSignRejectsOptionsLocally(t *testing.T) {
	t.Parallel()

	client := newFakeKMS()
	rsaSigner, rsaID := signerFor(t, client, types.KeySpecRsa2048)
	p256Signer, p256ID := signerFor(t, client, types.KeySpecEccNistP256)
	signCallsBefore := client.CallCount("Sign")

	var nilPSS *rsa.PSSOptions
	pss := func(hash crypto.Hash, saltLength int) *rsa.PSSOptions {
		return &rsa.PSSOptions{
			Hash:       hash,
			SaltLength: saltLength,
		}
	}
	for _, tc := range []struct {
		name   string
		signer crypto.Signer
		digest []byte
		opts   crypto.SignerOpts
		err    string
	}{
		{
			name:   "nil",
			signer: rsaSigner,
			digest: make([]byte, 32),
			opts:   nil,
			err:    "signer options are required",
		},
		{
			name:   "typed nil",
			signer: rsaSigner,
			digest: make([]byte, 32),
			opts:   nilPSS,
			err:    "signer options are required",
		},
		{
			name:   "no hash",
			signer: rsaSigner,
			digest: make([]byte, 32),
			opts:   crypto.Hash(0),
			err:    "unsupported hash: unknown hash value 0",
		},
		{
			name:   "SHA1",
			signer: rsaSigner,
			digest: make([]byte, 20),
			opts:   crypto.SHA1,
			err:    "unsupported hash: SHA-1",
		},
		{
			name:   "PSS SHA1",
			signer: rsaSigner,
			digest: make([]byte, 20),
			opts:   pss(crypto.SHA1, rsa.PSSSaltLengthEqualsHash),
			err:    "unsupported hash: SHA-1",
		},
		{
			name:   "SHA256 short",
			signer: rsaSigner,
			digest: make([]byte, 20),
			opts:   crypto.SHA256,
			err:    "digest length 20 does not match SHA-256 (32 bytes)",
		},
		{
			name:   "SHA512 empty",
			signer: rsaSigner,
			digest: nil,
			opts:   crypto.SHA512,
			err:    "digest length 0 does not match SHA-512 (64 bytes)",
		},
		{
			name:   "PSS digest long",
			signer: rsaSigner,
			digest: make([]byte, 48),
			opts:   pss(crypto.SHA256, rsa.PSSSaltLengthEqualsHash),
			err:    "digest length 48 does not match SHA-256 (32 bytes)",
		},
		{
			name:   "PSS salt 20",
			signer: rsaSigner,
			digest: make([]byte, 32),
			opts:   pss(crypto.SHA256, 20),
			err:    "PSS salt length 20 is not supported: KMS uses the digest length 32",
		},
		{
			name:   "PSS salt auto",
			signer: rsaSigner,
			digest: make([]byte, 32),
			opts:   pss(crypto.SHA256, rsa.PSSSaltLengthAuto),
			err:    "PSS salt length 0 is not supported: KMS uses the digest length 32",
		},
		{
			name:   "PSS on ECDSA",
			signer: p256Signer,
			digest: make([]byte, 32),
			opts:   pss(crypto.SHA256, rsa.PSSSaltLengthEqualsHash),
			err:    "PSS options are not valid for an ECDSA key",
		},
		{
			name:   "SHA384 on P256",
			signer: p256Signer,
			digest: make([]byte, 48),
			opts:   crypto.SHA384,
			err:    "key " + p256ID + " does not support ECDSA_SHA_384 (supported: [ECDSA_SHA_256])",
		},
		{
			name:   "SHA512 on P256",
			signer: p256Signer,
			digest: make([]byte, 64),
			opts:   crypto.SHA512,
			err:    "key " + p256ID + " does not support ECDSA_SHA_512 (supported: [ECDSA_SHA_256])",
		},
		{
			name:   "SHA1 on P256",
			signer: p256Signer,
			digest: make([]byte, 20),
			opts:   crypto.SHA1,
			err:    "unsupported hash: SHA-1",
		},
		{
			name:   "MD5",
			signer: rsaSigner,
			digest: make([]byte, 16),
			opts:   crypto.MD5,
			err:    "unsupported hash: MD5",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sig, err := tc.signer.Sign(rand.Reader, tc.digest, tc.opts)
			require.EqualError(t, err, tc.err)
			assert.Nil(t, sig)
		})
	}

	t.Run("no algorithms", func(t *testing.T) {
		signer := awskmscrypto.NewSigner(rsaID, "label", nil, rsaSigner.Public(), client)
		_, err := signer.Sign(rand.Reader, make([]byte, 32), crypto.SHA256)
		require.EqualError(t, err, "key "+rsaID+" does not support RSASSA_PKCS1_V1_5_SHA_256 (supported: [])")
	})
	t.Run("PKCS1 only key", func(t *testing.T) {
		pkcs1 := []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecRsassaPkcs1V15Sha256}
		signer := awskmscrypto.NewSigner(rsaID, "label", pkcs1, rsaSigner.Public(), client)
		_, err := signer.Sign(rand.Reader, make([]byte, 32), pss(crypto.SHA256, rsa.PSSSaltLengthEqualsHash))
		require.EqualError(t, err, "key "+rsaID+" does not support RSASSA_PSS_SHA_256 (supported: [RSASSA_PKCS1_V1_5_SHA_256])")
	})
	t.Run("unsupported key type", func(t *testing.T) {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		ed25519Algorithms := []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEd25519Sha512}
		signer := awskmscrypto.NewSigner(rsaID, "label", ed25519Algorithms, pub, client)
		_, err = signer.Sign(rand.Reader, make([]byte, 32), crypto.SHA256)
		require.EqualError(t, err, "unsupported public key type: ed25519.PublicKey")
	})
	t.Run("nil key", func(t *testing.T) {
		signer := awskmscrypto.NewSigner(rsaID, "label", rsaSigningAlgorithms, nil, client)
		_, err := signer.Sign(rand.Reader, make([]byte, 32), crypto.SHA256)
		require.EqualError(t, err, "unsupported public key type: <nil>")
	})

	assert.Equal(t, signCallsBefore, client.CallCount("Sign"), "no RPC for locally rejected input")
}

// TestSignAlgorithms signs with every supported algorithm and verifies the
// signature with the public key: PKCS#1 v1.5 and PSS (with the hash-length
// salt KMS uses) for RSA keys, and the curve's hash for ECDSA keys.
func TestSignAlgorithms(t *testing.T) {
	t.Parallel()

	pss := func(hash crypto.Hash, saltLength int) *rsa.PSSOptions {
		return &rsa.PSSOptions{
			Hash:       hash,
			SaltLength: saltLength,
		}
	}
	for _, tc := range []struct {
		name      string
		spec      types.KeySpec
		hash      crypto.Hash
		opts      crypto.SignerOpts
		algorithm types.SigningAlgorithmSpec
	}{
		{
			name:      "RSA 2048 PKCS1 SHA256",
			spec:      types.KeySpecRsa2048,
			hash:      crypto.SHA256,
			opts:      crypto.SHA256,
			algorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
		},
		{
			name:      "RSA 2048 PKCS1 SHA384",
			spec:      types.KeySpecRsa2048,
			hash:      crypto.SHA384,
			opts:      crypto.SHA384,
			algorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha384,
		},
		{
			name:      "RSA 2048 PKCS1 SHA512",
			spec:      types.KeySpecRsa2048,
			hash:      crypto.SHA512,
			opts:      crypto.SHA512,
			algorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
		},
		{
			name:      "RSA 2048 PSS SHA256 salt equals hash",
			spec:      types.KeySpecRsa2048,
			hash:      crypto.SHA256,
			opts:      pss(crypto.SHA256, rsa.PSSSaltLengthEqualsHash),
			algorithm: types.SigningAlgorithmSpecRsassaPssSha256,
		},
		{
			name:      "RSA 2048 PSS SHA256 salt 32",
			spec:      types.KeySpecRsa2048,
			hash:      crypto.SHA256,
			opts:      pss(crypto.SHA256, 32),
			algorithm: types.SigningAlgorithmSpecRsassaPssSha256,
		},
		{
			name:      "RSA 2048 PSS SHA384",
			spec:      types.KeySpecRsa2048,
			hash:      crypto.SHA384,
			opts:      pss(crypto.SHA384, rsa.PSSSaltLengthEqualsHash),
			algorithm: types.SigningAlgorithmSpecRsassaPssSha384,
		},
		{
			name:      "RSA 3072 PSS SHA512 salt 64",
			spec:      types.KeySpecRsa3072,
			hash:      crypto.SHA512,
			opts:      pss(crypto.SHA512, 64),
			algorithm: types.SigningAlgorithmSpecRsassaPssSha512,
		},
		{
			name:      "P256 SHA256",
			spec:      types.KeySpecEccNistP256,
			hash:      crypto.SHA256,
			opts:      crypto.SHA256,
			algorithm: types.SigningAlgorithmSpecEcdsaSha256,
		},
		{
			name:      "P384 SHA384",
			spec:      types.KeySpecEccNistP384,
			hash:      crypto.SHA384,
			opts:      crypto.SHA384,
			algorithm: types.SigningAlgorithmSpecEcdsaSha384,
		},
		{
			name:      "P521 SHA512",
			spec:      types.KeySpecEccNistP521,
			hash:      crypto.SHA512,
			opts:      crypto.SHA512,
			algorithm: types.SigningAlgorithmSpecEcdsaSha512,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client := newFakeKMS()
			signer, keyID := signerFor(t, client, tc.spec)
			digest := sum(tc.hash, "to be signed")

			sig, err := signer.Sign(rand.Reader, digest, tc.opts)
			require.NoError(t, err)

			requests := client.SignRequests()
			require.Len(t, requests, 1)
			assert.Equal(t, keyID, aws.ToString(requests[0].KeyId))
			assert.Equal(t, tc.algorithm, requests[0].SigningAlgorithm)
			assert.Equal(t, types.MessageTypeDigest, requests[0].MessageType)
			assert.Equal(t, digest, requests[0].Message)

			switch pub := signer.Public().(type) {
			case *rsa.PublicKey:
				if pssOpts, ok := tc.opts.(*rsa.PSSOptions); ok {
					require.NoError(t, rsa.VerifyPSS(pub, tc.hash, digest, sig, &rsa.PSSOptions{SaltLength: pssOpts.SaltLength}))
				} else {
					require.NoError(t, rsa.VerifyPKCS1v15(pub, tc.hash, digest, sig))
				}
			case *ecdsa.PublicKey:
				assert.True(t, ecdsa.VerifyASN1(pub, digest, sig))
			default:
				t.Fatalf("unexpected public key %T", pub)
			}
		})
	}
}

// TestSignErrors checks that a KMS failure keeps its identity through the
// wrapping and that an empty response is an error.
func TestSignErrors(t *testing.T) {
	t.Parallel()

	client := newFakeKMS()
	signer, keyID := signerFor(t, client, types.KeySpecEccNistP256)
	digest := sum(crypto.SHA256, "to be signed")

	t.Run("disabled key", func(t *testing.T) {
		client.setState(keyID, types.KeyStateDisabled)
		defer client.setState(keyID, types.KeyStateEnabled)

		_, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
		require.ErrorContains(t, err, "unable to sign")
		var disabled *types.DisabledException
		require.ErrorAs(t, err, &disabled)
	})
	t.Run("throttled", func(t *testing.T) {
		client.sign = func(*kms.SignInput) (*kms.SignOutput, error) {
			return nil, throttlingError()
		}
		defer func() { client.sign = nil }()

		_, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
		require.EqualError(t, err, "unable to sign: api error ThrottlingException: Rate exceeded")
		var apiErr smithy.APIError
		require.ErrorAs(t, err, &apiErr)
		assert.Equal(t, "ThrottlingException", apiErr.ErrorCode())
	})
	t.Run("empty response", func(t *testing.T) {
		for _, resp := range []*kms.SignOutput{nil, {}} {
			client.sign = func(*kms.SignInput) (*kms.SignOutput, error) {
				return resp, nil
			}
			_, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
			require.EqualError(t, err, "unable to sign: empty response")
		}
		client.sign = nil
	})
	t.Run("wrapped cause", func(t *testing.T) {
		cause := errors.New("network down")
		client.sign = func(*kms.SignInput) (*kms.SignOutput, error) {
			return nil, cause
		}
		defer func() { client.sign = nil }()

		_, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
		require.ErrorIs(t, err, cause)
	})
}

func TestSignerAccessors(t *testing.T) {
	t.Parallel()

	client := newFakeKMS()
	signer, keyID := signerFor(t, client, types.KeySpecRsa2048)

	assert.Equal(t, keyID, signer.KeyID())
	assert.Equal(t, "label", signer.Label())
	assert.Equal(t, "id="+keyID+", label=label", signer.String())
	assert.IsType(t, &rsa.PublicKey{}, signer.Public())

	algorithms := signer.SigningAlgorithms()
	assert.Equal(t, rsaSigningAlgorithms, algorithms)
	algorithms[0] = types.SigningAlgorithmSpecSm2dsa
	assert.Equal(t, rsaSigningAlgorithms, signer.SigningAlgorithms(), "the returned list is a copy")

	given := []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256}
	fromList := awskmscrypto.NewSigner(keyID, "label", given, signer.Public(), client).(*awskmscrypto.Signer)
	given[0] = types.SigningAlgorithmSpecSm2dsa
	expected := []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256}
	assert.Equal(t, expected, fromList.SigningAlgorithms(), "the list is copied by NewSigner")
}

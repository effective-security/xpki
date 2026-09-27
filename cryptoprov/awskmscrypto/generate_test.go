package awskmscrypto_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"strconv"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/cryptoprov/awskmscrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerateRSAKeyPurpose checks that an encryption key is rejected
// before any RPC and that every other purpose is a signing key (XPKI-031).
func TestGenerateRSAKeyPurpose(t *testing.T) {
	t.Parallel()

	client := newFakeKMS()
	provider := newProvider(t, client)

	_, err := provider.GenerateRSAKey("encrypt", 2048, 2)
	require.EqualError(t, err, "unsupported key purpose: 2, only signing keys are supported")
	assert.Equal(t, 0, client.CallCount("CreateKey"), "no key is created for an unsupported purpose")

	for _, purpose := range []int{0, 1, 3} {
		priv, err := provider.GenerateRSAKey("sign", 2048, purpose)
		require.NoError(t, err, "purpose %d", purpose)
		keyID, _, err := provider.IdentifyKey(priv)
		require.NoError(t, err)

		ki, err := provider.KeyInfo(0, keyID, false)
		require.NoError(t, err)
		assert.Equal(t, string(types.KeyUsageTypeSignVerify), ki.Meta["usage"], "purpose %d", purpose)
	}
	assert.Equal(t, 3, client.CallCount("CreateKey"))
}

// TestGenerateKeyInvalidInput checks that an unsupported key size or curve
// is rejected before any RPC.
func TestGenerateKeyInvalidInput(t *testing.T) {
	t.Parallel()

	client := newFakeKMS()
	provider := newProvider(t, client)

	for _, bits := range []int{0, 1024, 2047, 8192} {
		_, err := provider.GenerateRSAKey("rsa", bits, 1)
		require.EqualError(t, err, "unsupported RSA key size: "+strconv.Itoa(bits))
	}
	_, err := provider.GenerateECDSAKey("ec", elliptic.P224())
	require.EqualError(t, err, "unsupported curve")
	assert.Equal(t, 0, client.CallCount("CreateKey"))
}

// TestGenerateKeys checks the created keys: spec, usage, description and
// alias, and the signer's public key and algorithms.
func TestGenerateKeys(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		generate   func(*awskmscrypto.Provider, string) (crypto.PrivateKey, error)
		spec       types.KeySpec
		algorithms []types.SigningAlgorithmSpec
		public     any
	}{
		{
			name: "RSA 2048",
			generate: func(p *awskmscrypto.Provider, label string) (crypto.PrivateKey, error) {
				return p.GenerateRSAKey(label, 2048, 1)
			},
			spec:       types.KeySpecRsa2048,
			algorithms: rsaSigningAlgorithms,
			public:     &rsa.PublicKey{},
		},
		{
			name: "RSA 3072",
			generate: func(p *awskmscrypto.Provider, label string) (crypto.PrivateKey, error) {
				return p.GenerateRSAKey(label, 3072, 1)
			},
			spec:       types.KeySpecRsa3072,
			algorithms: rsaSigningAlgorithms,
			public:     &rsa.PublicKey{},
		},
		{
			name: "RSA 4096",
			generate: func(p *awskmscrypto.Provider, label string) (crypto.PrivateKey, error) {
				return p.GenerateRSAKey(label, 4096, 1)
			},
			spec:       types.KeySpecRsa4096,
			algorithms: rsaSigningAlgorithms,
			public:     &rsa.PublicKey{},
		},
		{
			name: "P256",
			generate: func(p *awskmscrypto.Provider, label string) (crypto.PrivateKey, error) {
				return p.GenerateECDSAKey(label, elliptic.P256())
			},
			spec:       types.KeySpecEccNistP256,
			algorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256},
			public:     &ecdsa.PublicKey{},
		},
		{
			name: "P384",
			generate: func(p *awskmscrypto.Provider, label string) (crypto.PrivateKey, error) {
				return p.GenerateECDSAKey(label, elliptic.P384())
			},
			spec:       types.KeySpecEccNistP384,
			algorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha384},
			public:     &ecdsa.PublicKey{},
		},
		{
			name: "P521",
			generate: func(p *awskmscrypto.Provider, label string) (crypto.PrivateKey, error) {
				return p.GenerateECDSAKey(label, elliptic.P521())
			},
			spec:       types.KeySpecEccNistP521,
			algorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha512},
			public:     &ecdsa.PublicKey{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client := newFakeKMS()
			provider := newProvider(t, client)

			priv, err := tc.generate(provider, "my key")
			require.NoError(t, err)
			signer, ok := priv.(*awskmscrypto.Signer)
			require.True(t, ok)
			assert.Equal(t, "my key", signer.Label())
			assert.Equal(t, tc.algorithms, signer.SigningAlgorithms())
			assert.IsType(t, tc.public, signer.Public())

			keyID, label, err := provider.IdentifyKey(priv)
			require.NoError(t, err)
			assert.Equal(t, signer.KeyID(), keyID)
			assert.Equal(t, "my key", label)

			ki, err := provider.KeyInfo(0, keyID, true)
			require.NoError(t, err)
			assert.Equal(t, "my key", ki.Label)
			assert.Equal(t, "my key", ki.Meta["description"])
			assert.Equal(t, "SIGN_VERIFY", ki.Meta["usage"])
			assert.Equal(t, "Enabled", ki.Meta["state"])
			assert.Contains(t, ki.PublicKey, "-----BEGIN PUBLIC KEY-----")

			// the alias of the label resolves to the key
			byAlias, err := provider.GetKey("alias/my_key")
			require.NoError(t, err)
			aliasID, _, err := provider.IdentifyKey(byAlias)
			require.NoError(t, err)
			assert.Equal(t, "alias/my_key", aliasID, "GetKey keeps the id it was given")
			assert.Equal(t, signer.Public(), byAlias.(crypto.Signer).Public())

			assert.Equal(t, 1, client.CallCount("CreateKey"))
			assert.Equal(t, 1, client.CallCount("CreateAlias"))
		})
	}
}

// TestGenerateKeyAlias checks that an empty label gets no alias and that an
// alias failure does not fail the generation: the key exists.
func TestGenerateKeyAlias(t *testing.T) {
	t.Parallel()

	t.Run("empty label", func(t *testing.T) {
		t.Parallel()
		client := newFakeKMS()
		priv, err := newProvider(t, client).GenerateECDSAKey("", elliptic.P256())
		require.NoError(t, err)
		assert.Equal(t, "", priv.(*awskmscrypto.Signer).Label())
		assert.Equal(t, 0, client.CallCount("CreateAlias"))
	})
	t.Run("reserved label", func(t *testing.T) {
		t.Parallel()
		client := newFakeKMS()
		priv, err := newProvider(t, client).GenerateECDSAKey("aws/", elliptic.P256())
		require.NoError(t, err, "the key is created without an alias")
		assert.Equal(t, "aws/", priv.(*awskmscrypto.Signer).Label())
		assert.Equal(t, 0, client.CallCount("CreateAlias"), "an empty alias is not requested")
	})
	t.Run("alias fails", func(t *testing.T) {
		t.Parallel()
		client := newFakeKMS()
		client.createAlias = func(*kms.CreateAliasInput) (*kms.CreateAliasOutput, error) {
			return nil, throttlingError()
		}
		provider := newProvider(t, client)
		priv, err := provider.GenerateECDSAKey("throttled", elliptic.P256())
		require.NoError(t, err, "the key exists and is usable without its alias")
		assert.Equal(t, 1, client.CallCount("CreateAlias"))
		assert.Equal(t, 0, client.CallCount("ScheduleKeyDeletion"), "the key is kept")

		_, err = provider.GetKey("alias/throttled")
		require.ErrorContains(t, err, "NotFoundException")
		_, err = provider.GetKey(priv.(*awskmscrypto.Signer).KeyID())
		require.NoError(t, err)
	})
	t.Run("alias exists", func(t *testing.T) {
		t.Parallel()
		client := newFakeKMS()
		provider := newProvider(t, client)
		first, err := provider.GenerateECDSAKey("dup", elliptic.P256())
		require.NoError(t, err)
		second, err := provider.GenerateECDSAKey("dup", elliptic.P256())
		require.NoError(t, err)
		assert.NotEqual(t, first.(*awskmscrypto.Signer).KeyID(), second.(*awskmscrypto.Signer).KeyID())
		assert.Equal(t, 2, client.CallCount("CreateAlias"))

		// the alias still names the first key
		byAlias, err := provider.GetKey("alias/dup")
		require.NoError(t, err)
		assert.Equal(t, first.(*awskmscrypto.Signer).Public(), byAlias.(crypto.Signer).Public())
	})
	t.Run("alias names", func(t *testing.T) {
		t.Parallel()
		for label, alias := range map[string]string{
			"plain":             "alias/plain",
			"with space & dot.": "alias/with_space___dot_",
			"aws/reserved":      "alias/reserved",
			"a/b:c_d-e":         "alias/a/b:c_d-e",
			"":                  "alias/",
		} {
			assert.Equal(t, alias, awskmscrypto.AliasFromLabel(label), label)
		}
	})
}

// TestGenerateKeyErrors checks the errors of key creation, and that a key
// whose public key can not be fetched is scheduled for deletion instead of
// being left behind.
func TestGenerateKeyErrors(t *testing.T) {
	t.Parallel()

	cause := errors.New("kms down")
	// createdKey returns the id of the only key in client.
	createdKey := func(t *testing.T, client *fakeKMS) string {
		t.Helper()
		client.mu.Lock()
		defer client.mu.Unlock()
		require.Len(t, client.order, 1)
		return client.order[0]
	}
	// discarded checks that the only key in client is pending deletion.
	discarded := func(t *testing.T, client *fakeKMS) {
		t.Helper()
		ki, err := newProvider(t, client).KeyInfo(0, createdKey(t, client), false)
		require.NoError(t, err)
		assert.Equal(t, string(types.KeyStatePendingDeletion), ki.Meta["state"], "the incomplete key is scheduled for deletion")
		assert.Equal(t, 1, client.CallCount("ScheduleKeyDeletion"))
	}

	t.Run("create fails", func(t *testing.T) {
		t.Parallel()
		client := newFakeKMS()
		client.createKey = func(*kms.CreateKeyInput) (*kms.CreateKeyOutput, error) {
			return nil, cause
		}
		_, err := newProvider(t, client).GenerateRSAKey("rsa", 2048, 1)
		require.EqualError(t, err, `failed to create key with label: "rsa": kms down`)
		require.ErrorIs(t, err, cause)
		assert.Equal(t, 0, client.CallCount("ScheduleKeyDeletion"))
	})
	t.Run("create empty response", func(t *testing.T) {
		t.Parallel()
		client := newFakeKMS()
		client.createKey = func(*kms.CreateKeyInput) (*kms.CreateKeyOutput, error) {
			return &kms.CreateKeyOutput{}, nil
		}
		_, err := newProvider(t, client).GenerateRSAKey("rsa", 2048, 1)
		require.EqualError(t, err, `failed to create key with label: "rsa": empty response`)
	})
	t.Run("public key fails", func(t *testing.T) {
		t.Parallel()
		client := newFakeKMS()
		client.getPublicKey = func(*kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error) {
			return nil, cause
		}
		_, err := newProvider(t, client).GenerateECDSAKey("ec", elliptic.P256())
		require.EqualError(t, err, "failed to get public key, id="+createdKey(t, client)+": kms down")
		require.ErrorIs(t, err, cause)
		discarded(t, client)
	})
	t.Run("public key fails and discard fails", func(t *testing.T) {
		t.Parallel()
		client := newFakeKMS()
		client.getPublicKey = func(*kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error) {
			return nil, cause
		}
		client.scheduleKeyDeletion = func(*kms.ScheduleKeyDeletionInput) (*kms.ScheduleKeyDeletionOutput, error) {
			return nil, throttlingError()
		}
		_, err := newProvider(t, client).GenerateECDSAKey("ec", elliptic.P256())
		require.ErrorIs(t, err, cause, "the creation error is returned")
		assert.Equal(t, 1, client.CallCount("ScheduleKeyDeletion"))
	})
	t.Run("public key empty", func(t *testing.T) {
		t.Parallel()
		client := newFakeKMS()
		client.getPublicKey = func(*kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error) {
			return &kms.GetPublicKeyOutput{}, nil
		}
		_, err := newProvider(t, client).GenerateECDSAKey("ec", elliptic.P256())
		require.EqualError(t, err, "failed to parse public key, id="+createdKey(t, client)+": empty response")
		discarded(t, client)
	})
	t.Run("public key malformed", func(t *testing.T) {
		t.Parallel()
		client := newFakeKMS()
		client.getPublicKey = func(*kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error) {
			return &kms.GetPublicKeyOutput{PublicKey: []byte("not DER")}, nil
		}
		_, err := newProvider(t, client).GenerateECDSAKey("ec", elliptic.P256())
		require.ErrorContains(t, err, "failed to parse public key, id=")
		require.ErrorContains(t, err, "asn1")
		discarded(t, client)
	})
}

// TestGetKey checks that GetKey returns a signer for a signing key only
// (XPKI-031) and keeps the KMS error identity.
func TestGetKey(t *testing.T) {
	t.Parallel()

	client := newFakeKMS()
	provider := newProvider(t, client)
	signID := client.mustAddKey(t, "sign", types.KeySpecEccNistP384, types.KeyUsageTypeSignVerify)
	encryptID := client.mustAddKey(t, "encrypt", types.KeySpecRsa2048, types.KeyUsageTypeEncryptDecrypt)

	priv, err := provider.GetKey(signID)
	require.NoError(t, err)
	signer := priv.(*awskmscrypto.Signer)
	assert.Equal(t, signID, signer.KeyID())
	assert.Equal(t, "sign", signer.Label())
	assert.Equal(t, []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha384}, signer.SigningAlgorithms())

	// by ARN
	priv, err = provider.GetKey(fakeArnBase + "key/" + signID)
	require.NoError(t, err)
	assert.Equal(t, signer.Public(), priv.(crypto.Signer).Public())

	publicKeyCalls := client.CallCount("GetPublicKey")
	_, err = provider.GetKey(encryptID)
	require.EqualError(t, err, "key "+encryptID+" usage ENCRYPT_DECRYPT is not valid for signing")
	assert.Equal(t, publicKeyCalls, client.CallCount("GetPublicKey"), "no public key for a key that can not sign")

	client.setState(signID, types.KeyStatePendingDeletion)
	_, err = provider.GetKey(signID)
	require.EqualError(t, err, "key "+signID+" is pending deletion")
	assert.Equal(t, publicKeyCalls, client.CallCount("GetPublicKey"))

	client.setState(signID, types.KeyStateDisabled)
	priv, err = provider.GetKey(signID)
	require.NoError(t, err, "a disabled key can be enabled again")
	assert.Equal(t, signer.Public(), priv.(crypto.Signer).Public())
	client.setState(signID, types.KeyStateEnabled)

	_, err = provider.GetKey("missing")
	require.EqualError(t, err, "failed to describe key, id=missing: NotFoundException: Key 'missing' does not exist")
	var notFound *types.NotFoundException
	require.ErrorAs(t, err, &notFound)

	client.describeKey = func(*kms.DescribeKeyInput) (*kms.DescribeKeyOutput, error) {
		return &kms.DescribeKeyOutput{}, nil
	}
	_, err = provider.GetKey(signID)
	require.EqualError(t, err, "failed to describe key, id="+signID+": empty response")
	client.describeKey = nil

	_, _, err = provider.IdentifyKey(nil)
	require.EqualError(t, err, "not supported key")
}

// TestKeyInfo checks the key info fields and errors.
func TestKeyInfo(t *testing.T) {
	t.Parallel()

	client := newFakeKMS()
	provider := newProvider(t, client)
	keyID := client.mustAddKey(t, "info", types.KeySpecRsa2048, types.KeyUsageTypeSignVerify)

	ki, err := provider.KeyInfo(0, keyID, false)
	require.NoError(t, err)
	assert.Equal(t, keyID, ki.ID)
	assert.Equal(t, "info", ki.Label)
	assert.Empty(t, ki.PublicKey)
	require.NotNil(t, ki.CreationTime)
	assert.Equal(t, map[string]string{
		"description": "info",
		"usage":       "SIGN_VERIFY",
		"origin":      "AWS_KMS",
		"state":       "Enabled",
		"enabled":     "true",
		"algo":        fmt.Sprintf("%v", rsaSigningAlgorithms),
	}, ki.Meta)
	assert.Equal(t, 0, client.CallCount("GetPublicKey"))

	ki, err = provider.KeyInfo(0, keyID, true)
	require.NoError(t, err)
	assert.Contains(t, ki.PublicKey, "-----BEGIN PUBLIC KEY-----")

	client.setState(keyID, types.KeyStateDisabled)
	ki, err = provider.KeyInfo(0, keyID, false)
	require.NoError(t, err)
	assert.Equal(t, "Disabled", ki.Meta["state"])
	assert.Equal(t, "false", ki.Meta["enabled"])

	_, err = provider.KeyInfo(0, "missing", true)
	require.ErrorContains(t, err, "failed to describe key, id=missing")

	client.getPublicKey = func(*kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error) {
		return nil, nil
	}
	_, err = provider.KeyInfo(0, keyID, true)
	require.EqualError(t, err, "failed to parse public key, id="+keyID+": empty response")
	client.getPublicKey = nil
}

func TestExportAndDestroyKey(t *testing.T) {
	t.Parallel()

	client := newFakeKMS()
	provider := newProvider(t, client)
	keyID := client.mustAddKey(t, "export", types.KeySpecEccNistP256, types.KeyUsageTypeSignVerify)

	uri, raw, err := provider.ExportKey(keyID)
	require.NoError(t, err)
	assert.Equal(t, "pkcs11:manufacturer=AWSKMS;model=KMS;id="+keyID+";serial="+fakeArnBase+"key/"+keyID+";type=private", uri)
	assert.Equal(t, []byte(uri), raw)

	_, _, err = provider.ExportKey("missing")
	require.ErrorContains(t, err, "failed to describe key, id=missing")

	require.NoError(t, provider.DestroyKeyPairOnSlot(0, keyID))
	ki, err := provider.KeyInfo(0, keyID, false)
	require.NoError(t, err)
	assert.Equal(t, "PendingDeletion", ki.Meta["state"])

	err = provider.DestroyKeyPairOnSlot(0, "missing")
	require.ErrorContains(t, err, "failed to schedule key deletion: missing")
	var notFound *types.NotFoundException
	require.ErrorAs(t, err, &notFound)

	client.scheduleKeyDeletion = func(*kms.ScheduleKeyDeletionInput) (*kms.ScheduleKeyDeletionOutput, error) {
		return nil, nil
	}
	err = provider.DestroyKeyPairOnSlot(0, keyID)
	require.EqualError(t, err, "failed to schedule key deletion: "+keyID+": empty response")

	_, err = provider.FindKeyPairOnSlot(0, keyID, "")
	require.EqualError(t, err, "unsupported command for this crypto provider")
	require.NoError(t, provider.Close())

	tokens, err := provider.EnumTokens(true)
	require.NoError(t, err)
	assert.Equal(t, uint(0), tokens[0].SlotID)
	assert.Equal(t, awskmscrypto.ProviderName, tokens[0].Manufacturer)
	assert.Equal(t, "KMS", tokens[0].Model)
	assert.Equal(t, uint(0), provider.CurrentSlotID())
}

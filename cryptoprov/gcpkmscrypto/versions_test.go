package gcpkmscrypto_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/cryptoprov/gcpkmscrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	rotatedKey   = "rot"
	rotatedLabel = "rotated"
	// legacyURI is a URI exported before versions were tracked (XPKI-020).
	legacyURI = "pkcs11:manufacturer=GCPKMS;model=KMS;id=rot;serial=1;type=private"
)

// ecSigner asserts that pk is a provider signer whose public key is the
// version name's, and returns it.
func ecSigner(t *testing.T, s *fakeKMSServer, pk crypto.PrivateKey, keyID, versionName string) crypto.Signer {
	t.Helper()
	signer, ok := pk.(*gcpkmscrypto.Signer)
	require.True(t, ok, "%T", pk)
	assert.Equal(t, keyID, signer.KeyID())
	assert.Equal(t, rotatedLabel, signer.Label())
	assert.Equal(t, kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, signer.Algorithm())
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	require.True(t, ok, "%T", signer.Public())
	assert.True(t, pub.Equal(s.PublicKey(t, versionName)), "public key of %s", versionName)
	return signer
}

// signAndVerify signs a digest with signer and reports which of the
// version names verifies it.
func signAndVerify(t *testing.T, s *fakeKMSServer, signer crypto.Signer, versionNames ...string) []bool {
	t.Helper()
	digest := sha256.Sum256([]byte("to be signed by " + signer.(*gcpkmscrypto.Signer).KeyID()))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	verified := make([]bool, len(versionNames))
	for i, name := range versionNames {
		verified[i] = ecdsa.VerifyASN1(s.PublicKey(t, name).(*ecdsa.PublicKey), digest[:], sig)
	}
	return verified
}

// TestKeyVersions checks which version a key ID selects for lookup, signing
// and export, before and after a new version is added (XPKI-020).
func TestKeyVersions(t *testing.T) {
	t.Parallel()

	s := newFakeKMSServer()
	provider := grpcProvider(t, s)
	keyName := s.AddKey(t, rotatedKey, kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, rotatedLabel)
	v1 := keyName + "/cryptoKeyVersions/1"
	v1ID := rotatedKey + "/cryptoKeyVersions/1"
	v2ID := rotatedKey + "/cryptoKeyVersions/2"

	// the only version is the newest enabled one
	pk, err := provider.GetKey(rotatedKey)
	require.NoError(t, err)
	signer1 := ecSigner(t, s, pk, v1ID, v1)

	// after rotation a bare id selects version 2, the version-1 signer
	// and an explicit version 1 keep signing with version 1
	v2 := s.AddVersion(t, keyName, kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, kmspb.CryptoKeyVersion_ENABLED)
	pk, err = provider.GetKey(rotatedKey)
	require.NoError(t, err)
	signer2 := ecSigner(t, s, pk, v2ID, v2)
	assert.Equal(t, []bool{false, true}, signAndVerify(t, s, signer2, v1, v2))
	assert.Equal(t, []bool{true, false}, signAndVerify(t, s, signer1, v1, v2))

	pk, err = provider.GetKey(v1ID)
	require.NoError(t, err)
	assert.Equal(t, []bool{true, false}, signAndVerify(t, s, ecSigner(t, s, pk, v1ID, v1), v1, v2))

	// the exported URI of a signer pins its version; a legacy URI without
	// a version follows the newest enabled version
	uri, key, err := provider.ExportKey(signer1.(*gcpkmscrypto.Signer).KeyID())
	require.NoError(t, err)
	assert.Equal(t, "pkcs11:manufacturer=GCPKMS;model=KMS;id=rot/cryptoKeyVersions/1;serial=1;type=private", uri)
	assert.Equal(t, []byte(uri), key)
	pinned, err := cryptoprov.ParsePrivateKeyURI(uri)
	require.NoError(t, err)
	pk, err = provider.GetKey(pinned.ID())
	require.NoError(t, err)
	ecSigner(t, s, pk, v1ID, v1)

	legacy, err := cryptoprov.ParsePrivateKeyURI(legacyURI)
	require.NoError(t, err)
	assert.Equal(t, rotatedKey, legacy.ID())
	pk, err = provider.GetKey(legacy.ID())
	require.NoError(t, err)
	ecSigner(t, s, pk, v2ID, v2)

	// a disabled version is skipped by a bare id and rejected by name
	s.SetState(t, v2, kmspb.CryptoKeyVersion_DISABLED)
	pk, err = provider.GetKey(rotatedKey)
	require.NoError(t, err)
	ecSigner(t, s, pk, v1ID, v1)
	_, err = provider.GetKey(v2ID)
	require.EqualError(t, err, "key version rot/cryptoKeyVersions/2 is DISABLED")

	// no enabled version at all
	s.SetState(t, v1, kmspb.CryptoKeyVersion_DISABLED)
	_, err = provider.GetKey(rotatedKey)
	require.EqualError(t, err, "key rot has no enabled version")

	// a missing version or key is the KMS error
	_, err = provider.GetKey(rotatedKey + "/cryptoKeyVersions/3")
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(errors.UnwrapAll(err)))
	_, err = provider.GetKey("missing")
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(errors.UnwrapAll(err)))
}

// TestKeyVersionPaging resolves a bare id over several pages of versions.
func TestKeyVersionPaging(t *testing.T) {
	t.Parallel()

	s := newFakeKMSServer()
	provider := grpcProvider(t, s)
	keyName := s.AddKey(t, rotatedKey, kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, rotatedLabel)
	var names []string
	for range 4 {
		names = append(names, s.AddVersion(t, keyName, kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, kmspb.CryptoKeyVersion_ENABLED))
	}
	// version 5 is the newest enabled one; 4 and 3 are not enabled. The fake
	// serves fakeVersionPageSize versions per page, so the SDK iterator
	// follows page tokens.
	s.SetState(t, names[1], kmspb.CryptoKeyVersion_DISABLED)
	s.SetState(t, names[2], kmspb.CryptoKeyVersion_DESTROY_SCHEDULED)
	pk, err := provider.GetKey(rotatedKey)
	require.NoError(t, err)
	ecSigner(t, s, pk, rotatedKey+"/cryptoKeyVersions/5", names[3])
	assert.Equal(t, (5+fakeVersionPageSize-1)/fakeVersionPageSize, s.CallCount("ListCryptoKeyVersions"), "pages fetched")
	s.SetState(t, names[3], kmspb.CryptoKeyVersion_DESTROYED)
	pk, err = provider.GetKey(rotatedKey)
	require.NoError(t, err)
	ecSigner(t, s, pk, rotatedKey+"/cryptoKeyVersions/2", names[0])
}

// TestKeyInfoVersions checks that KeyInfo describes the selected version
// and that EnumKeys does not invent one (XPKI-020).
func TestKeyInfoVersions(t *testing.T) {
	t.Parallel()

	s := newFakeKMSServer()
	provider := grpcProvider(t, s)
	keyName := s.AddKey(t, rotatedKey, kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, rotatedLabel)
	v1 := keyName + "/cryptoKeyVersions/1"
	v2 := s.AddVersion(t, keyName, kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384, kmspb.CryptoKeyVersion_ENABLED)

	ki, err := provider.KeyInfo(0, rotatedKey, true)
	require.NoError(t, err)
	assert.Equal(t, rotatedKey, ki.ID)
	assert.Equal(t, "2", ki.CurrentVersionID)
	assert.Equal(t, "protection=HSM,label=rotated", ki.Label)
	assert.Equal(t, map[string]string{
		"purpose":    "ASYMMETRIC_SIGN",
		"state":      "ENABLED",
		"algo":       "EC_SIGN_P384_SHA384",
		"protection": "HSM",
	}, ki.Meta)
	pub, err := provider.GetKey(rotatedKey)
	require.NoError(t, err)
	assert.Equal(t, publicPEM(t, pub.(crypto.Signer).Public()), ki.PublicKey)

	s.SetState(t, v2, kmspb.CryptoKeyVersion_DISABLED)
	ki, err = provider.KeyInfo(0, rotatedKey, true)
	require.NoError(t, err)
	assert.Equal(t, "1", ki.CurrentVersionID)
	assert.Equal(t, "EC_SIGN_P256_SHA256", ki.Meta["algo"])
	assert.Equal(t, publicPEM(t, s.PublicKey(t, v1)), ki.PublicKey)

	// an explicit version is described whatever its state
	ki, err = provider.KeyInfo(0, rotatedKey+"/cryptoKeyVersions/2", false)
	require.NoError(t, err)
	assert.Equal(t, "2", ki.CurrentVersionID)
	assert.Equal(t, "DISABLED", ki.Meta["state"])
	assert.Empty(t, ki.PublicKey)

	// with no enabled version, a bare id describes the newest version that
	// is not destroyed (XPKI-117), and GetKey still refuses it
	s.SetState(t, v1, kmspb.CryptoKeyVersion_DISABLED)
	ki, err = provider.KeyInfo(0, rotatedKey, false)
	require.NoError(t, err)
	assert.Equal(t, "2", ki.CurrentVersionID)
	assert.Equal(t, "DISABLED", ki.Meta["state"])
	_, err = provider.GetKey(rotatedKey)
	require.EqualError(t, err, "key rot has no enabled version")
	// KMS refuses the public key of a disabled version; the error is its
	_, err = provider.KeyInfo(0, rotatedKey, true)
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(errors.UnwrapAll(err)))

	s.SetState(t, v2, kmspb.CryptoKeyVersion_DESTROYED)
	ki, err = provider.KeyInfo(0, rotatedKey, false)
	require.NoError(t, err)
	assert.Equal(t, "1", ki.CurrentVersionID)

	// with every version destroyed, the key alone is described
	s.SetState(t, v1, kmspb.CryptoKeyVersion_DESTROYED)
	ki, err = provider.KeyInfo(0, rotatedKey, false)
	require.NoError(t, err)
	assert.Equal(t, rotatedKey, ki.ID)
	assert.Empty(t, ki.CurrentVersionID)
	assert.Equal(t, map[string]string{
		"purpose":    "ASYMMETRIC_SIGN",
		"algo":       "EC_SIGN_P256_SHA256",
		"protection": "HSM",
	}, ki.Meta)
	_, err = provider.KeyInfo(0, rotatedKey, true)
	require.EqualError(t, err, "key rot has no version with a public key")

	// listing does not resolve versions
	keys, err := provider.EnumKeys(0, "")
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, rotatedKey, keys[0].ID)
	assert.Empty(t, keys[0].CurrentVersionID)
	assert.NotContains(t, keys[0].Meta, "state")
}

// TestDestroyVersions checks exactly which versions DestroyKeyPairOnSlot
// destroys (XPKI-020, XPKI-116).
func TestDestroyVersions(t *testing.T) {
	t.Parallel()

	s := newFakeKMSServer()
	provider := grpcProvider(t, s)
	keyName := s.AddKey(t, rotatedKey, kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, rotatedLabel)
	v1 := keyName + "/cryptoKeyVersions/1"
	v2 := s.AddVersion(t, keyName, kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, kmspb.CryptoKeyVersion_ENABLED)
	v3 := s.AddVersion(t, keyName, kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, kmspb.CryptoKeyVersion_DISABLED)
	v4 := s.AddVersion(t, keyName, kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, kmspb.CryptoKeyVersion_DESTROY_SCHEDULED)
	v5 := s.AddVersion(t, keyName, kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, kmspb.CryptoKeyVersion_PENDING_GENERATION)
	stateOf := func(names ...string) []kmspb.CryptoKeyVersion_CryptoKeyVersionState {
		states := make([]kmspb.CryptoKeyVersion_CryptoKeyVersionState, len(names))
		for i, name := range names {
			states[i] = s.State(t, name)
		}
		return states
	}
	const (
		enabled   = kmspb.CryptoKeyVersion_ENABLED
		disabled  = kmspb.CryptoKeyVersion_DISABLED
		scheduled = kmspb.CryptoKeyVersion_DESTROY_SCHEDULED
		pending   = kmspb.CryptoKeyVersion_PENDING_GENERATION
	)

	// an explicit version is destroyed on its own, whatever its state, with
	// one RPC and no lookup
	require.NoError(t, provider.DestroyKeyPairOnSlot(0, rotatedKey+"/cryptoKeyVersions/3"))
	assert.Equal(t, []kmspb.CryptoKeyVersion_CryptoKeyVersionState{enabled, enabled, scheduled, scheduled, pending}, stateOf(v1, v2, v3, v4, v5))
	assert.Equal(t, []string{"DestroyCryptoKeyVersion"}, s.Calls()[len(s.Calls())-1:])
	s.SetState(t, v3, disabled)

	// a bare id destroys every enabled or disabled version, newest first,
	// and stops at the first failure
	s.FailDestroy(v2, status.Error(codes.Internal, "hsm busy"))
	err := provider.DestroyKeyPairOnSlot(0, rotatedKey)
	require.Error(t, err)
	assert.Equal(t, "failed to schedule key deletion: rot/cryptoKeyVersions/2: rpc error: code = Internal desc = hsm busy", err.Error())
	assert.Equal(t, []kmspb.CryptoKeyVersion_CryptoKeyVersionState{enabled, enabled, scheduled, scheduled, pending}, stateOf(v1, v2, v3, v4, v5))

	s.FailDestroy(v2, nil)
	require.NoError(t, provider.DestroyKeyPairOnSlot(0, rotatedKey))
	assert.Equal(t, []kmspb.CryptoKeyVersion_CryptoKeyVersionState{scheduled, scheduled, scheduled, scheduled, pending}, stateOf(v1, v2, v3, v4, v5))
	_, err = provider.GetKey(rotatedKey)
	require.EqualError(t, err, "key rot has no enabled version", "the key can no longer sign")

	// nothing left to destroy
	require.EqualError(t, provider.DestroyKeyPairOnSlot(0, rotatedKey), "key rot has no version to destroy")
	assert.Equal(t, 5, s.CallCount("DestroyCryptoKeyVersion"))

	// a retired key whose only version is disabled is destroyed by its bare id
	retired := s.AddKey(t, "retired", kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, "retired") + "/cryptoKeyVersions/1"
	s.SetState(t, retired, disabled)
	require.NoError(t, provider.DestroyKeyPairOnSlot(0, "retired"))
	assert.Equal(t, scheduled, s.State(t, retired))

	// a missing version is the KMS error
	err = provider.DestroyKeyPairOnSlot(0, rotatedKey+"/cryptoKeyVersions/9")
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(errors.UnwrapAll(err)))
	assert.Equal(t, 0, s.CallCount("GetCryptoKeyVersion"), "destroy never fetches a version")
}

// TestInvalidKeyIDs checks that malformed key IDs fail before any RPC.
func TestInvalidKeyIDs(t *testing.T) {
	t.Parallel()

	client := &fakeKMS{}
	provider := newProvider(t, client)
	for _, keyID := range []string{
		"",
		"a/b",
		"projects/p/locations/l/keyRings/r/cryptoKeys/k",
		"k/cryptoKeyVersions/",
		"k/cryptoKeyVersions/x",
		"k/cryptoKeyVersions/1/2",
		"/cryptoKeyVersions/1",
	} {
		t.Run(keyID, func(t *testing.T) {
			want := `invalid key ID: "` + keyID + `"`
			_, err := provider.GetKey(keyID)
			assert.EqualError(t, err, want)
			_, err = provider.KeyInfo(0, keyID, true)
			assert.EqualError(t, err, want)
			assert.EqualError(t, provider.DestroyKeyPairOnSlot(0, keyID), want)
			_, _, err = provider.ExportKey(keyID)
			assert.EqualError(t, err, want)
			signer := gcpkmscrypto.NewSigner(keyID, "label", nil, kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, provider)
			_, err = signer.Sign(rand.Reader, make([]byte, sha256.Size), crypto.SHA256)
			assert.EqualError(t, err, want)
		})
	}
	assert.Empty(t, client.Calls(), "no RPC for an invalid key ID")
}

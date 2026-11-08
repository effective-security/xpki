package crypto11

import (
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"os"
	"strings"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/certutil"
	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// PKCS11V32ConfigEnv names the token config of a PKCS#11 v3.2 module with
// ML-DSA (for example Kryoptic). TestMLDSAOnPKCS11v32Token runs only when
// it is set: SoftHSM, the CI fixture, has no ML-DSA, so this test is opt-in
// and does not follow XPKI_INTEGRATION.
const PKCS11V32ConfigEnv = "XPKI_PKCS11_V32_CONFIG"

// TestMLDSAParameterSets round-trips the CKA_PARAMETER_SET values and
// rejects unknown and malformed ones.
func TestMLDSAParameterSets(t *testing.T) {
	t.Parallel()
	for set, params := range map[uint]mldsa.Parameters{
		ckpMLDSA44: mldsa.MLDSA44(),
		ckpMLDSA65: mldsa.MLDSA65(),
		ckpMLDSA87: mldsa.MLDSA87(),
	} {
		got, err := mldsaParameterSet(params)
		require.NoError(t, err)
		assert.Equal(t, set, got)
		back, err := mldsaParameters(UlongToBytes(set))
		require.NoError(t, err)
		assert.Equal(t, params, back)
	}

	_, err := mldsaParameters(UlongToBytes(4))
	require.ErrorIs(t, err, errUnsupportedMLDSAParameterSet)
	assert.EqualError(t, err, "CKA_PARAMETER_SET 4: crypto11/mldsa: unsupported ML-DSA parameter set")
	_, err = mldsaParameters([]byte{1, 2})
	require.ErrorIs(t, err, errMalformedUlong)
	_, err = mldsaParameterSet(mldsa.Parameters{})
	require.ErrorIs(t, err, errUnsupportedMLDSAParameterSet)

	assert.Equal(t, certutil.KeyTypeMLDSA, KeyTypeNames[ckkMLDSA])
}

// TestMLDSAPublicKeyDecode decodes a public key from the attribute values a
// token returns.
func TestMLDSAPublicKeyDecode(t *testing.T) {
	t.Parallel()
	for set, params := range map[uint]mldsa.Parameters{
		ckpMLDSA44: mldsa.MLDSA44(),
		ckpMLDSA65: mldsa.MLDSA65(),
		ckpMLDSA87: mldsa.MLDSA87(),
	} {
		key, err := mldsa.GenerateKey(params)
		require.NoError(t, err)
		pub, err := mldsaPublicKey(UlongToBytes(set), key.PublicKey().Bytes())
		require.NoError(t, err)
		assert.True(t, key.PublicKey().Equal(pub))

		_, err = mldsaPublicKey(UlongToBytes(set), key.PublicKey().Bytes()[1:])
		require.ErrorContains(t, err, "CKA_VALUE: ")
		_, err = mldsaPublicKey(UlongToBytes(7), key.PublicKey().Bytes())
		require.ErrorIs(t, err, errUnsupportedMLDSAParameterSet)
	}
}

// TestMLDSASignOptionsWithoutToken checks the option validation of
// PKCS11PrivateKeyMLDSA.Sign, which happens before any token call, and the
// key type plumbing (Public, ConvertToPublic).
func TestMLDSASignOptionsWithoutToken(t *testing.T) {
	t.Parallel()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	priv := &PKCS11PrivateKeyMLDSA{key: &PKCS11PrivateKey{PubKey: key.PublicKey()}}

	assert.Equal(t, key.PublicKey(), priv.Public())
	pub, err := ConvertToPublic(priv)
	require.NoError(t, err)
	assert.Equal(t, key.PublicKey(), pub)
	pub, err = ConvertToPublic(key)
	require.NoError(t, err)
	assert.Equal(t, key.Public(), pub)
	gen := &privateKeyGen{id: "id", label: "label", PKCS11PrivateKey: priv.key, PrivateKey: priv}
	pub, err = ConvertToPublic(gen)
	require.NoError(t, err)
	assert.Equal(t, key.PublicKey(), pub)

	for _, tc := range []struct {
		name string
		opts crypto.SignerOpts
		err  error
		text string
	}{
		{name: "digest", opts: crypto.SHA256, text: "ML-DSA signs a message, not a digest: unsupported signer options SHA-256"},
		{name: "mu", opts: crypto.MLDSAMu, err: errMLDSAExternalMu},
		{name: "context", opts: &mldsa.Options{Context: "xpki"}, err: errMLDSAContext},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := priv.Sign(rand.Reader, make([]byte, 64), tc.opts)
			require.Error(t, err)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
			} else {
				require.EqualError(t, err, tc.text)
			}
		})
	}
	// the privateKeyGen wrapper forwards the error
	_, err = gen.Sign(rand.Reader, make([]byte, 32), crypto.SHA256)
	require.ErrorContains(t, err, "ML-DSA signs a message")
}

// TestGenerateMLDSAKeyOnSoftHSM records the SoftHSM limitation: the token
// has no CKM_ML_DSA_KEY_PAIR_GEN, so generation fails with a PKCS#11 error
// and leaves no key behind.
func TestGenerateMLDSAKeyOnSoftHSM(t *testing.T) {
	requireP11(t)
	label := "mldsa-" + t.Name()
	priv, err := p11lib.GenerateMLDSAKey(label, mldsa.MLDSA65())
	require.Error(t, err)
	assert.Nil(t, priv)
	var p11Err pkcs11.Error
	require.ErrorAs(t, err, &p11Err, "a PKCS#11 error, not a Go one: %v", err)

	keys, err := p11lib.EnumKeys(p11lib.CurrentSlotID(), label)
	require.NoError(t, err)
	assert.Empty(t, keys, "no orphan key")

	// IdentifyKey of a stale ML-DSA object is a token error, not a panic
	key, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	stale := &PKCS11PrivateKeyMLDSA{
		key: &PKCS11PrivateKey{PKCS11Object: PKCS11Object{Slot: p11lib.Slot.id}, PubKey: key.PublicKey()},
		lib: p11lib,
	}
	_, _, err = p11lib.IdentifyKey(stale)
	require.Error(t, err)
	_, err = stale.Sign(rand.Reader, []byte("message"), nil)
	require.Error(t, err)
	require.ErrorAs(t, err, &p11Err)
}

// TestMLDSAOnPKCS11v32Token is the opt-in fixture test for a PKCS#11 v3.2
// module: generate a key of every parameter set, find it by id and by
// label, sign and verify, export the public key, and destroy it. It skips
// unless PKCS11V32ConfigEnv names a token config.
func TestMLDSAOnPKCS11v32Token(t *testing.T) {
	path := os.Getenv(PKCS11V32ConfigEnv)
	if path == "" {
		t.Skipf("%s is not set: no PKCS#11 v3.2 token with ML-DSA", PKCS11V32ConfigEnv)
	}
	lib, err := ConfigureFromFile(path)
	require.NoError(t, err)
	defer closeLib(t, lib)

	message := []byte("signed by a PKCS#11 v3.2 token")
	for _, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		t.Run(params.String(), func(t *testing.T) {
			label := "mldsa-" + strings.ToLower(params.String())
			priv, err := lib.GenerateMLDSAKey(label, params)
			require.NoError(t, err)
			keyID, gotLabel, err := lib.IdentifyKey(priv)
			require.NoError(t, err)
			assert.Equal(t, label, gotLabel)
			defer func() {
				require.NoError(t, lib.DestroyKeyPairOnSlot(lib.Slot.id, keyID))
			}()

			signer := priv.(crypto.Signer)
			pub, ok := signer.Public().(*mldsa.PublicKey)
			require.True(t, ok, "%T", signer.Public())
			assert.Equal(t, params, pub.Parameters())

			sig, err := signer.Sign(rand.Reader, message, nil)
			require.NoError(t, err)
			require.NoError(t, mldsa.Verify(pub, message, sig, nil))

			byID, err := lib.FindKeyPair(keyID, "")
			require.NoError(t, err)
			found, ok := byID.(*PKCS11PrivateKeyMLDSA)
			require.True(t, ok, "%T", byID)
			assert.True(t, pub.Equal(found.Public()))
			sig, err = found.Sign(rand.Reader, message, crypto.Hash(0))
			require.NoError(t, err)
			require.NoError(t, mldsa.Verify(pub, message, sig, nil))

			byLabel, err := lib.FindKeyPair("", label)
			require.NoError(t, err)
			assert.True(t, pub.Equal(byLabel.(*PKCS11PrivateKeyMLDSA).Public()))

			ki, err := lib.KeyInfo(lib.Slot.id, keyID, true)
			require.NoError(t, err)
			assert.Equal(t, certutil.KeyTypeMLDSA, ki.Type)
			assert.Contains(t, ki.PublicKey, "PUBLIC KEY")

			uri, _, err := lib.ExportKey(keyID)
			require.NoError(t, err)
			assert.Contains(t, uri, "id="+keyID)
		})
	}
	// the mechanism error is distinguishable from a Go error
	_, err = lib.GenerateMLDSAKey("", mldsa.Parameters{})
	require.True(t, errors.Is(err, errUnsupportedMLDSAParameterSet))
}

package crypto11

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/v2/certutil"
	"github.com/effective-security/xpki/v2/cryptoprov"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TokensInfo(t *testing.T) {
	requireP11(t)
	slots, err := p11lib.TokensInfo()
	require.NoError(t, err)
	assert.NotNil(t, slots)
	assert.True(t, len(slots) > 0, "At least one slot must already exist")
	for _, si := range slots {
		if si.id == 0 {
			continue
		}
		if si.serial != "" {
			assert.NotEmpty(t, si.label)
		}
	}
}

func Test_GetSlotKeys(t *testing.T) {
	requireP11(t)
	slots, err := p11lib.TokensInfo()
	require.NoError(t, err)
	assert.NotNil(t, slots)
	assert.True(t, len(slots) > 0, "At least one slot must already exist")
	for _, si := range slots {
		if si.id == 0 {
			continue
		}
		if si.serial != "" {
			_, err := enumKeys(p11lib, si.id, "")
			require.NoError(t, err)
			//assert.NotEmpty(t, list)
		}
	}
}

func Test_ListTokens(t *testing.T) {
	requireP11(t)
	assert.Equal(t, p11lib.Slot.id, p11lib.CurrentSlotID())

	list, err := p11lib.ListTokens(t.Context())
	require.NoError(t, err)
	require.NotEmpty(t, list)
	current := 0
	for _, token := range list {
		if !token.Current {
			continue
		}
		current++
		assert.Equal(t, p11lib.Slot.id, token.SlotID)
		assert.Equal(t, p11lib.Slot.serial, token.Serial)
		assert.Equal(t, p11lib.Slot.label, token.Label)

		// the manager of the token lib is logged in to lists its keys
		km, err := p11lib.Token(token.SlotID)
		require.NoError(t, err)
		_, err = km.ListKeys(t.Context(), &cryptoprov.ListKeysRequest{PageSize: 1})
		require.NoError(t, err)
		_, err = km.KeyInfo(t.Context(), "Test_ListTokens_missing", cryptoprov.KeyFieldMetadata)
		require.ErrorIs(t, err, cryptoprov.ErrKeyNotFound)
		require.ErrorIs(t, km.DestroyKey(t.Context(), "Test_ListTokens_missing"), cryptoprov.ErrKeyNotFound)
	}
	assert.Equal(t, 1, current, "one token is the current one")

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = p11lib.ListTokens(ctx)
	require.ErrorIs(t, err, context.Canceled)
}

func Test_DestroyKey(t *testing.T) {
	requireP11(t)
	k, err := p11lib.GenerateRSAKeyPairWithLabel(t.Context(), "Test_DestroyKey", 1024, cryptoprov.KeyUsageSign)
	require.NoError(t, err)
	assert.NotNil(t, k)

	slotID := p11lib.CurrentSlotID()
	var list []cryptoprov.KeyInfo
	// there is a delay after key is created and visible
	for i := 0; i < 2; i++ {
		list, err = enumKeys(p11lib, slotID, "Test_DestroyKey")
		require.NoError(t, err)
		time.Sleep(time.Second)
	}
	//assert.NotEmpty(t, list)

	for _, key := range list {
		ki, err := p11lib.keyInfoOnSlot(t.Context(), slotID, key.ID, keyFieldsPublic)
		require.NoError(t, err)

		if strings.HasPrefix(ki.Label, "Test_DestroyKey") {
			err = p11lib.destroyKeyOnSlot(context.Background(), slotID, ki.ID)
			require.NoError(t, err)
		} else {
			assert.Contains(t, ki.Label, "Test_DestroyKey")
		}
	}
}

func Test_DestroyKey_NotFound(t *testing.T) {
	requireP11(t)
	slotID := p11lib.CurrentSlotID()
	err := p11lib.destroyKeyOnSlot(context.Background(), slotID, "Test_DestroyKey_NotFound_missing")
	require.Error(t, err)
	assert.True(t, errors.Is(err, errKeyNotFound), "got %v", err)
	require.ErrorIs(t, err, cryptoprov.ErrKeyNotFound)
	assert.EqualError(t, err, fmt.Sprintf("unable to destroy key %q: slot=%d, key=Test_DestroyKey_NotFound_missing: crypto11: could not find PKCS#11 key", "Test_DestroyKey_NotFound_missing", slotID))
}

func Test_ConvertToPublic(t *testing.T) {
	requireP11(t)
	rsaKey, err := p11lib.GenerateKey(t.Context(), &cryptoprov.GenerateKeyRequest{
		Label: "Test_ConvertToPublic_rsa",
		Type:  certutil.KeyTypeRSA,
		Size:  2048,
		Usage: cryptoprov.KeyUsageSign,
	})
	require.NoError(t, err)
	gen, ok := rsaKey.(*privateKeyGen)
	require.True(t, ok)
	t.Cleanup(func() {
		_ = p11lib.destroyKeyOnSlot(context.Background(), p11lib.CurrentSlotID(), gen.KeyID())
	})

	pub, err := ConvertToPublic(rsaKey)
	require.NoError(t, err)
	rsaPub, ok := pub.(*rsa.PublicKey)
	require.True(t, ok)
	assert.True(t, rsaPub.Equal(gen.Public()))

	ecKey, err := p11lib.GenerateKey(t.Context(), &cryptoprov.GenerateKeyRequest{
		Label: "Test_ConvertToPublic_ec",
		Type:  certutil.KeyTypeECDSA,
		Size:  256,
	})
	require.NoError(t, err)
	ecGen, ok := ecKey.(*privateKeyGen)
	require.True(t, ok)
	t.Cleanup(func() {
		_ = p11lib.destroyKeyOnSlot(context.Background(), p11lib.CurrentSlotID(), ecGen.KeyID())
	})

	pub, err = ConvertToPublic(ecKey)
	require.NoError(t, err)
	ecPub, ok := pub.(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.True(t, ecPub.Equal(ecGen.Public()))

	_, err = ConvertToPublic("not a key")
	require.Error(t, err)
	assert.True(t, errors.Is(err, errUnsupportedKeyType), "got %v", err)
}

// Test_KeyTypeAndClass checks that CK_ULONG attributes read from a real
// token decode to the expected key type and class (XPKI-011).
func Test_KeyTypeAndClass(t *testing.T) {
	requireP11(t)
	const prefix = "Test_KeyTypeAndClass"
	slotID := p11lib.CurrentSlotID()

	_, err := p11lib.GenerateRSAKeyPairWithLabel(t.Context(), prefix+"_rsa", 1024, cryptoprov.KeyUsageSign)
	require.NoError(t, err)
	_, err = p11lib.GenerateECDSAKeyPairWithLabel(t.Context(), prefix+"_ec", elliptic.P256())
	require.NoError(t, err)

	list, err := enumKeys(p11lib, slotID, prefix)
	require.NoError(t, err)
	t.Cleanup(func() {
		for _, key := range list {
			assert.NoError(t, p11lib.destroyKeyOnSlot(context.Background(), slotID, key.ID))
		}
	})

	expTypes := map[string]string{
		prefix + "_rsa": "RSA",
		prefix + "_ec":  "ECDSA",
	}
	require.Len(t, list, len(expTypes))
	for _, key := range list {
		exp, ok := expTypes[key.Label]
		require.True(t, ok, "unexpected key %q", key.Label)
		assert.Equal(t, exp, key.Type, key.Label)
		assert.Equal(t, "Private key", key.Class, key.Label)

		ki, err := p11lib.keyInfoOnSlot(t.Context(), slotID, key.ID, keyFields)
		require.NoError(t, err)
		assert.Equal(t, exp, ki.Type, key.Label)
		assert.Equal(t, "Private key", ki.Class, key.Label)

		priv, err := p11lib.FindKeyPair(t.Context(), key.ID, "")
		require.NoError(t, err)
		switch exp {
		case "RSA":
			assert.IsType(t, &PKCS11PrivateKeyRSA{}, priv)
		default:
			assert.IsType(t, &PKCS11PrivateKeyECDSA{}, priv)
		}
	}
}

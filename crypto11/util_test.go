package crypto11

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/cryptoprov"
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
			_, err := p11lib.EnumKeys(si.id, "")
			require.NoError(t, err)
			//assert.NotEmpty(t, list)
		}
	}
}

func Test_EnumTokens(t *testing.T) {
	requireP11(t)
	assert.NotPanics(t, func() {
		p11lib.CurrentSlotID()
	})
	assert.NotPanics(t, func() {
		list, err := p11lib.EnumTokens(false)
		require.NoError(t, err)
		assert.NotEmpty(t, list)

		list, err = p11lib.EnumTokens(true)
		require.NoError(t, err)
		assert.NotEmpty(t, list)
	})
}

func Test_DestroyKey(t *testing.T) {
	requireP11(t)
	k, err := p11lib.GenerateRSAKeyPairWithLabel("Test_DestroyKey", 1024, Signing)
	require.NoError(t, err)
	assert.NotNil(t, k)

	slotID := p11lib.CurrentSlotID()
	var list []cryptoprov.KeyInfo
	// there is a delay after key is created and visible
	for i := 0; i < 2; i++ {
		list, err = p11lib.EnumKeys(slotID, "Test_DestroyKey")
		require.NoError(t, err)
		time.Sleep(time.Second)
	}
	//assert.NotEmpty(t, list)

	for _, key := range list {
		ki, err := p11lib.KeyInfo(slotID, key.ID, true)
		require.NoError(t, err)

		if strings.HasPrefix(ki.Label, "Test_DestroyKey") {
			err = p11lib.DestroyKeyPairOnSlot(slotID, ki.ID)
			require.NoError(t, err)
		} else {
			assert.Contains(t, ki.Label, "Test_DestroyKey")
		}
	}
}

func Test_DestroyKey_NotFound(t *testing.T) {
	requireP11(t)
	slotID := p11lib.CurrentSlotID()
	err := p11lib.DestroyKeyPairOnSlot(slotID, "Test_DestroyKey_NotFound_missing")
	require.Error(t, err)
	assert.True(t, errors.Is(err, errKeyNotFound), "got %v", err)
	assert.EqualError(t, err, fmt.Sprintf("slot=%d, key=Test_DestroyKey_NotFound_missing: crypto11: could not find PKCS#11 key", slotID))
}

func Test_ConvertToPublic(t *testing.T) {
	requireP11(t)
	rsaKey, err := p11lib.GenerateRSAKey("Test_ConvertToPublic_rsa", 2048, int(Signing))
	require.NoError(t, err)
	gen, ok := rsaKey.(*privateKeyGen)
	require.True(t, ok)
	t.Cleanup(func() {
		_ = p11lib.DestroyKeyPairOnSlot(p11lib.CurrentSlotID(), gen.KeyID())
	})

	pub, err := ConvertToPublic(rsaKey)
	require.NoError(t, err)
	rsaPub, ok := pub.(*rsa.PublicKey)
	require.True(t, ok)
	assert.True(t, rsaPub.Equal(gen.Public()))

	ecKey, err := p11lib.GenerateECDSAKey("Test_ConvertToPublic_ec", elliptic.P256())
	require.NoError(t, err)
	ecGen, ok := ecKey.(*privateKeyGen)
	require.True(t, ok)
	t.Cleanup(func() {
		_ = p11lib.DestroyKeyPairOnSlot(p11lib.CurrentSlotID(), ecGen.KeyID())
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

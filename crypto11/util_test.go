package crypto11

import (
	"strings"
	"testing"
	"time"

	"github.com/effective-security/xpki/cryptoprov"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TokensInfo(t *testing.T) {
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

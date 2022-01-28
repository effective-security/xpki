package crypto11

import (
	"testing"
	"time"

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
			count := 0
			err := p11lib.EnumKeys(si.id, "", func(id, label, typ, class, currentVersionID string, creationTime *time.Time) error {
				count++
				return nil
			})
			require.NoError(t, err)
		}
	}
}

func Test_EnumTokens(t *testing.T) {
	assert.NotPanics(t, func() {
		p11lib.CurrentSlotID()
	})
	assert.NotPanics(t, func() {
		count := 0
		p11lib.EnumTokens(false, func(slotID uint, description, label, manufacturer, model, serial string) error {
			count++
			return nil
		})
		assert.Greater(t, count, 0)
		count = 0
		p11lib.EnumTokens(true, func(slotID uint, description, label, manufacturer, model, serial string) error {
			count++
			return nil
		})
		assert.Greater(t, count, 0)
	})
}

func Test_DestroyKey(t *testing.T) {
	k, err := p11lib.GenerateRSAKeyPairWithLabel("Test_DestroyKey", 1024, Signing)
	require.NoError(t, err)
	assert.NotNil(t, k)

	slotID := p11lib.CurrentSlotID()
	p11lib.EnumKeys(slotID, "Test_DestroyKey",
		func(id, label, typ, class, currentVersionID string, creationTime *time.Time) error {

			p11lib.KeyInfo(slotID, id, true, func(id, label, typ, class, currentVersionID, pubKey string, creationTime *time.Time) error {
				assert.NotEmpty(t, id)
				return nil
			})

			return p11lib.DestroyKeyPairOnSlot(slotID, id)
		})
}

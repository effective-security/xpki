package crypto11

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_LoadConfigTwice(t *testing.T) {
	requireP11(t)
	c, err := LoadTokenConfig(SoftHSMConfig)
	require.NoError(t, err)

	assert.NotEmpty(t, c.Path)
	assert.NotEmpty(t, c.Pin)
	assert.NotEmpty(t, c.TokenLabel)

	p11, err := Init(c)
	require.NoError(t, err)
	require.NotNil(t, p11)

	p11_2, err := Init(c)
	require.NoError(t, err)
	require.NotNil(t, p11_2)
	assert.Same(t, p11.Ctx, p11_2.Ctx)

	closeLib(t, p11)
	_, err = p11_2.GenRandom(make([]byte, 8))
	require.NoError(t, err)
	closeLib(t, p11_2)
}

func TestLoadConfigYaml(t *testing.T) {
	c, err := LoadTokenConfig("../cryptoprov/awskmscrypto/testdata/aws-dev-kms.yaml")
	require.NoError(t, err)

	c2, err := LoadTokenConfig("../cryptoprov/awskmscrypto/testdata/aws-dev-kms.json")
	require.NoError(t, err)

	assert.NotEqual(t, c, c2)
}

func Test_selectToken(t *testing.T) {
	t.Parallel()
	a1 := &SlotTokenInfo{id: 1, serial: "S1", label: "A"}
	noLabel := &SlotTokenInfo{id: 2, serial: "S2"}
	noSerial := &SlotTokenInfo{id: 3, label: "B"}
	a4 := &SlotTokenInfo{id: 4, serial: "S4", label: "A"}
	slots := []*SlotTokenInfo{a1, noLabel, noSerial, a4}

	tcs := []struct {
		name   string
		slots  []*SlotTokenInfo
		serial string
		label  string
		exp    *SlotTokenInfo
		expErr error
	}{
		{name: "serial", slots: slots, serial: "S4", exp: a4},
		{name: "serial of token without label", slots: slots, serial: "S2", exp: noLabel},
		{name: "label", slots: slots, label: "B", exp: noSerial},
		{name: "duplicate label first wins", slots: slots, label: "A", exp: a1},
		{name: "serial and label", slots: slots, serial: "S4", label: "A", exp: a4},
		{name: "conflicting serial and label", slots: slots, serial: "S1", label: "B", expErr: errTokenNotFound},
		{name: "unknown serial skips empty labels", slots: slots, serial: "S9", expErr: errTokenNotFound},
		{name: "unknown label skips empty serials", slots: slots, label: "Z", expErr: errTokenNotFound},
		{name: "no tokens", label: "A", expErr: errTokenNotFound},
		{name: "no selector", slots: slots, expErr: errNoTokenSelector},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			slot, err := selectToken(tc.slots, tc.serial, tc.label)
			if tc.expErr != nil {
				require.ErrorIs(t, err, tc.expErr)
				assert.EqualError(t, err, tc.expErr.Error())
				assert.Nil(t, slot)
				return
			}
			require.NoError(t, err)
			assert.Same(t, tc.exp, slot)
		})
	}
}

func TestInit_NoTokenSelector(t *testing.T) {
	t.Parallel()
	const path = "/nonexistent/libpkcs11.so"
	lib, err := Init(&config{Dir: path, Pwd: "1234"})
	require.ErrorIs(t, err, errNoTokenSelector)
	assert.EqualError(t, err, "crypto11: token serial or token label is required")
	assert.Nil(t, lib)
	assert.Zero(t, moduleRefs(path))

	cfgFile := filepath.Join(t.TempDir(), "p11.json")
	require.NoError(t, os.WriteFile(cfgFile, []byte(`{"Path":"`+path+`","Pin":"1234"}`), 0o600))
	lib, err = ConfigureFromFile(cfgFile)
	require.ErrorIs(t, err, errNoTokenSelector)
	assert.EqualError(t, err, `initialize p11 config: "`+cfgFile+`": crypto11: token serial or token label is required`)
	assert.Nil(t, lib)
}

func TestInit_TokenSelection(t *testing.T) {
	requireP11(t)
	cfg := loadTestConfig(t)
	serial, label := p11lib.Slot.serial, p11lib.Slot.label
	require.NotEmpty(t, serial)
	require.NotEmpty(t, label)
	refs := moduleRefs(cfg.Path())

	tcs := []struct {
		name   string
		serial string
		label  string
		found  bool
	}{
		{name: "serial", serial: serial, found: true},
		{name: "label", label: label, found: true},
		{name: "serial and label", serial: serial, label: label, found: true},
		{name: "label with other serial", serial: "no-such-serial", label: label},
		{name: "serial with other label", serial: serial, label: "no-such-label"},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			lib, err := Init(&config{
				Dir:    cfg.Path(),
				Serial: tc.serial,
				Label:  tc.label,
				Pwd:    cfg.Pin(),
			})
			if !tc.found {
				require.ErrorIs(t, err, errTokenNotFound)
				assert.EqualError(t, err, "crypto11: could not find PKCS#11 token")
				assert.Nil(t, lib)
				assert.Equal(t, refs, moduleRefs(cfg.Path()))
				return
			}
			require.NoError(t, err)
			assert.Equal(t, p11lib.Slot.id, lib.Slot.id)
			assert.Equal(t, serial, lib.Slot.serial)
			assert.Equal(t, label, lib.Slot.label)
			closeLib(t, lib)
		})
	}
}

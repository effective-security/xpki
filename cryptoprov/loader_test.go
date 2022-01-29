package cryptoprov_test

import (
	"path/filepath"
	"testing"

	"github.com/effective-security/xpki/crypto11"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/cryptoprov/testprov"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func inmemloader(_ cryptoprov.TokenConfig) (cryptoprov.Provider, error) {
	p, err := testprov.Init()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return p, nil
}

func Test_LoadProvider(t *testing.T) {
	_, _ = cryptoprov.Unregister("SoftHSM")

	_, err := cryptoprov.LoadProvider(SoftHSMConfig)
	assert.Error(t, err)

	err = cryptoprov.Register("SoftHSM", crypto11.LoadProvider)
	assert.NoError(t, err)
	defer cryptoprov.Unregister("SoftHSM")

	p, err := cryptoprov.LoadProvider(SoftHSMConfig)
	require.NoError(t, err)

	assert.Equal(t, "SoftHSM", p.Manufacturer())
}

func Test_Load(t *testing.T) {
	_ = cryptoprov.Register("SoftHSM", crypto11.LoadProvider)
	defer cryptoprov.Unregister("SoftHSM")
	_ = cryptoprov.Register("inmem", inmemloader)
	defer cryptoprov.Unregister("inmem")

	cp, err := cryptoprov.Load(
		SoftHSMConfig,
		[]string{filepath.Join(projFolder, "xpki/cryptoprov/testdata/inmem_testprov.json")})
	require.NoError(t, err)
	assert.Equal(t, "SoftHSM", cp.Default().Manufacturer())
}

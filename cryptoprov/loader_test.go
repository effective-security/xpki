package cryptoprov_test

import (
	"testing"

	"github.com/effective-security/xpki/cryptoprov"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// register the SoftHSM loader
	_ "github.com/effective-security/xpki/crypto11"
)

func Test_Load(t *testing.T) {
	requireSoftHSM(t)

	for _, extra := range []string{
		"testdata/inmem_testprov.json",
		"testdata/inmem_testprov.yaml",
	} {
		t.Run(extra, func(t *testing.T) {
			cp, err := cryptoprov.Load(SoftHSMConfig, []string{extra})
			require.NoError(t, err)
			t.Cleanup(func() { closeProvider(t, cp.Default()) })
			assert.Equal(t, "SoftHSM", cp.Default().Manufacturer())

			im, err := cp.ByManufacturer("inmem", "")
			require.NoError(t, err)
			assert.Equal(t, "inmem", im.Manufacturer())
		})
	}
}

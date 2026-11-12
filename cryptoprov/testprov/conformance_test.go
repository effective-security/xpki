package testprov_test

import (
	"testing"

	"github.com/effective-security/xpki/v2/cryptoprov"
	"github.com/effective-security/xpki/v2/cryptoprov/testprov"
	"github.com/effective-security/xpki/v2/internal/provtest"
	"github.com/stretchr/testify/require"
)

// TestConformance runs the key management conformance suite.
func TestConformance(t *testing.T) {
	t.Parallel()
	provtest.Run(t, provtest.Config{
		New: func(t *testing.T) cryptoprov.Provider {
			p, err := testprov.Init()
			require.NoError(t, err)
			return p
		},
		Tags:           true,
		Encrypt:        true,
		MLDSA:          true,
		DestroyRemoves: true,
	})
}

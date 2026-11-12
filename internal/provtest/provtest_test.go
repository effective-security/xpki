package provtest_test

import (
	"testing"

	"github.com/effective-security/xpki/v2/cryptoprov"
	"github.com/effective-security/xpki/v2/cryptoprov/inmemcrypto"
	"github.com/effective-security/xpki/v2/internal/provtest"
)

// TestReferenceProvider runs the suite on the in-memory provider, the
// reference implementation of the contract, in both paging modes.
func TestReferenceProvider(t *testing.T) {
	t.Parallel()
	for name, byLabel := range map[string]bool{
		"prefix": false,
		"label":  true,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			provtest.Run(t, provtest.Config{
				New: func(*testing.T) cryptoprov.Provider {
					return inmemcrypto.NewProvider()
				},
				Tags:           true,
				Encrypt:        true,
				MLDSA:          true,
				DestroyRemoves: true,
				PagingByLabel:  byLabel,
			})
		})
	}
}

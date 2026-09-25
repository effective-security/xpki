package crypto11

import (
	"fmt"
	"os"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/internal/testenv"
	"github.com/stretchr/testify/require"
)

// SoftHSMConfig provides location for PKCS11 config
const SoftHSMConfig = "/tmp/xpki/softhsm_unittest.json"

// childEnv marks a re-executed test binary that must start without a
// loaded module; see runChild.
const childEnv = "XPKI_CRYPTO11_CHILD"

var (
	// p11lib specifies PKCS11 Context for the loaded HSM module; it is nil
	// when the SoftHSM fixture is absent or failed to load (p11err).
	p11lib *PKCS11Lib
	p11err error
)

func loadConfigAndInitP11() error {
	var err error
	p11lib, err = ConfigureFromFile(SoftHSMConfig)
	if err != nil {
		return errors.WithMessagef(err, "failed to load HSM config in dir: %s", SoftHSMConfig)
	}
	return nil
}

// requireP11 gates tb on the SoftHSM fixture: it skips when the config is
// absent (or fails with XPKI_INTEGRATION=required) and fails when the
// config is present but the token did not load.
func requireP11(tb testing.TB) {
	tb.Helper()
	testenv.RequireFile(tb, "SoftHSM config", SoftHSMConfig)
	require.NoError(tb, p11err, "SoftHSM config is present but did not load")
	require.NotNil(tb, p11lib)
}

// closeLib closes lib and asserts it succeeded.
func closeLib(tb testing.TB, lib *PKCS11Lib) {
	tb.Helper()
	require.NoError(tb, lib.Close())
}

func TestMain(m *testing.M) {
	if os.Getenv(childEnv) == "" {
		if _, err := os.Stat(SoftHSMConfig); err == nil {
			p11err = loadConfigAndInitP11()
		}
	}
	code := m.Run()
	if p11lib != nil {
		if err := p11lib.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "crypto11: close SoftHSM: %v\n", err)
			code = 1
		}
	}
	os.Exit(code)
}

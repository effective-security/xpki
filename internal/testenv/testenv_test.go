package testenv_test

import (
	"fmt"
	"net"
	"testing"

	"github.com/effective-security/xpki/internal/testenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recorder captures how RequireTCP ends a test.
type recorder struct {
	testing.TB
	skipped string
	failed  string
}

func (r *recorder) Helper() {}

func (r *recorder) Skipf(format string, args ...any) {
	r.skipped = fmt.Sprintf(format, args...)
}

func (r *recorder) Fatalf(format string, args ...any) {
	r.failed = fmt.Sprintf(format, args...)
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	return l
}

// closedAddr returns an address that refuses connections.
func closedAddr(t *testing.T) string {
	t.Helper()
	l := listen(t)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	return addr
}

func TestRequireTCP(t *testing.T) {
	up := listen(t)
	t.Cleanup(func() { _ = up.Close() })
	down := closedAddr(t)

	for _, tc := range []struct {
		name     string
		env      string
		addr     string
		required bool
		skipped  bool
		failed   bool
	}{
		{name: "reachable optional", addr: up.Addr().String()},
		{name: "reachable required", env: testenv.Required, addr: up.Addr().String(), required: true},
		{name: "unreachable optional", addr: down, skipped: true},
		{name: "unreachable other value", env: "yes", addr: down, skipped: true},
		{name: "unreachable required", env: testenv.Required, addr: down, required: true, failed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(testenv.IntegrationEnv, tc.env)
			assert.Equal(t, tc.required, testenv.IntegrationRequired())

			r := &recorder{TB: t}
			testenv.RequireTCP(r, "fixture", tc.addr)
			if tc.skipped {
				assert.Contains(t, r.skipped, "fixture is not reachable at "+down+" (set XPKI_INTEGRATION=required to fail instead): ")
			} else {
				assert.Empty(t, r.skipped)
			}
			if tc.failed {
				assert.Contains(t, r.failed, "fixture is required (XPKI_INTEGRATION=required) but not reachable at "+down+": ")
			} else {
				assert.Empty(t, r.failed)
			}
		})
	}
}

package testenv_test

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
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

func TestRequireFile(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "present.json")
	require.NoError(t, os.WriteFile(present, []byte("{}"), 0o600))
	missing := filepath.Join(dir, "missing.json")
	// a path below a regular file fails with ENOTDIR, not ErrNotExist
	broken := filepath.Join(present, "child")

	for _, tc := range []struct {
		name    string
		env     string
		path    string
		skipped string
		failed  string
	}{
		{name: "present optional", path: present},
		{name: "present required", env: testenv.Required, path: present},
		{name: "missing optional", path: missing,
			skipped: "fixture is not found at " + missing + " (set XPKI_INTEGRATION=required to fail instead)"},
		{name: "missing required", env: testenv.Required, path: missing,
			failed: "fixture is required (XPKI_INTEGRATION=required) but not found at " + missing},
		{name: "unreadable optional", path: broken,
			failed: "fixture at " + broken + " can not be read: "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(testenv.IntegrationEnv, tc.env)

			r := &recorder{TB: t}
			testenv.RequireFile(r, "fixture", tc.path)
			if tc.skipped != "" {
				assert.Equal(t, tc.skipped, r.skipped)
			} else {
				assert.Empty(t, r.skipped)
			}
			if tc.failed != "" {
				assert.Contains(t, r.failed, tc.failed)
			} else {
				assert.Empty(t, r.failed)
			}
		})
	}
}

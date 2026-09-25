package testenv

import (
	"errors"
	"io/fs"
	"net"
	"os"
	"testing"
	"time"
)

const (
	// IntegrationEnv is the environment variable that selects whether a
	// missing fixture skips or fails a test.
	IntegrationEnv = "XPKI_INTEGRATION"
	// Required is the IntegrationEnv value that makes a missing fixture fail.
	Required = "required"

	dialTimeout = time.Second
)

// IntegrationRequired reports whether a missing fixture must fail the test.
func IntegrationRequired() bool {
	return os.Getenv(IntegrationEnv) == Required
}

// RequireTCP gates t on the fixture name listening at addr ("host:port").
// It returns when addr accepts a TCP connection. Otherwise it fails t when
// IntegrationRequired, and skips t when not.
func RequireTCP(t testing.TB, name, addr string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err == nil {
		_ = conn.Close()
		return
	}
	if IntegrationRequired() {
		t.Fatalf("%s is required (%s=%s) but not reachable at %s: %v", name, IntegrationEnv, Required, addr, err)
		return
	}
	t.Skipf("%s is not reachable at %s (set %s=%s to fail instead): %v", name, addr, IntegrationEnv, Required, err)
}

// RequireFile gates t on the fixture name whose file is at path, such as the
// SoftHSM token configuration. It returns when path exists. Otherwise it
// fails t when IntegrationRequired, and skips t when not. Any stat error
// other than a missing file fails t, since the fixture is present but broken.
func RequireFile(t testing.TB, name, path string) {
	t.Helper()
	_, err := os.Stat(path)
	if err == nil {
		return
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("%s at %s can not be read: %v", name, path, err)
		return
	}
	if IntegrationRequired() {
		t.Fatalf("%s is required (%s=%s) but not found at %s", name, IntegrationEnv, Required, path)
		return
	}
	t.Skipf("%s is not found at %s (set %s=%s to fail instead)", name, path, IntegrationEnv, Required)
}

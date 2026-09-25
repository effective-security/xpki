package testenv

import (
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

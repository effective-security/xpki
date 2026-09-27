package version

import (
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/effective-security/xpki/internal/testenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCLIVersion builds the CLIs and checks the version they report: the
// linker-set version with -ldflags (what make build passes), and the module
// version or VCS revision recorded by a plain go build (XPKI-097).
func TestCLIVersion(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the CLIs")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		if testenv.IntegrationRequired() {
			t.Fatalf("go is required (XPKI_INTEGRATION=required) but not found: %v", err)
		}
		t.Skipf("go is not found (set XPKI_INTEGRATION=required to fail instead): %v", err)
	}

	for _, name := range []string{"hsm-tool", "xpki-tool"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			pkg := "../../cmd/" + name
			dir := t.TempDir()

			bin := filepath.Join(dir, name+"-linker")
			goRun(t, goBin, "build", "-ldflags",
				"-X github.com/effective-security/xpki/internal/version.build=v1.2.3-test",
				"-o", bin, pkg)
			assert.Equal(t, "v1.2.3-test\n", goRun(t, bin, "--version"))

			bin = filepath.Join(dir, name)
			goRun(t, goBin, "build", "-o", bin, pkg)
			info := readBuildInfo(t, goBin, bin)
			exp := buildVersion("", info, true)
			assert.NotEqual(t, "(devel)", exp)
			assert.Equal(t, exp+"\n", goRun(t, bin, "--version"))
		})
	}
}

// goRun runs a command and returns its stdout.
func goRun(t *testing.T, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	require.NoError(t, err, "%s %s: %s", name, strings.Join(args, " "), stderr.String())
	return string(out)
}

// readBuildInfo returns the build information embedded in the binary, as
// `go version -m` prints it.
func readBuildInfo(t *testing.T, goBin, bin string) *debug.BuildInfo {
	t.Helper()
	out := goRun(t, goBin, "version", "-m", bin)
	// the first line names the binary; the rest is BuildInfo.String()
	// with a leading tab on every line
	_, rest, ok := strings.Cut(out, "\n")
	require.True(t, ok, out)
	var lines []string
	for line := range strings.SplitSeq(rest, "\n") {
		lines = append(lines, strings.TrimPrefix(line, "\t"))
	}
	info, err := debug.ParseBuildInfo(strings.Join(lines, "\n"))
	require.NoError(t, err, out)
	return info
}

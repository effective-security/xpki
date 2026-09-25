//go:build !unix

package crypto11

// loadedHandle is not available on this platform; modules are matched by
// moduleID only.
func loadedHandle(string) uintptr {
	return 0
}

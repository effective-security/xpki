// Package testenv gates tests that need external fixtures, such as the
// local-kms emulator or the SoftHSM token (XPKI-100).
//
// A fixture that is not reachable skips the test, unless XPKI_INTEGRATION is
// "required" (the Makefile exports it, so make test/covtest and CI fail
// instead). A reachable fixture always runs the test, so a present but
// broken fixture fails. Unit tests must not call it.
//
//	func TestKMS(t *testing.T) {
//		testenv.RequireTCP(t, "local-kms", "localhost:14556")
//		// ...
//	}
package testenv

// Package provtest is the conformance suite of the cryptoprov key management
// contract: every provider of this module runs it against its own backend or
// fake, so that the rules of a listing mean the same thing on a PKCS#11
// token, on AWS KMS, on Google Cloud KMS and in memory.
//
// The suite generates a small set of keys with a random label prefix, lists
// and describes them, and destroys them when it ends. It asserts that a full
// listing at several page sizes returns every key once, that every filter
// selects the expected keys, that a page token is rejected with another
// filter or field mask, that no listing returns a public key, that the
// requested field groups are filled, that a missing key and an unsupported
// request are reported with cryptoprov.ErrKeyNotFound and
// cryptoprov.ErrNotSupported, and that a cancelled context fails the call.
// What a backend cannot do is declared in Config, not skipped silently.
//
//	func TestConformance(t *testing.T) {
//		provtest.Run(t, provtest.Config{
//			New: func(t *testing.T) cryptoprov.Provider {
//				return inmemcrypto.NewProvider()
//			},
//			Tags:           true,
//			Encrypt:        true,
//			MLDSA:          true,
//			DestroyRemoves: true,
//		})
//	}
package provtest

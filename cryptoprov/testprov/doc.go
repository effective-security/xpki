// Package testprov is a test-only in-memory cryptoprov.Provider whose keys
// are not exportable: ExportKey returns a pkcs11: URI like the HSM and KMS
// providers do, and the key wrapper implements crypto.Decrypter. Unlike the
// other providers it is not registered in init(); tests call Register or
// Loader explicitly.
//
// Key generation, lookup, and URI export may run concurrently. Registry locking
// does not cover key generation, signing, or decryption. Token configuration
// passed to Loader must remain unchanged while the provider is in use.
package testprov

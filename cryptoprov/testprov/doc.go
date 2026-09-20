// Package testprov is a test-only in-memory cryptoprov.Provider whose keys
// are not exportable: ExportKey returns a pkcs11: URI like the HSM and KMS
// providers do, and the key wrapper implements crypto.Decrypter. Unlike the
// other providers it is not registered in init(); tests call Register or
// Loader explicitly.
package testprov

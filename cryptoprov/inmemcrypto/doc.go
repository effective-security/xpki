// Package inmemcrypto is a software cryptoprov.Provider that keeps RSA and
// ECDSA keys in memory and can export them as PEM. It registers itself as
// manufacturer "inmem" and is selected by cryptoprov.Load when the config
// location is "" or "inmem". Intended for development, tests and delegated
// OCSP responder keys; it is not a KeyManager.
//
// Key generation, lookup, and PEM export may run concurrently. Registry locking
// does not cover key generation, signing, or PEM serialization. Each export
// returns a caller-owned byte slice. Token configuration passed to Loader must
// remain unchanged while the provider is in use.
package inmemcrypto

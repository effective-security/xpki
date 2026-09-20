// Package inmemcrypto is a software cryptoprov.Provider that keeps RSA and
// ECDSA keys in memory and can export them as PEM. It registers itself as
// manufacturer "inmem" and is selected by cryptoprov.Load when the config
// location is "" or "inmem". Intended for development, tests and delegated
// OCSP responder keys; it is not a KeyManager.
package inmemcrypto

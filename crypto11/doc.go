// Package crypto11 provides a Go interface to PKCS#11 cryptographic devices
// such as Hardware Security Modules (HSMs) and smart cards.
//
// This package implements the standard Go crypto interfaces for:
//   - RSA private keys and signatures
//   - ECDSA private keys and signatures
//   - Random number generation
//   - Session management
//
// The package supports common PKCS#11 operations including:
//   - Key generation on the device
//   - Signing operations using device-stored keys
//   - Object discovery and management
//   - Session pooling for performance
//
// Keys generated or imported into the HSM cannot be exported,
// providing hardware-level protection for cryptographic operations.
//
// Open a token with Init or ConfigureFromFile and release it with Close.
// Every PKCS11Lib on the same library path shares one loaded module: the
// first one initializes it and the last Close finalizes it. Each PKCS11Lib
// keeps at most WithMaxSessions pooled sessions per slot (default
// DefaultMaxSessions); an operation waits while all of them are in use.
//
//	lib, err := crypto11.ConfigureFromFile("/path/softhsm.json", crypto11.WithMaxSessions(64))
//	if err != nil {
//		return err
//	}
//	defer func() { _ = lib.Close() }()
//	key, err := lib.GenerateECDSAKeyPair(ctx, elliptic.P256())
//	if err != nil {
//		return err
//	}
//	sig, err := key.Sign(rand.Reader, digest, crypto.SHA256)
//
// A PKCS11Lib is the cryptoprov.Provider and cryptoprov.KeyManager of the
// token it is logged in to, and a cryptoprov.TokenManager for the other
// tokens of the module. The methods that take a context wait for a session
// no longer than it allows; a PKCS#11 call that has started is not
// interrupted, and Sign and Decrypt, which have no context, wait without a
// deadline.
//
// This package is based on github.com/ThalesIgnite/crypto11 with
// modifications for integration with the xpki ecosystem.
package crypto11

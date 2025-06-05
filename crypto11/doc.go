// Package crypto11 provides a Go interface to PKCS#11 cryptographic devices
// such as Hardware Security Modules (HSMs) and smart cards.
//
// This package implements the standard Go crypto interfaces for:
//   - RSA private keys and signatures
//   - ECDSA private keys and signatures
//   - DSA private keys and signatures
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
// This package is based on github.com/ThalesIgnite/crypto11 with
// modifications for integration with the xpki ecosystem.
package crypto11

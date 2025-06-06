// Package testca provides utilities for creating test Certificate Authorities
// and certificates for testing and development purposes.
//
// This package supports:
//   - Generation of test CA certificates and private keys
//   - Creation of end-entity certificates signed by test CAs
//   - Certificate chain building for testing
//   - Generation of various key types (RSA, ECDSA) for testing
//   - PEM encoding/decoding utilities for test certificates
//
// The package is primarily intended for use in unit tests and development
// environments where real certificates are not required or desired.
//
// Note: Certificates generated by this package should never be used in
// production environments as they are not trusted by any real PKI.
package testca

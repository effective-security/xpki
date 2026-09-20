// Package csr provides utilities for creating, parsing, and validating
// Certificate Signing Requests (CSRs) as defined by RFC 2986.
//
// This package supports:
//   - CSR generation with various key types (RSA, ECDSA)
//   - CSR parsing and validation
//   - Request and key-request types shared with the authority package
//   - Extension handling for certificate requests
//   - Key request generation for automated certificate enrollment
//
// The package integrates with the cryptoprov package to support
// hardware-backed private keys and various cryptographic providers.
package csr

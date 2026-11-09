// Package jwt provides JSON Web Token (JWT) signing, verification, and parsing capabilities.
//
// This package implements JWT as defined by RFC 7519, with support for:
//   - JWT signing and verification using various algorithms (HMAC, RSA, ECDSA,
//     and ML-DSA per RFC 9964)
//   - JWT parsing and validation with configurable verification options
//   - JWKS (JSON Web Key Set) for key management and distribution, including
//     RFC 9964 AKP keys
//
// Subpackages: dpop (RFC 9449 proofs), accesstoken (opaque encrypted tokens),
// oauth2client (identity-provider client registry).
//
// The package provides both high-level APIs for common use cases and
// lower-level primitives for advanced JWT operations.
package jwt
